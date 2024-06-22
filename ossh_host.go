package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"sort"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

// Conn wraps a net.Conn, and sets a deadline for every read and write operation.
// https://stackoverflow.com/questions/31554196/ssh-connection-timeout
type Conn struct {
	net.Conn
	host *OsshHost
}

func (c *Conn) Read(b []byte) (int, error) {
	err := c.Conn.SetReadDeadline(time.Now().Add(c.host.connectTimeout))
	if err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *Conn) Write(b []byte) (int, error) {
	err := c.Conn.SetWriteDeadline(time.Now().Add(c.host.connectTimeout))
	if err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

// OsshHost ...
type OsshHost struct {
	address        string
	label          string
	port           int
	user           string
	err            error
	exitStatus     int
	sshc           *ssh.Client
	connectTimeout time.Duration
	runTimeout     time.Duration
}

func (host *OsshHost) setLabel(showip bool, canLookupHost bool) error {
	var err error
	var out []string
	if net.ParseIP(host.address) == nil { // if address is not ip
		if len(host.label) == 0 {
			host.label = host.address
		}
		if canLookupHost {
			if out, err = net.LookupHost(host.address); err != nil {
				return err
			}
			sort.Strings(out)
			host.address = out[0]
		}
	}
	if showip {
		host.label = host.address
	}
	if len(host.label) > 0 {
		return nil
	}
	if canLookupHost {
		out, _ = net.LookupAddr(host.address) // PTR record may be absent so we ignore error
	}
	if len(out) > 0 { // if PTR record exists
		sort.Strings(out)   // sort the list for consistency
		host.label = out[0] // and use the 1st name in the list
	} else { // if there is no PTR record
		host.label = host.address // use ip address as a label
	}
	return nil
}

func (host *OsshHost) runPipe(c chan *OsshMessage, reader io.Reader, messageType int) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		c <- &OsshMessage{
			data:        scanner.Text(),
			messageType: messageType,
			host:        host,
		}
	}
}

func (host *OsshHost) markHostFailed(c chan *OsshMessage, err error) {
	host.err = err
	c <- &OsshMessage{
		data:        err.Error(),
		messageType: ERROR,
		host:        host,
	}
}

func (host *OsshHost) setSSHClient(config *ssh.ClientConfig, socks5ProxyAddr string, jumpHostAddr string) error {
	var conn net.Conn
	var err error
        var clientConn ssh.Conn
        var chans <-chan ssh.NewChannel
        var reqs <-chan *ssh.Request
	addr := fmt.Sprintf("%s:%d", host.address, host.port)
	if len(socks5ProxyAddr) != 0 {
		dialer, err := proxy.SOCKS5("tcp", socks5ProxyAddr, nil, &net.Dialer{Timeout: host.connectTimeout})
		if err != nil {
			return err
		}
		if conn, err = dialer.Dial("tcp", addr); err != nil {
			return err
		}
	} else if len(jumpHostAddr) != 0 {
		dialer, err := ssh.Dial("tcp", jumpHostAddr, config)
		if err != nil {
			return err
		}
		if conn, err = dialer.Dial("tcp", addr); err != nil {
			return err
		}
	} else {
		if conn, err = net.DialTimeout("tcp", addr, host.connectTimeout); err != nil {
			return err
		}
	}
	timeoutConn := &Conn{conn, host}
	if host.user != "" {
		config = &ssh.ClientConfig{
			User:            host.user,
			Auth:            config.Auth,
			HostKeyCallback: config.HostKeyCallback,
		}
	}
	// tcp over ssh doesn't support SetDeadline() so far
	// https://github.com/golang/crypto/blob/master/ssh/tcpip.go#L486-L509
	// so no read/write timeouts via jump host
	if len(jumpHostAddr) == 0 {
		clientConn, chans, reqs, err = ssh.NewClientConn(timeoutConn, addr, config)
	} else {
		clientConn, chans, reqs, err = ssh.NewClientConn(conn, addr, config)
	}
	if err != nil {
		conn.Close()
		return err
	}
	host.sshc = ssh.NewClient(clientConn, chans, reqs)
	return nil
}

func (host *OsshHost) sshConnect(c chan *OsshMessage, config *ssh.ClientConfig, socks5ProxyAddr string, retryCount int, jumpHostAddr string) {
	var err error
	for i := 1; ; i++ {
		if err = host.setSSHClient(config, socks5ProxyAddr, jumpHostAddr); err == nil {
			break
		}
		if i > retryCount {
			host.markHostFailed(c, err)
			return
		}
		c <- &OsshMessage{
			data:        "retrying after error: " + err.Error(),
			messageType: VERBOSE,
			host:        host,
		}
		time.Sleep(1 * time.Second)
	}
	// this sends keepalive packets based on the timeout value
	// there's no useful response from these, so we can just abort if there's an error
	go func() {
		t := time.NewTicker(host.connectTimeout / 2)
		defer t.Stop()
		for range t.C {
			if _, _, err := host.sshc.Conn.SendRequest("", true, nil); err != nil {
				return
			}
		}
	}()
	if host.runTimeout.Seconds() > 0 {
		go func() {
			timer := time.NewTimer(host.runTimeout)
			<-timer.C
			host.sshc.Close()
		}()
	}
	c <- &OsshMessage{
		data:        "connected",
		messageType: VERBOSE,
		host:        host,
	}
}

func (host *OsshHost) sshClose(c chan *OsshMessage) {
	host.sshc.Close()
	c <- &OsshMessage{
		data:        "",
		messageType: CLOSE,
		host:        host,
	}
}

func (host *OsshHost) sshRun(c chan *OsshMessage, config *ssh.ClientConfig, command string, socks5ProxyAddr string, retryCount int, jumpHostAddr string) {
	if host.sshc == nil {
		if host.sshConnect(c, config, socks5ProxyAddr, retryCount, jumpHostAddr); host.err != nil {
			return
		}
	}

	defer host.sshClose(c)

	session, err := host.sshc.NewSession()
	if err != nil {
		host.markHostFailed(c, err)
		return
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		host.markHostFailed(c, err)
		return
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		host.markHostFailed(c, err)
		return
	}

	go host.runPipe(c, stdout, STDOUT)
	go host.runPipe(c, stderr, STDERR)

	// if err is nil ssh command returned 0
	if err = session.Run(command); err != nil {
		if err, ok := err.(*ssh.ExitError); ok {
			host.exitStatus = err.ExitStatus()
		}
	}
}
