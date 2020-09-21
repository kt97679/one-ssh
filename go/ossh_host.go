package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
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
	status         int
	err            error
	exitStatus     int
	sshc           *ssh.Client
	connectTimeout time.Duration
	runTimeout     time.Duration
}

func (host *OsshHost) setLabel(showip bool) error {
	var err error
	var out []string
	if net.ParseIP(host.address) == nil { // if address is not ip
		if len(host.label) == 0 {
			host.label = strings.Split(host.address, ".")[0]
		}
		out, err = net.LookupHost(host.address)
		if err != nil {
			return err
		}
		sort.Strings(out)
		host.address = out[0]
	}
	if showip {
		host.label = host.address
	}
	if len(host.label) > 0 {
		return nil
	}
	out, err = net.LookupAddr(host.address)
	if err != nil {
		return err
	}
	sort.Strings(out)
	name := out[0]
	if len(name) > 0 {
		host.label = strings.Split(name, ".")[0]
	} else {
		host.label = host.address
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
	c <- &OsshMessage{
		data:        "",
		messageType: messageType | EXIT,
		host:        host,
	}
}

func (host *OsshHost) markHostFailed(c chan *OsshMessage, err error) {
	host.err = err
	c <- &OsshMessage{
		data:        "",
		messageType: ERROR,
		host:        host,
	}
}

func (host *OsshHost) sshConnect(c chan *OsshMessage, config *ssh.ClientConfig) {
	var err error
	addr := fmt.Sprintf("%s:%d", host.address, host.port)
	conn, err := net.DialTimeout("tcp", addr, host.connectTimeout)
	if err != nil {
		host.markHostFailed(c, err)
		return
	}
	timeoutConn := &Conn{conn, host}
	clientConn, chans, reqs, err := ssh.NewClientConn(timeoutConn, addr, config)
	if err != nil {
		conn.Close()
		host.markHostFailed(c, err)
		return
	}
	host.sshc = ssh.NewClient(clientConn, chans, reqs)

	// this sends keepalive packets based on the timeout value
	// there's no useful response from these, so we can just abort if there's an error
	go func() {
		t := time.NewTicker(host.connectTimeout / 2)
		defer t.Stop()
		for range t.C {
			_, _, err := host.sshc.Conn.SendRequest("", true, nil)
			if err != nil {
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

func (host *OsshHost) sshRun(c chan *OsshMessage, config *ssh.ClientConfig, command string) {
	var err error
	if host.sshc == nil {
		host.sshConnect(c, config)
		if host.err != nil {
			return
		}
	}

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

	err = session.Run(command)
	// if err is nil ssh command returned 0
	if err != nil {
		if err, ok := err.(*ssh.ExitError); ok {
			host.exitStatus = err.ExitStatus()
		}
	}

	//session.Close()
	host.sshc.Close()
	c <- &OsshMessage{
		data:        "",
		messageType: STATUS | EXIT,
		host:        host,
	}
}
