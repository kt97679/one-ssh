package main

import (
	"bufio"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
)

type OsshHost struct {
	address    string
	label      string
	port       int
	status     int
	err        error
	exitStatus int
	sshc       *ssh.Client
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
	host.sshc, err = ssh.Dial("tcp", fmt.Sprintf("%s:%d", host.address, host.port), config)
	if err != nil {
		host.markHostFailed(c, err)
		return
	} else {
		c <- &OsshMessage{
			data:        "connected",
			messageType: VERBOSE,
			host:        host,
		}
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
			fmt.Println("exit code: ", err.ExitStatus())
			host.exitStatus = err.ExitStatus()
		} else {
			host.markHostFailed(c, err)
		}
	}
	c <- &OsshMessage{
		data:        "",
		messageType: STATUS | EXIT,
		host:        host,
	}
	host.sshc.Close()
}
