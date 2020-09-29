package main

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// OsshDisaptcher ...
type OsshDisaptcher struct {
	par             int
	command         string
	sshClientConfig *ssh.ClientConfig
	hosts           []OsshHost
	preconnect      bool
	ignoreFailures  bool
}

func (d *OsshDisaptcher) validate() error {
	var errList []string
	if d.par < 1 {
		errList = append(errList, "parallelism should be > 0")
	}
	if len(d.command) == 0 {
		errList = append(errList, "no command is specified")
	}
	if len(d.hosts) == 0 {
		errList = append(errList, "host list is empty")
	}
	if len(errList) > 0 {
		return errors.New(strings.Join(errList, "\n"))
	}
	return nil
}

func (d *OsshDisaptcher) run() error {
	var failureCount int
	hostIdx := 0
	c := make(chan *OsshMessage)
	if d.preconnect {
		for hostIdx = 0; hostIdx < len(d.hosts); hostIdx++ {
			go (&d.hosts[hostIdx]).sshConnect(c, d.sshClientConfig)
		}
		for hostIdx = 0; hostIdx < len(d.hosts); hostIdx++ {
			message, ok := <-c
			if ok == false {
				return fmt.Errorf("channel got closed unexpectedly, exiting")
			}
			if (message.messageType & ERROR) != 0 {
				message.println()
				failureCount++
			} else if (message.messageType & VERBOSE) != 0 {
				message.println()
			}
		}
	}
	if !d.ignoreFailures && failureCount > 0 {
		return fmt.Errorf("failed to connect to %d hosts, exiting", failureCount)
	}
	running := 0
	for hostIdx = 0; hostIdx < len(d.hosts) && running < d.par; hostIdx++ {
		if d.hosts[hostIdx].err != nil {
			continue
		}
		go (&d.hosts[hostIdx]).sshRun(c, d.sshClientConfig, d.command)
		running++
	}
	for running > 0 {
		message, ok := <-c
		if ok == false {
			break
		}
		if (message.messageType & ERROR) != 0 {
			message.println()
			running--
		} else if (message.messageType & STATUS) != 0 {
			running--
		} else {
			message.println()
			continue
		}
		if hostIdx < len(d.hosts) {
			go (&d.hosts[hostIdx]).sshRun(c, d.sshClientConfig, d.command)
			running++
			hostIdx++
		}
	}
	return nil
}
