package main

import (
	"fmt"
	"os"

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

func (d *OsshDisaptcher) run() {
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
				fmt.Println("Error: channel got closed unexpectidly, exiting.")
				os.Exit(1)
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
		fmt.Printf("Error: failed to connect to %d hosts, exiting.\n", failureCount)
		os.Exit(1)
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
		} else if (message.messageType & EXIT) != 0 {
			message.host.status |= message.messageType
			if message.host.status == EXIT|STDOUT|STDERR|STATUS {
				running--
			}
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
}
