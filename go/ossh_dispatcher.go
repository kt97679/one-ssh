package main

import (
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// OsshDisaptcher ...
type OsshDisaptcher struct {
}

func (d *OsshDisaptcher) run(settings *OsshSettings, hosts []OsshHost, sshClientConfig *ssh.ClientConfig, command string) {
	var failureCount int
	hostIdx := 0
	c := make(chan *OsshMessage)
	if *(settings.preconnect) {
		for hostIdx = 0; hostIdx < len(hosts); hostIdx++ {
			go (&hosts[hostIdx]).sshConnect(c, sshClientConfig)
		}
		for hostIdx = 0; hostIdx < len(hosts); hostIdx++ {
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
	if (!*(settings.ignoreFailures)) && failureCount > 0 {
		fmt.Printf("Error: failed to connect to %d hosts, exiting.\n", failureCount)
		os.Exit(1)
	}
	running := 0
	for hostIdx = 0; hostIdx < len(hosts) && running < *(settings.par); hostIdx++ {
		if hosts[hostIdx].err != nil {
			continue
		}
		go (&hosts[hostIdx]).sshRun(c, sshClientConfig, command)
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
		if hostIdx < len(hosts) {
			go (&hosts[hostIdx]).sshRun(c, sshClientConfig, command)
			running++
			hostIdx++
		}
	}
}
