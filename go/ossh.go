// https://github.com/thimoonxy/go-pssh
// https://github.com/xuchenCN/go-psshA
// https://github.com/reconquest/orgalorg
// https://github.com/YuriyNasretdinov/GoSSHa
package main

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kujtimiihoxha/go-brace-expansion"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
)

func PublicKeyFile(file string) (ssh.AuthMethod, error) {
	var key ssh.Signer
	var err error
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	p, rest := pem.Decode(buffer)
	if len(rest) > 0 {
		return nil, errors.New("Failed to decode the key \"" + file + "\"")
	}
	pBlock := pem.Block{
		Bytes:   buffer,
		Type:    p.Type,
		Headers: p.Headers,
	}
	if x509.IsEncryptedPEMBlock(&pBlock) {
		fmt.Printf("SSH Passphrase: ")
		bytePassword, _ := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Printf("\n")
		key, err = ssh.ParsePrivateKeyWithPassphrase(buffer, bytePassword)
	} else {
		key, err = ssh.ParsePrivateKey(buffer)
	}
	if err != nil {
		return nil, err
	}
	return ssh.PublicKeys(key), nil
}

func getSshClientConfig(logname *string, key *string, password string) (*ssh.ClientConfig, error) {
	var authMethod []ssh.AuthMethod
	if len(password) > 0 {
		authMethod = append(authMethod, ssh.Password(password))
	}
	if len(*key) != 0 {
		publicKeyFile, err := PublicKeyFile(*key)
		if err != nil {
			return nil, err
		}
		authMethod = append(authMethod, publicKeyFile)
	}
	// ssh-agent has a UNIX socket under $SSH_AUTH_SOCK
	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		// Use a callback rather than PublicKeys
		// so we only consult the agent once the remote server
		// wants it.
		authMethod = append(authMethod, ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers))
	}
	if len(authMethod) == 0 {
		return nil, errors.New("No authentication method provided")
	}
	return &ssh.ClientConfig{
		User:            *logname,
		Auth:            authMethod,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}, nil
}

func getLabel(hostAddr string, maxLabelLength *int) string {
	if len(hostAddr) > *maxLabelLength {
		*maxLabelLength = len(hostAddr)
	}
	return hostAddr
}

func main() {
	var err error
	var hosts []OsshHost
	var failureCount int
	var bytePassword []byte
	hostIdx := 0
	maxLabelLength := 0
	useColor = terminal.IsTerminal(int(os.Stdout.Fd()))
	var settings OsshSettings
	settings.parseCliOptions()
	if len(settings.inventoryList) > 0 {
		var out []byte
		if out, err = exec.Command(settings.inventoryPath, settings.inventoryList...).Output(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		for _, h := range strings.Split(string(out), "\n") {
			host := strings.Split(h, " ")
			if len(host) < 2 {
				continue
			}
			if len(host[0]) > maxLabelLength {
				maxLabelLength = len(host[0])
			}
			hosts = append(hosts, OsshHost{
				address:        host[1],
				label:          host[0],
				port:           *(settings.port),
				status:         0,
				err:            nil,
				connectTimeout: time.Duration(*(settings.connectTimeout)) * time.Second,
				runTimeout:     time.Duration(*(settings.runTimeout)) * time.Second,
			})
			hostIdx += 1
		}
	}
	for _, hostFile := range settings.hostFiles {
		file, err := os.Open(hostFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		scanner := bufio.NewScanner(file)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "#") {
				continue
			}
			settings.hostStrings = append(settings.hostStrings, line)
		}
		defer file.Close()
	}
	for _, hostString := range settings.hostStrings {
		for _, hs := range strings.Split(hostString, " ") {
			for _, h := range gobrex.Expand(hs) {
				host := strings.Split(h, ":")
				hostAddress := host[0]
				hostPort := *(settings.port)
				if len(host) > 1 {
					hostPort, err = strconv.Atoi(host[1])
					if err != nil {
						fmt.Println(err)
						os.Exit(1)
					}

				}
				hosts = append(hosts, OsshHost{
					address:        hostAddress,
					label:          getLabel(hostAddress, &maxLabelLength),
					port:           hostPort,
					status:         0,
					err:            nil,
					connectTimeout: time.Duration(*(settings.connectTimeout)) * time.Second,
					runTimeout:     time.Duration(*(settings.runTimeout)) * time.Second,
				})
				hostIdx += 1
			}
		}
	}
	if *(settings.askpass) {
		fmt.Printf("SSH password: ")
		bytePassword, _ = terminal.ReadPassword(int(syscall.Stdin))
		fmt.Printf("\n")
	}
	command := strings.Join(settings.commandStrings, "\n")
	sshClientConfig, err := getSshClientConfig(settings.logname, settings.key, string(bytePassword))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
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
				failureCount += 1
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
		running += 1
	}
	for running > 0 {
		message, ok := <-c
		if ok == false {
			break
		}
		if (message.messageType & ERROR) != 0 {
			message.println()
			running -= 1
		} else if (message.messageType & EXIT) != 0 {
			message.host.status |= message.messageType
			if message.host.status == EXIT|STDOUT|STDERR|STATUS {
				running -= 1
			}
		} else {
			message.println()
			continue
		}
		if hostIdx < len(hosts) {
			go (&hosts[hostIdx]).sshRun(c, sshClientConfig, command)
			running += 1
			hostIdx += 1
		}
	}
}
