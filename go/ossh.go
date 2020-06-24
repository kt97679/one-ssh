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

	gobrex "github.com/kujtimiihoxha/go-brace-expansion"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
)

func publicKeyFile(file string) (ssh.AuthMethod, error) {
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

func getSSHClientConfig(logname *string, key *string, password string) (*ssh.ClientConfig, error) {
	var authMethod []ssh.AuthMethod
	if len(password) > 0 {
		authMethod = append(authMethod, ssh.Password(password))
	}
	if len(*key) != 0 {
		publicKeyFile, err := publicKeyFile(*key)
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
	var dispatcher OsshDisaptcher
	var err error
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
			dispatcher.hosts = append(dispatcher.hosts, OsshHost{
				address:        host[1],
				label:          host[0],
				port:           *(settings.port),
				status:         0,
				err:            nil,
				connectTimeout: time.Duration(*(settings.connectTimeout)) * time.Second,
				runTimeout:     time.Duration(*(settings.runTimeout)) * time.Second,
			})
			hostIdx++
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
				dispatcher.hosts = append(dispatcher.hosts, OsshHost{
					address:        hostAddress,
					label:          getLabel(hostAddress, &maxLabelLength),
					port:           hostPort,
					status:         0,
					err:            nil,
					connectTimeout: time.Duration(*(settings.connectTimeout)) * time.Second,
					runTimeout:     time.Duration(*(settings.runTimeout)) * time.Second,
				})
				hostIdx++
			}
		}
	}
	dispatcher.command = strings.Join(settings.commandStrings, "\n")
	dispatcher.sshClientConfig, err = getSSHClientConfig(settings.logname, settings.key, settings.password)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	dispatcher.par = *settings.par
	dispatcher.ignoreFailures = *settings.ignoreFailures
	dispatcher.preconnect = *settings.preconnect
	(&dispatcher).run()
}
