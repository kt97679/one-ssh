// https://github.com/thimoonxy/go-pssh
// https://github.com/xuchenCN/go-psshA
// https://github.com/reconquest/orgalorg
// https://github.com/YuriyNasretdinov/GoSSHa
package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"syscall"

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
	useColor = terminal.IsTerminal(int(os.Stdout.Fd()))
	settings := &OsshSettings{}
	settings.parseCliOptions()
	dispatcher.command = strings.Join(settings.commandStrings, "\n")
	dispatcher.sshClientConfig, err = getSSHClientConfig(settings.logname, settings.key, settings.password)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	dispatcher.hosts = settings.getHosts()
	dispatcher.par = *settings.par
	dispatcher.ignoreFailures = *settings.ignoreFailures
	dispatcher.preconnect = *settings.preconnect
	(&dispatcher).run()
}
