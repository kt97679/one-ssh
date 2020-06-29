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
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
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

func getLabel(hostAddr string, maxLabelLength *int) string {
	if len(hostAddr) > *maxLabelLength {
		*maxLabelLength = len(hostAddr)
	}
	return hostAddr
}

func abortOnError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func main() {
	var dispatcher OsshDisaptcher
	var err error
	useColor = terminal.IsTerminal(int(os.Stdout.Fd()))
	settings := &OsshSettings{}
	settings.parseCliOptions()
	dispatcher.command = strings.Join(settings.commandStrings, "\n")
	dispatcher.par = *settings.par
	dispatcher.ignoreFailures = *settings.ignoreFailures
	dispatcher.preconnect = *settings.preconnect
	dispatcher.sshClientConfig, err = settings.getSSHClientConfig()
	abortOnError(err)
	dispatcher.hosts, err = settings.getHosts()
	abortOnError(err)
	(&dispatcher).run()
}
