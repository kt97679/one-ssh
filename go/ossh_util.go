package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

func readBytePasswordFromTerminal(prompt string) []byte {
	fmt.Printf("%s ", prompt)
	bytePassword, _ := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Printf("\n")
	return bytePassword
}

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
		key, err = ssh.ParsePrivateKeyWithPassphrase(buffer, readBytePasswordFromTerminal("SSH Passphrase:"))
	} else {
		key, err = ssh.ParsePrivateKey(buffer)
	}
	if err != nil {
		return nil, err
	}
	return ssh.PublicKeys(key), nil
}

func getLabel(hostAddr string) string {
	// addr, err := net.LookupIP(hostAddr) // add is array of addresses
	// net.ParseIP(hostAddr) != nil // how to check that hostAddr is ip address
	return hostAddr
}

func abortOnError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
