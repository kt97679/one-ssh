package main

import (
	"fmt"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

func readBytePasswordFromTerminal(prompt string) []byte {
	fmt.Printf("%s ", prompt)
	bytePassword, _ := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Printf("\n")
	return bytePassword
}
