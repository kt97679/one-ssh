package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/pborman/getopt/v2"
	"golang.org/x/crypto/ssh/terminal"
)

// we need to define new type because by default getopt will split
// string arguments for the string lists using ',' as a delimiter
// New type should implement getopt.Value interface

type arrayFlags []string

func (i *arrayFlags) String() string {
	return ""
}

func (i *arrayFlags) Set(value string, option getopt.Option) error {
	*i = append(*i, value)
	return nil
}

type OsshSettings struct {
	hostStrings    arrayFlags
	commandStrings arrayFlags
	hostFiles      arrayFlags
	inventoryPath  string
	inventoryList  arrayFlags
	logname        *string
	key            *string
	par            *int
	preconnect     *bool
	ignoreFailures *bool
	port           *int
	connectTimeout *int
	runTimeout     *int
	password       string
}

func (s *OsshSettings) parseCliOptions() {
	var err error
	s.logname = getopt.StringLong("user", 'l', os.Getenv("LOGNAME"), "Username for connections", "USER")
	s.key = getopt.StringLong("key", 'k', "", "Use this private key", "PRIVATE_KEY")
	optHelp := getopt.BoolLong("help", '?', "Show help")
	getopt.FlagLong(&(s.hostStrings), "host", 'H', "Add the given HOST_STRING to the list of hosts", "HOST_STRING")
	getopt.FlagLong(&(s.hostFiles), "hosts", 'h', "Read hosts from file", "HOST_FILE")
	getopt.FlagLong(&(s.commandStrings), "command", 'c', "Command to run", "COMMAND")
	s.par = getopt.IntLong("par", 'p', 512, "How many hosts to run simultaneously", "PARALLELISM")
	s.preconnect = getopt.BoolLong("preconnect", 'P', "Connect to all hosts before running command")
	s.ignoreFailures = getopt.BoolLong("ignore-failures", 'i', "Ignore connection failures in the preconnect mode")
	verbose = getopt.BoolLong("verbose", 'v', "Verbose output")
	s.port = getopt.IntLong("port", 'o', 22, "Port to connect to", "PORT")
	s.connectTimeout = getopt.IntLong("connect-timeout", 'T', 60, "Connect timeout in seconds", "TIMEOUT")
	s.runTimeout = getopt.IntLong("timeout", 't', 0, "Run timeout in seconds", "TIMEOUT")
	askpass := getopt.BoolLong("askpass", 'A', "Prompt for a password for ssh connects")
	if s.inventoryPath, err = exec.LookPath("ossh-inventory"); err == nil {
		getopt.FlagLong(&(s.inventoryList), "inventory", 'I', "Use FILTER expression to select hosts from inventory", "FILTER")
	}
	getopt.Parse()

	if *optHelp {
		getopt.Usage()
		os.Exit(0)
	}
	if *askpass {
		fmt.Printf("SSH password: ")
		bytePassword, _ := terminal.ReadPassword(int(syscall.Stdin))
		s.password = string(bytePassword)
		fmt.Printf("\n")
	}
}
