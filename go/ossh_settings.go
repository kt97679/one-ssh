package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	gobrex "github.com/kujtimiihoxha/go-brace-expansion"
	"github.com/pborman/getopt/v2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
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

// OsshSettings ...
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
	maxLabelLength *int
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

func (s *OsshSettings) getInventoryHosts(hosts []OsshHost) []OsshHost {
	if len(s.inventoryList) > 0 {
		var out []byte
		var err error
		if out, err = exec.Command(s.inventoryPath, s.inventoryList...).Output(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		for _, h := range strings.Split(string(out), "\n") {
			host := strings.Split(h, " ")
			if len(host) < 2 {
				continue
			}
			if len(host[0]) > *s.maxLabelLength {
				*s.maxLabelLength = len(host[0])
			}
			hosts = append(hosts, OsshHost{
				address:        host[1],
				label:          host[0],
				port:           *(s.port),
				status:         0,
				err:            nil,
				connectTimeout: time.Duration(*(s.connectTimeout)) * time.Second,
				runTimeout:     time.Duration(*(s.runTimeout)) * time.Second,
			})
		}
	}
	return hosts
}

func (s *OsshSettings) processHostFiles() {
	for _, hostFile := range s.hostFiles {
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
			s.hostStrings = append(s.hostStrings, line)
		}
		defer file.Close()
	}
}

func (s *OsshSettings) processHostStrings(hosts []OsshHost) []OsshHost {
	var err error
	for _, hostString := range s.hostStrings {
		for _, hs := range strings.Split(hostString, " ") {
			for _, h := range gobrex.Expand(hs) {
				host := strings.Split(h, ":")
				hostAddress := host[0]
				hostPort := *(s.port)
				if len(host) > 1 {
					hostPort, err = strconv.Atoi(host[1])
					if err != nil {
						fmt.Println(err)
						os.Exit(1)
					}

				}
				hosts = append(hosts, OsshHost{
					address:        hostAddress,
					label:          getLabel(hostAddress, s.maxLabelLength),
					port:           hostPort,
					status:         0,
					err:            nil,
					connectTimeout: time.Duration(*(s.connectTimeout)) * time.Second,
					runTimeout:     time.Duration(*(s.runTimeout)) * time.Second,
				})
			}
		}
	}
	return hosts
}

func (s *OsshSettings) getHosts() []OsshHost {
	var hosts []OsshHost
	s.maxLabelLength = new(int)
	hosts = s.getInventoryHosts(hosts)
	s.processHostFiles()
	hosts = s.processHostStrings(hosts)
	return hosts
}

func (s *OsshSettings) getSSHClientConfig() (*ssh.ClientConfig, error) {
	var authMethod []ssh.AuthMethod
	if len(s.password) > 0 {
		authMethod = append(authMethod, ssh.Password(s.password))
	}
	if len(*s.key) != 0 {
		publicKeyFile, err := publicKeyFile(*s.key)
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
		User:            *s.logname,
		Auth:            authMethod,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}, nil
}
