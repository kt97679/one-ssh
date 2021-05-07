package main

import (
	"bufio"
	"errors"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	gobrex "github.com/kujtimiihoxha/go-brace-expansion"
	"github.com/pborman/getopt/v2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
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
	hostStrings     arrayFlags
	commandStrings  arrayFlags
	hostFiles       arrayFlags
	commandFiles    arrayFlags
	inventoryPath   string
	inventoryList   arrayFlags
	logname         *string
	key             *string
	par             *int
	preconnect      *bool
	showip          *bool
	ignoreFailures  *bool
	port            *int
	connectTimeout  *int
	runTimeout      *int
	password        string
	maxLabelLength  *int
	socks5ProxyAddr *string
}

func (s *OsshSettings) parseCliOptions() {
	var err error
	s.logname = getopt.StringLong("user", 'l', os.Getenv("LOGNAME"), "Username for connections", "USER")
	s.key = getopt.StringLong("key", 'k', "", "Use this private key", "PRIVATE_KEY")
	s.socks5ProxyAddr = getopt.StringLong("proxy-addr", 'a', "", "Use socks5 proxy for connection", "SOCKS5_PROXY_ADDR")
	optHelp := getopt.BoolLong("help", '?', "Show help")
	getopt.FlagLong(&(s.hostStrings), "host", 'H', "Add the given HOST_STRING to the list of hosts", "HOST_STRING")
	getopt.FlagLong(&(s.hostFiles), "hosts", 'h', "Read hosts from file", "HOST_FILE")
	getopt.FlagLong(&(s.commandStrings), "command", 'c', "Command to run", "COMMAND")
	getopt.FlagLong(&(s.commandFiles), "command-file", 'C', "file with commands to run", "COMMAND_FILE")
	s.par = getopt.IntLong("par", 'p', 512, "How many hosts to run simultaneously", "PARALLELISM")
	s.preconnect = getopt.BoolLong("preconnect", 'P', "Connect to all hosts before running command")
	s.ignoreFailures = getopt.BoolLong("ignore-failures", 'i', "Ignore connection failures in the preconnect mode")
	verbose = getopt.BoolLong("verbose", 'v', "Verbose output")
	s.port = getopt.IntLong("port", 'o', 22, "Port to connect to", "PORT")
	s.connectTimeout = getopt.IntLong("connect-timeout", 'T', 60, "Connect timeout in seconds", "TIMEOUT")
	s.runTimeout = getopt.IntLong("timeout", 't', 0, "Run timeout in seconds", "TIMEOUT")
	askpass := getopt.BoolLong("askpass", 'A', "Prompt for a password for ssh connects")
	s.showip = getopt.BoolLong("showip", 'n', "In the output show ips instead of names")
	if s.inventoryPath, err = exec.LookPath("ossh-inventory"); err == nil {
		getopt.FlagLong(&(s.inventoryList), "inventory", 'I', "Use FILTER expression to select hosts from inventory", "FILTER")
	}
	getopt.Parse()

	if *optHelp {
		getopt.Usage()
		os.Exit(0)
	}
	if *askpass {
		s.password = string(readBytePasswordFromTerminal("SSH password:"))
	}
}

func (s *OsshSettings) getCommand() (string, error) {
	var out []string
	for _, commandFile := range s.commandFiles {
		file, err := os.Open(commandFile)
		if err != nil {
			return "", err
		}
		scanner := bufio.NewScanner(file)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			line := scanner.Text()
			out = append(out, line)
		}
		defer file.Close()
	}
	out = append(out, strings.Join(s.commandStrings, "\n"))
	return strings.Join(out, "\n"), nil
}

func (s *OsshSettings) getHost(address string, label string) (*OsshHost, error) {
	var err error
	hostPort := *(s.port)
	addressAndPort := strings.Split(address, ":")
	hostAddress := addressAndPort[0]
	if len(addressAndPort) > 1 {
		if hostPort, err = strconv.Atoi(addressAndPort[1]); err != nil {
			return nil, err
		}
	}
	host := OsshHost{
		address:        hostAddress,
		label:          label,
		port:           hostPort,
		err:            nil,
		connectTimeout: time.Duration(*(s.connectTimeout)) * time.Second,
		runTimeout:     time.Duration(*(s.runTimeout)) * time.Second,
	}
	if len(*s.socks5ProxyAddr) == 0 {
		if err = host.setLabel(*s.showip); err != nil {
			return nil, err
		}
	} else {
		// if socks5 proxy is used name resolution should happen on the proxy
		// FIXME -n flag will not work
		if len(host.label) == 0 {
			host.label = host.address
		}
	}
	if len(host.label) > *s.maxLabelLength {
		*s.maxLabelLength = len(host.label)
	}
	return &host, nil
}

func (s *OsshSettings) getInventoryHosts(hosts []OsshHost) ([]OsshHost, error) {
	if len(s.inventoryList) > 0 {
		var out []byte
		var err error
		var newHost *OsshHost
		if out, err = exec.Command(s.inventoryPath, s.inventoryList...).Output(); err != nil {
			return nil, err
		}
		for _, h := range strings.Split(string(out), "\n") {
			host := strings.Split(h, " ")
			if len(host) < 2 {
				continue
			}
			if newHost, err = s.getHost(host[1], host[0]); err != nil {
				return nil, err
			}
			hosts = append(hosts, *newHost)
		}
	}
	return hosts, nil
}

func (s *OsshSettings) processHostFiles() error {
	for _, hostFile := range s.hostFiles {
		file, err := os.Open(hostFile)
		if err != nil {
			return err
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
	return nil
}

func (s *OsshSettings) processHostStrings(hosts []OsshHost) ([]OsshHost, error) {
	var err error
	var newHost *OsshHost
	for _, hostString := range s.hostStrings {
		for _, hs := range strings.Split(hostString, " ") {
			for _, h := range gobrex.Expand(hs) {
				if newHost, err = s.getHost(h, ""); err != nil {
					return nil, err
				}
				hosts = append(hosts, *newHost)
			}
		}
	}
	return hosts, nil
}

func (s *OsshSettings) getHosts() ([]OsshHost, error) {
	var hosts []OsshHost
	var err error
	s.maxLabelLength = new(int)
	hosts, err = s.getInventoryHosts(hosts)
	if err != nil {
		return nil, err
	}
	err = s.processHostFiles()
	if err != nil {
		return nil, err
	}
	hosts, err = s.processHostStrings(hosts)
	if err != nil {
		return nil, err
	}
	// add space padding to the labels for better output formatting
	for i := 0; i < len(hosts); i++ {
		hosts[i].label = hosts[i].label + strings.Repeat(" ", *s.maxLabelLength-len(hosts[i].label))
	}
	return hosts, nil
}

func (s *OsshSettings) getSSHClientConfig() (*ssh.ClientConfig, error) {
	var authMethod []ssh.AuthMethod
	if len(s.password) > 0 {
		authMethod = append(authMethod, ssh.Password(s.password))
		authMethod = append(authMethod,
			ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				// Just send the password back for all questions
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = s.password
				}

				return answers, nil
			}),
		)
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
		// Use a callback rather than PublicKeys so we only consult the agent
		// once the remote server wants it.
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
