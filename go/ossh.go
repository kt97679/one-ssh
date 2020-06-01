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
	"github.com/pborman/getopt/v2"
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

func get_ssh_client_config(logname *string, key *string, password string) (*ssh.ClientConfig, error) {
	var auth_method []ssh.AuthMethod
	if len(password) > 0 {
		auth_method = append(auth_method, ssh.Password(password))
	}
	if len(*key) != 0 {
		public_key_file, err := PublicKeyFile(*key)
		if err != nil {
			return nil, err
		}
		auth_method = append(auth_method, public_key_file)
	}
	// ssh-agent has a UNIX socket under $SSH_AUTH_SOCK
	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		// Use a callback rather than PublicKeys
		// so we only consult the agent once the remote server
		// wants it.
		auth_method = append(auth_method, ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers))
	}
	if len(auth_method) == 0 {
		return nil, errors.New("No authentication method provided")
	}
	return &ssh.ClientConfig{
		User:            *logname,
		Auth:            auth_method,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}, nil
}

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

func main() {
	var host_strings arrayFlags
	var commandStrings arrayFlags
	var hosts []OsshHost
	var failure_count int
	var bytePassword []byte
	var err error
	var inventoryPath string
	var inventoryList arrayFlags
	hostIdx := 0
	useColor = terminal.IsTerminal(int(os.Stdout.Fd()))
	logname := getopt.StringLong("user", 'l', os.Getenv("LOGNAME"), "Username for connections", "USER")
	key := getopt.StringLong("key", 'k', "", "Use this private key", "PRIVATE_KEY")
	optHelp := getopt.BoolLong("help", '?', "Show help")
	getopt.FlagLong(getopt.Value(&host_strings), "host", 'H', "Add the given HOST_STRING to the list of hosts", "HOST_STRING")
	getopt.FlagLong(&commandStrings, "command", 'c', "Command to run", "COMMAND")
	par := getopt.IntLong("par", 'p', 512, "How many hosts to run simultaneously", "PARALLELISM")
	preconnect := getopt.BoolLong("preconnect", 'P', "Connect to all hosts before running command")
	ignore_failures := getopt.BoolLong("ignore-failures", 'i', "Ignore connection failures in the preconnect mode")
	verbose = getopt.BoolLong("verbose", 'v', "Verbose output")
	port := getopt.IntLong("port", 'o', 22, "Port to connect to", "PORT")
	connectTimeout := getopt.IntLong("connect-timeout", 'T', 60, "Connect timeout in seconds", "TIMEOUT")
	runTimeout := getopt.IntLong("timeout", 't', 0, "Run timeout in seconds", "TIMEOUT")
	askpass := getopt.BoolLong("askpass", 'A', "Prompt for a password for ssh connects")
	if inventoryPath, err = exec.LookPath("ossh-inventory"); err == nil {
		getopt.FlagLong(&inventoryList, "inventory", 'I', "Use FILTER expression to select hosts from inventory", "FILTER")
	}
	getopt.Parse()

	if *optHelp {
		getopt.Usage()
		os.Exit(0)
	}
	if len(inventoryList) > 0 {
		var out []byte
		if out, err = exec.Command(inventoryPath, inventoryList...).Output(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		for _, h := range strings.Split(string(out), "\n") {
			host := strings.Split(h, " ")
			if len(host) < 2 {
				continue
			}
			hosts = append(hosts, OsshHost{
				address:        host[1],
				label:          host[0],
				port:           *port,
				status:         0,
				err:            nil,
				connectTimeout: time.Duration(*connectTimeout) * time.Second,
				runTimeout:     time.Duration(*runTimeout) * time.Second,
			})
			hostIdx += 1
		}
	}
	for _, host_string := range host_strings {
		for _, hs := range strings.Split(host_string, " ") {
			for _, h := range gobrex.Expand(hs) {
				host := strings.Split(h, ":")
				host_address := host[0]
				host_port := *port
				if len(host) > 1 {
					host_port, err = strconv.Atoi(host[1])
					if err != nil {
						fmt.Println(err)
						os.Exit(1)
					}

				}
				hosts = append(hosts, OsshHost{
					address:        host_address,
					label:          host_address,
					port:           host_port,
					status:         0,
					err:            nil,
					connectTimeout: time.Duration(*connectTimeout) * time.Second,
					runTimeout:     time.Duration(*runTimeout) * time.Second,
				})
				hostIdx += 1
			}
		}
	}
	if *askpass {
		fmt.Printf("SSH password: ")
		bytePassword, _ = terminal.ReadPassword(int(syscall.Stdin))
		fmt.Printf("\n")
	}
	command := strings.Join(commandStrings, "\n")
	ssh_client_config, err := get_ssh_client_config(logname, key, string(bytePassword))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	c := make(chan *OsshMessage)
	if *preconnect {
		for hostIdx = 0; hostIdx < len(hosts); hostIdx++ {
			go (&hosts[hostIdx]).sshConnect(c, ssh_client_config)
		}
		for hostIdx = 0; hostIdx < len(hosts); hostIdx++ {
			message, ok := <-c
			if ok == false {
				fmt.Println("Error: channel got closed unexpectidly, exiting.")
				os.Exit(1)
			}
			if (message.messageType & ERROR) != 0 {
				message.println()
				failure_count += 1
			} else if (message.messageType & VERBOSE) != 0 {
				message.println()
			}
		}
	}
	if (!*ignore_failures) && failure_count > 0 {
		fmt.Printf("Error: failed to connect to %d hosts, exiting.\n", failure_count)
		os.Exit(1)
	}
	running := 0
	for hostIdx = 0; hostIdx < len(hosts) && running < *par; hostIdx++ {
		if hosts[hostIdx].err != nil {
			continue
		}
		go (&hosts[hostIdx]).sshRun(c, ssh_client_config, command)
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
			go (&hosts[hostIdx]).sshRun(c, ssh_client_config, command)
			running += 1
			hostIdx += 1
		}
	}
}
