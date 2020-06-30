// https://github.com/thimoonxy/go-pssh
// https://github.com/xuchenCN/go-psshA
// https://github.com/reconquest/orgalorg
// https://github.com/YuriyNasretdinov/GoSSHa
package main

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh/terminal"
)

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
	dispatcher := &(OsshDisaptcher{})
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
	err = dispatcher.validate()
	abortOnError(err)
	err = dispatcher.run()
	abortOnError(err)
}
