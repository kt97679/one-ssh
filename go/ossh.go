package main

import (
	"os"
	"strings"

	"golang.org/x/crypto/ssh/terminal"
)

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
