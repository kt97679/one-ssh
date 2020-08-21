package main

import (
	"os"
	"strings"

	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	var err error
	useColor = terminal.IsTerminal(int(os.Stdout.Fd()))
	settings := &OsshSettings{}
	settings.parseCliOptions()
	dispatcher := &(OsshDisaptcher{
		command:        strings.Join(settings.commandStrings, "\n"),
		par:            *settings.par,
		ignoreFailures: *settings.ignoreFailures,
		preconnect:     *settings.preconnect,
	})
	dispatcher.sshClientConfig, err = settings.getSSHClientConfig()
	abortOnError(err)
	dispatcher.hosts, err = settings.getHosts()
	abortOnError(err)
	err = dispatcher.validate()
	abortOnError(err)
	err = dispatcher.run()
	abortOnError(err)
}
