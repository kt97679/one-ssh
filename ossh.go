package main

import (
	"os"

	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	var err error
	useColor = terminal.IsTerminal(int(os.Stdout.Fd()))
	settings := &OsshSettings{}
	settings.parseCliOptions()
	dispatcher := &(OsshDisaptcher{
		par:             *settings.par,
		ignoreFailures:  *settings.ignoreFailures,
		preconnect:      *settings.preconnect,
		socks5ProxyAddr: *settings.socks5ProxyAddr,
	})
	dispatcher.command, err = settings.getCommand()
	abortOnError(err)
	dispatcher.sshClientConfig, err = settings.getSSHClientConfig()
	abortOnError(err)
	dispatcher.hosts, err = settings.getHosts()
	abortOnError(err)
	err = dispatcher.validate()
	abortOnError(err)
	err = dispatcher.run()
	abortOnError(err)
}
