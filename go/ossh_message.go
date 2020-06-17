package main

import (
	"fmt"
)

var useColor bool
var verbose *bool

//
const (
	STDOUT  = 1
	STDERR  = 2
	EXIT    = 4
	ERROR   = 8
	STATUS  = 16
	VERBOSE = 32
)

// OsshMessage ...
type OsshMessage struct {
	data        string
	messageType int
	host        *OsshHost
}

var hostColor = map[int]int{
	ERROR:   31, // red
	STDOUT:  36, // cyan
	STDERR:  33, // yellow
	VERBOSE: 32, // green
}

var hostSuffix = map[int]string{
	ERROR:   "[!]",
	STDOUT:  "[1]",
	STDERR:  "[2]",
	VERBOSE: "[v]",
}

func (m *OsshMessage) println() {
	if m.messageType == VERBOSE && !*verbose {
		return
	}
	out := m.data
	if m.messageType == ERROR {
		out = m.host.err.Error()
	}
	if useColor {
		fmt.Printf("\033[%dm%s\033[0m %s\n", hostColor[m.messageType], m.host.label, out)
	} else {
		fmt.Printf("%s %s %s\n", m.host.label, hostSuffix[m.messageType], out)
	}
}
