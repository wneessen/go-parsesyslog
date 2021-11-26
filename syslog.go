// Package syslog implements a syslog message parser for different RFC log formats
package syslog

import "io"

// Parser defines the interface for parsing different types of Syslog messages
type Parser interface {
	ParseReader(r io.Reader) (LogMsg, error)
}
