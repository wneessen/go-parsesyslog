// Package parsesyslog implements a syslog message parser for different RFC log formats
package parsesyslog

import "io"

// Parser defines the interface for parsing different types of Syslog messages
type Parser interface {
	ParseReader(io.Reader) (LogMsg, error)
}
