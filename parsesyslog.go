// Package parsesyslog implements a syslog message parser for different RFC log formats
package parsesyslog

import (
	"bufio"
	"io"
	"strings"
)

// Parser defines the interface for parsing different types of Syslog messages
type Parser interface {
	parseReader(io.Reader) (LogMsg, error)
}

// NewRFC5424Parser returns a new Parser for RFC5424 messages
func NewRFC5424Parser() *RFC5424Msg {
	return &RFC5424Msg{}
}

/*
// NewRFC3164Parser returns a new Parser for RFC3164 messages
func NewRFC3164Parser() *RFC3164Msg {
	return &RFC3164Msg{}
}

*/

// ParseReader returns the parsed log message based on the given parser
// interface read from the io.Reader
func ParseReader(p Parser, r io.Reader) (LogMsg, error) {
	return p.parseReader(r)
}

// ParseString returns the parsed log message based on the given parser
// interface read from a string (as buffered i/o)
func ParseString(p Parser, s string) (LogMsg, error) {
	sr := strings.NewReader(s)
	br := bufio.NewReader(sr)
	return p.parseReader(br)
}
