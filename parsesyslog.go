// Package parsesyslog implements a syslog message parser for different RFC log formats
package parsesyslog

import (
	"errors"
	"io"
	"sync"
)

var (
	// lock protects the types during Register()
	lock sync.RWMutex

	// types is a map of installed message parser types, supplying a function that
	//creates a new instance of that Parser.
	types = map[ParserType]func() (Parser, error){}
)

var (
	// ErrUnknownParserType is returned if a Parser is requested via New() which is not registered
	ErrUnknownParserType = errors.New("unknown parser type")
)

// Parser defines the interface for parsing different types of Syslog messages
type Parser interface {
	ParseReader(io.Reader) (LogMsg, error)
	ParseString(s string) (LogMsg, error)
}

// ParserType is a type of parser for logs messages
type ParserType string

// Register does something
func Register(t ParserType, fn func() (Parser, error)) {
	lock.Lock()
	defer lock.Unlock()
	// if already registered, leave
	if _, ok := types[t]; ok {
		return
	}
	types[t] = fn
}

// New returns a new Parser based on the given parameter
func New(t ParserType) (Parser, error) {
	p, ok := types[t]
	if !ok {
		return nil, ErrUnknownParserType
	}
	return p()
}
