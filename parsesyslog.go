// SPDX-FileCopyrightText: 2021-2023 Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

// Package parsesyslog implements a syslog message parser for different
// RFC log formats
package parsesyslog

import (
	"io"
	"sync"
)

var (
	// lock ensures thread-safe access to the types map during registration operations.
	lock sync.RWMutex

	// types is a registry mapping ParserType to factory functions that create new Parser instances.
	types = map[ParserType]newFunc{}
)

// Parser defines an interface for parsing Syslog messages from various input sources into LogMsg objects.
type Parser interface {
	ParseReader(io.Reader) (LogMsg, error)
	ParseString(s string) (LogMsg, error)
}

// newFunc is a function type that defines a factory for creating a new Parser instance, returning the
// Parser and an error.
type newFunc func() (Parser, error)

// ParserType is an alias type for a string. It represents a type of parser used to process and
// interpret log messages.
type ParserType string

// Register adds a new parser factory function for a specified ParserType if it is not already registered.
func Register(parserType ParserType, newFunc newFunc) {
	lock.Lock()
	defer lock.Unlock()
	if _, ok := types[parserType]; ok {
		return
	}
	types[parserType] = newFunc
}

// New creates a new Parser instance based on the provided ParserType.
// Returns an error if the requested ParserType is not registered.
// The ParserType must correspond to a key in the internal types registry.
func New(t ParserType) (Parser, error) {
	if newParser, ok := types[t]; ok {
		return newParser()
	}
	return nil, ErrParserTypeUnknown
}
