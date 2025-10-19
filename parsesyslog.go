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
	types = map[ParserType]func() (Parser, error){}
)

// Parser defines an interface for parsing log messages from various inputs.
// It supports parsing from an io.Reader or a raw string.
type Parser interface {
	ParseReader(io.Reader) (LogMsg, error)
	ParseString(s string) (LogMsg, error)
}

// ParserType is an alias type for a string. It represents a type of parser used to process and
// interpret log messages.
type ParserType string

// Register adds a new parser factory function for a specified ParserType if it is not already registered.
func Register(parserType ParserType, registerFn func() (Parser, error)) {
	lock.Lock()
	defer lock.Unlock()
	if _, ok := types[parserType]; ok {
		return
	}
	types[parserType] = registerFn
}

// New creates a new Parser instance based on the provided ParserType.
// Returns an error if the requested ParserType is not registered.
// The ParserType must correspond to a key in the internal types registry.
func New(t ParserType) (Parser, error) {
	p, ok := types[t]
	if !ok {
		return nil, ErrParserTypeUnknown
	}
	return p()
}
