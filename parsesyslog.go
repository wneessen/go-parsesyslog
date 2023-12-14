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
	// lock protects the types during Register()
	lock sync.RWMutex

	// types is a map of installed message parser types, supplying a function that
	// creates a new instance of that Parser.
	types = map[ParserType]func() (Parser, error){}
)

// Parser is an interface for parsing log messages.
type Parser interface {
	ParseReader(io.Reader) (LogMsg, error)
	ParseString(s string) (LogMsg, error)
}

// ParserType is a type of parser for logs messages
type ParserType string

// Register registers a new ParserType with its corresponding
// Parser function.
func Register(t ParserType, fn func() (Parser, error)) {
	lock.Lock()
	defer lock.Unlock()
	// if already registered, leave
	if _, ok := types[t]; ok {
		return
	}
	types[t] = fn
}

// New returns a Parser of the specified ParserType and an error.
// It looks up the ParserType in the types map and if found,
// calls the corresponding Parser function to create a new Parser
// instance.
//
// If the ParserType is not found in the map, it returns nil
// and ErrParserTypeUnknown.
func New(t ParserType) (Parser, error) {
	p, ok := types[t]
	if !ok {
		return nil, ErrParserTypeUnknown
	}
	return p()
}
