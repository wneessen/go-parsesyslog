// SPDX-FileCopyrightText: 2021-2023 Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package parsesyslog

import "errors"

var (
	// ErrInvalidPrio should be used if the PRI part of the message is not following the log format
	ErrInvalidPrio = errors.New("PRI header not a valid priority string")
	// ErrInvalidProtoVersion should be used if the protocol version part of the header is not following the log format
	ErrInvalidProtoVersion = errors.New("protocol version string invalid")
	// ErrInvalidTimestamp should be used if it was not possible to parse the timestamp of the log message
	ErrInvalidTimestamp = errors.New("timestamp does not conform the logging format")
	// ErrParserTypeUnknown is returned if a Parser is requested via New() which is not registered
	ErrParserTypeUnknown = errors.New("unknown parser type")
	// ErrPrematureEOF should be used in case a log message ends before the provided length
	ErrPrematureEOF = errors.New("log message is shorter than the expected length")
	// ErrWrongFormat should be used if a log messages does not comply with the logging format definitions
	ErrWrongFormat = errors.New("log message does not conform the logging format")
	// ErrWrongSDFormat should be used in case the structured data is not parsable
	ErrWrongSDFormat = errors.New("structured data does not conform the format")
	// ErrInvalidLength should be used if the length of the log message does not match the provided length
	ErrInvalidLength = errors.New("log message does not match the provided length value")
	// ErrInvalidNumber should be used if the number is not valid
	ErrInvalidNumber = errors.New("invalid number")
)
