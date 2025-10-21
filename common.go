// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package parsesyslog

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
)

const (
	space       = ' '
	lowerThan   = '<'
	greaterThan = '>'
)

// ReadBytesUntilSpace reads bytes from the provided bufio.Reader until the first space character (' ')
// is encountered. It returns the bytes read (excluding the trailing space), the total number of bytes
// read, and any error encountered.
func ReadBytesUntilSpace(reader *bufio.Reader) ([]byte, int, error) {
	buf, err := reader.ReadSlice(space)
	if err != nil {
		return buf, len(buf), err
	}
	return buf[:len(buf)-1], len(buf), nil
}

// ParsePriority will try to parse the priority part of the RFC3164 header
// See: https://tools.ietf.org/search/rfc3164#section-4.1.1
func ParsePriority(reader *bufio.Reader, buffer *bytes.Buffer, logMessage *LogMsg) error {
	priority, err := readPriorityValue(reader, buffer)
	if err != nil {
		return err
	}
	if priority < 0 || priority > 191 {
		return ErrInvalidPrio
	}

	logMessage.Priority = Priority(priority)
	logMessage.Facility = FacilityFromPrio(logMessage.Priority)
	logMessage.Severity = SeverityFromPrio(logMessage.Priority)
	return nil
}

// readPriorityValue reads and parses the priority value enclosed in angle brackets
func readPriorityValue(reader *bufio.Reader, buffer *bytes.Buffer) (int, error) {
	buffer.Reset()

	data, err := reader.ReadByte()
	if err != nil {
		return 0, fmt.Errorf("error reading priority value: %w", err)
	}
	if data != lowerThan {
		return 0, ErrWrongFormat
	}

	for {
		data, err = reader.ReadByte()
		if err != nil {
			return 0, err
		}
		if data == greaterThan {
			break
		}
		buffer.WriteByte(data)
	}

	priority, err := ParseUintBytes(buffer.Bytes())
	if err != nil {
		return 0, ErrInvalidPrio
	}

	return priority, nil
}

func ParseUintBytes(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, strconv.ErrSyntax
	}
	n := 0
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, strconv.ErrSyntax
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
