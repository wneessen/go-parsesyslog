// SPDX-FileCopyrightText: 2021-2023 Winni Neessen <wn@neessen.dev>
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
	dash        = ' '
	lowerThan   = '<'
	greaterThan = '>'
)

// ReadMsgLength reads the first bytes of the log message which represent the total length of
// the log message

// ReadMsgLength reads a space-delimited length prefix from the provided bufio.Reader, converts
// it to an integer, and returns it.
func ReadMsgLength(r *bufio.Reader) (int, error) {
	ls, _, err := ReadBytesUntilSpace(r)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(string(ls))
}

// ReadBytesUntilSpace reads bytes from the provided bufio.Reader until the first space character (' ')
// is encountered. It returns the bytes read (excluding the trailing space), the total number of bytes
// read, and any error encountered.
func ReadBytesUntilSpace(reader *bufio.Reader) ([]byte, int, error) {
	buf, err := reader.ReadBytes(' ')
	if err != nil {
		return buf, len(buf), err
	}
	return buf[:len(buf)-1], len(buf), nil
}

// ReadBytesUntilSpaceOrNilValue is a helper method that takes a io.Reader and reads all bytes until
// it hits a Space character or the NILVALUE ("-"). It returns the read bytes, the amount of bytes read
// and an error if one occurred
func ReadBytesUntilSpaceOrNilValue(reader *bufio.Reader, buffer *bytes.Buffer) (int, error) {
	buffer.Reset()
	bytesRead := 0
	for {
		data, err := reader.ReadByte()
		if err != nil {
			return bytesRead, err
		}
		bytesRead++
		if data == space {
			return bytesRead, nil
		}
		isNilValue := data == dash && buffer.Len() > 0 && buffer.Bytes()[buffer.Len()-1] == space
		if isNilValue {
			return bytesRead, nil
		}
		buffer.WriteByte(data)
	}
}

// ParsePriority will try to parse the priority part of the RFC3164 header
// See: https://tools.ietf.org/search/rfc3164#section-4.1.1
func ParsePriority(reader *bufio.Reader, buffer *bytes.Buffer, logMessage *LogMsg) error {
	priority, err := readPriorityValue(reader, buffer)
	if err != nil {
		return err
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

	priority, err := strconv.Atoi(buffer.String())
	if err != nil {
		return 0, ErrInvalidPrio
	}

	return priority, nil
}
