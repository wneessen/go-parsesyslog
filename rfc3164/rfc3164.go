// SPDX-FileCopyrightText: 2021-2023 Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

// Package rfc3164 implements a go-parsesyslog parser for the syslog format
// as described in RFC3164
package rfc3164

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"

	"github.com/wneessen/go-parsesyslog"
)

// msg represents a log message in that matches RFC3164
type msg struct {
	buf       bytes.Buffer
	appBuffer *bytes.Buffer
	pidBuffer *bytes.Buffer
	reol      bool
}

const (
	// Type represents the ParserType for this Parser
	Type parsesyslog.ParserType = "rfc3164"
)

const (
	// maxTagLength defines the maximum length for a tag in an RFC3164 syslog message.
	maxTagLength = 32
	// colonSeparator represents the colon character ':' used as a delimiter in RFC3164 syslog message parsing.
	colonSeparator = 58
	// spaceChar represents the space character used as a delimiter in parsing RFC3164 syslog messages.
	spaceChar = 32
	// newlineChar defines the newline character used to detect the end of a line in RFC3164 syslog message parsing.
	newlineChar = 10
	// leftBracket represents the opening square bracket character used in parsing or formatting operations.
	leftBracket = 91
	// rightBracket represents the closing square bracket character used in parsing or formatting operations.
	rightBracket = 93
)

// init registers the Parser
func init() {
	fn := func() (parsesyslog.Parser, error) {
		return &msg{
			appBuffer: bytes.NewBuffer(nil),
			pidBuffer: bytes.NewBuffer(nil),
		}, nil
	}
	parsesyslog.Register(Type, fn)
}

// ParseString returns the parsed log message read from a string (as buffered i/o)
func (m *msg) ParseString(message string) (parsesyslog.LogMsg, error) {
	stringReader := strings.NewReader(message)
	bufferedReader := bufio.NewReader(stringReader)
	return m.ParseReader(bufferedReader)
}

// ParseReader is the parser function that is able to interpret RFC3164 and
// satisfies the Parser interface
func (m *msg) ParseReader(r io.Reader) (parsesyslog.LogMsg, error) {
	logMessage := parsesyslog.LogMsg{
		Type: parsesyslog.RFC3164,
	}
	m.reol = false

	bufferedString := bufio.NewReaderSize(r, 1024)
	if err := m.parseHeader(bufferedString, &logMessage); err != nil {
		switch {
		case errors.Is(err, io.EOF):
			return logMessage, parsesyslog.ErrPrematureEOF
		default:
			return logMessage, err
		}
	}

	if !m.reol {
		rd, err := bufferedString.ReadSlice('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return logMessage, err
		}

		_, err = logMessage.Message.Write(rd)
		if err != nil {
			return logMessage, err
		}
	}
	logMessage.MsgLength = logMessage.Message.Len()

	return logMessage, nil
}

// parseHeader will try to parse the header of a RFC3164 syslog message and store
// it in the provided LogMsg pointer
// See: https://tools.ietf.org/search/rfc3164#section-4.1.2
func (m *msg) parseHeader(reader *bufio.Reader, logMessage *parsesyslog.LogMsg) error {
	if err := parsesyslog.ParsePriority(reader, &m.buf, logMessage); err != nil {
		return err
	}
	if err := m.parseTimestamp(reader, logMessage); err != nil {
		return err
	}
	if err := m.parseHostname(reader, logMessage); err != nil {
		return err
	}

	/*
		_, _, _ = parsesyslog.ReadBytesUntilSpace(reader)
		_, _, _ = parsesyslog.ReadBytesUntilSpace(reader)
		_, _, _ = parsesyslog.ReadBytesUntilSpace(reader)
		_, _, _ = parsesyslog.ReadBytesUntilSpace(reader)

	*/
	if err := m.parseTag(reader, logMessage); err != nil {
		return err
	}

	return nil
}

// parseTimestamp will try to parse the timestamp part of the RFC3164 header
// See: https://tools.ietf.org/search/rfc3164#section-4.1.2
func (m *msg) parseTimestamp(reader *bufio.Reader, logMessage *parsesyslog.LogMsg) error {
	m.buf.Reset()
	var err error
	var b byte

	for m.buf.Len() < timestampLength {
		b, err = reader.ReadByte()
		if err != nil {
			return err
		}
		m.buf.WriteByte(b)
	}
	if discard, err := reader.Discard(1); err != nil || discard != 1 {
		return errors.New("failed to discard space")
	}

	logMessage.Timestamp, err = ParseTimestamp(m.buf.Bytes())
	return err
}

// parseHostname will try to parse the hostname part of the RFC3164 header
// See: https://tools.ietf.org/search/rfc3164#section-4.1.2
func (m *msg) parseHostname(reader *bufio.Reader, logMessage *parsesyslog.LogMsg) error {
	m.buf.Reset()
	hostname, _, err := parsesyslog.ReadBytesUntilSpace(reader)
	if err != nil {
		return err
	}
	logMessage.Host = hostname

	return nil
}

// parseTag will try to parse the tag part of the RFC3164 header
// See: https://tools.ietf.org/search/rfc3164#section-4.1.2
func (m *msg) parseTag(reader *bufio.Reader, logMessage *parsesyslog.LogMsg) error {
	m.buf.Reset()
	m.appBuffer.Reset()
	m.pidBuffer.Reset()

	hasColon, inPid := false, false
	bytesRead := 0

	// Read up to maxTagLength bytes to parse the tag
	for c := 0; c < maxTagLength; c++ {
		b, err := reader.ReadByte()
		if err != nil {
			return err
		}
		m.buf.WriteByte(b)
		bytesRead++

		if b == newlineChar {
			m.reol = true
			break
		}
		if b == spaceChar {
			break
		}
		if b == colonSeparator {
			hasColon = true
			continue
		}
		if b == leftBracket && !inPid {
			inPid = true
			continue
		}
		if b == rightBracket && inPid {
			inPid = false
			continue
		}

		if !inPid {
			m.appBuffer.WriteByte(b)
			continue
		}
		m.pidBuffer.WriteByte(b)
	}

	// We have a valid tag (colon present and app name exists)
	if hasColon && m.appBuffer.Len() > 0 {
		logMessage.App = m.appBuffer.Bytes()
		if m.pidBuffer.Len() > 0 {
			logMessage.PID = m.pidBuffer.Bytes()
		}
		return m.readMessageContent(reader, logMessage, bytesRead)
	}

	// No valid tag found, treat buffer content as message
	if m.buf.Len() > 0 {
		if _, err := logMessage.Message.Write(m.buf.Bytes()); err != nil {
			return err
		}
	}

	return m.readMessageContent(reader, logMessage, m.buf.Len())
}

// readMessageContent reads the remaining message content up to maxTagLength or newline
func (m *msg) readMessageContent(reader *bufio.Reader, logMessage *parsesyslog.LogMsg, startPosition int) error {
	for x := startPosition; x < maxTagLength; x++ {
		b, err := reader.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		logMessage.Message.WriteByte(b)
		if b == newlineChar {
			m.reol = true
			break
		}
	}
	return nil
}
