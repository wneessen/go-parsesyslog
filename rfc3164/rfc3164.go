// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

// Package rfc3164 implements a go-parsesyslog parser for the syslog format
// as described in RFC3164
package rfc3164

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/wneessen/go-parsesyslog"
)

// rfc3164 defines a struct for parsing syslog messages compliant with the RFC3164 protocol format.
type rfc3164 struct {
	buf       *bytes.Buffer
	appBuffer *bytes.Buffer
	pidBuffer *bytes.Buffer
	reol      bool
}

const (
	// Type represents the ParserType for this Parser
	Type parsesyslog.ParserType = "rfc3164"
	// MsgType represents the log message type of this package
	MsgType parsesyslog.LogMsgType = "RFC3164"
)

const (
	// maxTagLength defines the maximum length for a tag in an RFC3164 syslog message.
	maxTagLength = 32
	// colonSeparator represents the colon character ':' used as a delimiter in RFC3164 syslog message parsing.
	colon = 58
	// spaceChar represents the space character used as a delimiter in parsing RFC3164 syslog messages.
	space = 32
	// newlineChar defines the newline character used to detect the end of a line in RFC3164 syslog message parsing.
	newline = 10
	// leftBracket represents the opening square bracket character used in parsing or formatting operations.
	leftBracket = 91
	// rightBracket represents the closing square bracket character used in parsing or formatting operations.
	rightBracket = 93
	lowerThan    = '<'
	greaterThan  = '>'
)

// init registers the Parser with go-parsesyslog
func init() {
	fn := func() (parsesyslog.Parser, error) {
		return &rfc3164{
			buf:       bytes.NewBuffer(nil),
			appBuffer: bytes.NewBuffer(nil),
			pidBuffer: bytes.NewBuffer(nil),
		}, nil
	}
	parsesyslog.Register(Type, fn)
}

// ParseString parses a syslog message from a string based on RFC3164 and returns a parsed LogMsg or an error.
func (r *rfc3164) ParseString(message string) (parsesyslog.LogMsg, error) {
	stringReader := strings.NewReader(message)
	return r.ParseReader(stringReader)
}

// ParseReader parses syslog messages from an io.Reader according to RFC3164 and returns a LogMsg or an error.
func (r *rfc3164) ParseReader(reader io.Reader) (parsesyslog.LogMsg, error) {
	logMessage := parsesyslog.LogMsg{
		Type: MsgType,
	}
	r.reol = false

	bufreader, ok := reader.(*bufio.Reader)
	if !ok {
		bufreader = bufio.NewReaderSize(reader, 1024)
	}
	if err := r.parseHeader(bufreader, &logMessage); err != nil {
		switch {
		case errors.Is(err, io.EOF):
			return logMessage, parsesyslog.ErrPrematureEOF
		default:
			return logMessage, err
		}
	}

	if !r.reol {
		data, err := bufreader.ReadSlice('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return logMessage, fmt.Errorf("failed to read bytes: %w", err)
		}

		_, err = logMessage.Message.Write(data)
		if err != nil {
			return logMessage, fmt.Errorf("failed to write bytes: %w", err)
		}
	}
	logMessage.MsgLength = int32(logMessage.Message.Len())

	return logMessage, nil
}

// parseHeader will try to parse the header of a RFC3164 syslog message and store
// it in the provided LogMsg pointer
// See: https://tools.ietf.org/search/rfc3164#section-4.1.2
func (r *rfc3164) parseHeader(reader *bufio.Reader, logMessage *parsesyslog.LogMsg) error {
	if err := r.parsePriority(reader, r.buf, logMessage); err != nil {
		return err
	}
	if err := r.parseTimestamp(reader, logMessage); err != nil {
		return err
	}
	if err := r.parseHostname(reader, logMessage); err != nil {
		return err
	}
	if err := r.parseTag(reader, logMessage); err != nil {
		return err
	}

	return nil
}

// parsePriority will try to parse the priority part of the RFC3164 header
// See: https://tools.ietf.org/search/rfc3164#section-4.1.1
func (r *rfc3164) parsePriority(reader *bufio.Reader, buffer *bytes.Buffer, logMessage *parsesyslog.LogMsg) error {
	priority, err := readPriorityValue(reader, buffer)
	if err != nil {
		return err
	}
	if priority < 0 || priority > 191 {
		return parsesyslog.ErrInvalidPrio
	}

	logMessage.Priority = parsesyslog.Priority(priority)
	logMessage.Facility = parsesyslog.FacilityFromPrio(logMessage.Priority)
	logMessage.Severity = parsesyslog.SeverityFromPrio(logMessage.Priority)
	return nil
}

// parseTimestamp will try to parse the timestamp part of the RFC3164 header
// See: https://tools.ietf.org/search/rfc3164#section-4.1.2
func (r *rfc3164) parseTimestamp(reader *bufio.Reader, logMessage *parsesyslog.LogMsg) error {
	r.buf.Reset()
	var err error
	var b byte

	for r.buf.Len() < timestampLength {
		b, err = reader.ReadByte()
		if err != nil {
			return err
		}
		r.buf.WriteByte(b)
	}
	if discard, err := reader.Discard(1); err != nil || discard != 1 {
		return errors.New("failed to discard space")
	}

	logMessage.Timestamp, err = ParseTimestamp(r.buf.Bytes())
	return err
}

// parseHostname will try to parse the hostname part of the RFC3164 header
// See: https://tools.ietf.org/search/rfc3164#section-4.1.2
func (r *rfc3164) parseHostname(reader *bufio.Reader, logMessage *parsesyslog.LogMsg) error {
	r.buf.Reset()

	buf, err := reader.ReadSlice(' ')
	if err != nil {
		return err
	}
	logMessage.Host = buf[:len(buf)-1]

	return nil
}

// parseTag will try to parse the tag part of the RFC3164 header
// See: https://tools.ietf.org/search/rfc3164#section-4.1.2
func (r *rfc3164) parseTag(reader *bufio.Reader, logMessage *parsesyslog.LogMsg) error {
	r.buf.Reset()
	r.appBuffer.Reset()
	r.pidBuffer.Reset()

	hasColon, inPid := false, false
	bytesRead := 0

	// Read up to maxTagLength bytes to parse the tag
	for c := 0; c < maxTagLength; c++ {
		b, err := reader.ReadByte()
		if err != nil {
			return err
		}
		if b == newline {
			r.reol = true
			break
		}
		r.buf.WriteByte(b)
		bytesRead++

		if b == space {
			break
		}
		if b == colon {
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
			r.appBuffer.WriteByte(b)
			continue
		}
		r.pidBuffer.WriteByte(b)
	}

	// We have a valid tag (colon present and app name exists)
	if hasColon && r.appBuffer.Len() > 0 {
		logMessage.App = r.appBuffer.Bytes()
		if r.pidBuffer.Len() > 0 {
			logMessage.PID = r.pidBuffer.Bytes()
		}
		return r.readMessageContent(reader, logMessage, bytesRead)
	}

	// No valid tag found, treat buffer content as message
	if r.buf.Len() > 0 {
		if _, err := logMessage.Message.Write(r.buf.Bytes()); err != nil {
			return err
		}
	}

	return r.readMessageContent(reader, logMessage, r.buf.Len())
}

// readMessageContent reads the remaining message content up to maxTagLength or newline
func (r *rfc3164) readMessageContent(reader *bufio.Reader, logMessage *parsesyslog.LogMsg, startPosition int) error {
	for x := startPosition; x < maxTagLength; x++ {
		b, err := reader.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		logMessage.Message.WriteByte(b)
		if b == newline {
			r.reol = true
			break
		}
	}
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
		return 0, parsesyslog.ErrWrongFormat
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

	priority, err := parsesyslog.ParseUintBytes(buffer.Bytes())
	if err != nil {
		return 0, parsesyslog.ErrInvalidPrio
	}

	return priority, nil
}
