// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

// Package rfc5424 implements a go-parsesyslog parser for the syslog format
// as described in RFC5424
package rfc5424

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/wneessen/go-parsesyslog"
)

const (
	space       = ' '
	dash        = '-'
	lowerThan   = '<'
	greaterThan = '>'
)

// rfc5424 represents a log message in that matches RFC5424
type rfc5424 struct {
	buf    *bytes.Buffer
	arena  []byte
	offset int
	len    int
	sds    []parsesyslog.StructuredDataElement
}

// Type represents the ParserType for this Parser
const Type parsesyslog.ParserType = "rfc5424"

// init registers the Parser
func init() {
	fn := func() (parsesyslog.Parser, error) {
		return &rfc5424{
			buf:   bytes.NewBuffer(nil),
			arena: make([]byte, 0, 2048),
			sds:   make([]parsesyslog.StructuredDataElement, 0),
		}, nil
	}
	parsesyslog.Register(Type, fn)
}

// ParseString returns the parsed log message read from a string (as buffered i/o)
func (r *rfc5424) ParseString(s string) (parsesyslog.LogMsg, error) {
	sr := strings.NewReader(s)
	br := bufio.NewReader(sr)
	return r.ParseReader(br)
}

// ParseReader is the parser function that is able to interpret RFC5424 and
// satisfies the Parser interface
func (r *rfc5424) ParseReader(reader io.Reader) (parsesyslog.LogMsg, error) {
	r.offset, r.len = 0, 0
	logMessage := parsesyslog.LogMsg{
		Type: parsesyslog.RFC5424,
	}

	msgReader, ok := reader.(*bufio.Reader)
	if !ok {
		msgReader = bufio.NewReader(reader)
	}

	// Consume the length information of the log message
	wantLength, err := r.parseMessageLength(msgReader)
	if err != nil {
		return logMessage, err
	}

	// Parse the log header and structured data
	if err = r.parseHeader(msgReader, &logMessage); err != nil {
		return logMessage, r.handleParseError(err)
	}
	if err = r.parseStructuredData(msgReader, &logMessage); err != nil {
		return logMessage, r.handleParseError(err)
	}
	if err = r.parseBOM(msgReader, &logMessage); err != nil {
		return logMessage, nil
	}

	// Consume the rest of the message
	md := make([]byte, wantLength-r.len)
	if _, err = io.ReadFull(msgReader, md); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return logMessage, parsesyslog.ErrPrematureEOF
		}
		return logMessage, fmt.Errorf("failed to read log message content: %w", err)
	}
	logMessage.Message.Write(md)
	logMessage.MsgLength = logMessage.Message.Len()

	if msgReader.Buffered() != 0 {
		return logMessage, parsesyslog.ErrInvalidLength
	}

	return logMessage, nil
}

// handleParseError converts io.EOF errors to ErrPrematureEOF and returns other errors as-is
func (r *rfc5424) handleParseError(err error) error {
	if errors.Is(err, io.EOF) {
		return parsesyslog.ErrPrematureEOF
	}
	return err
}

// parseHeader will try to parse the header of a RFC5424 syslog message and store
// it in the provided LogMsg pointer
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.2
func (r *rfc5424) parseHeader(reader *bufio.Reader, logMessage *parsesyslog.LogMsg) error {
	if err := r.parsePriority(reader, logMessage); err != nil {
		return err
	}
	if err := r.parseProtoVersion(reader, logMessage); err != nil {
		return err
	}
	if err := r.parseTimestamp(reader, logMessage); err != nil {
		return err
	}
	if err := r.parseHostname(reader, logMessage); err != nil {
		return err
	}
	if err := r.parseAppName(reader, logMessage); err != nil {
		return err
	}
	if err := r.parseProcID(reader, logMessage); err != nil {
		return err
	}
	if err := r.parseMsgID(reader, logMessage); err != nil {
		return err
	}

	return nil
}

// parseStructuredData will try to parse the SD of a RFC5424 syslog message and
// store it in the provided LogMsg pointer
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.2
// We are using a simple finite state machine here to parse through the different
// states of the parameters and elements
func (r *rfc5424) parseStructuredData(reader *bufio.Reader, logMessage *parsesyslog.LogMsg) error {
	r.sds = r.sds[:0]
	r.buf.Reset()

	nextByte, err := reader.ReadByte()
	if err != nil {
		return err
	}

	// Handle NILVALUE: "-"
	if nextByte == '-' {
		// Check if the NILVALUE is correctly followed by a space or EOF
		b, err := reader.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				logMessage.StructuredData = nil
				return nil
			}
			return err
		}

		// Invalid NILVALUE: Must be followed by space. Unread both and return error.
		if b != ' ' {
			_ = reader.UnreadByte()
			_ = reader.UnreadByte()
			return parsesyslog.ErrWrongSDFormat
		}

		// Found valid NILVALUE: "- ". We consumed the space, which is correct because
		// the stream is now positioned at the start of the MSG body.
		logMessage.StructuredData = nil
		r.len = r.len + 2

		return nil
	}

	// Structured data must start with '['
	if nextByte != '[' {
		return parsesyslog.ErrWrongSDFormat
	}
	r.buf.WriteByte(nextByte)

	var sdContent []byte
	var inQuotes bool
	depth := 1

	for {
		data, err := reader.ReadByte()
		if err != nil {
			// If EOF is hit, the structured data block was the last thing. Process the buffer contents.
			if errors.Is(err, io.EOF) {
				sdContent = r.buf.Bytes()
				break
			}
			return err
		}
		r.buf.WriteByte(data)

		// Toggle quoted state
		if data == '"' {
			inQuotes = !inQuotes
		}

		if !inQuotes {
			if data == ' ' && depth == 0 {
				// Found the space that terminates the SD section.
				// We have read one byte too far (' '). Unread it.
				if err = reader.UnreadByte(); err != nil {
					return fmt.Errorf("failed to unread byte: %w", err)
				}

				// Trim the space from the buffer content as well.
				sdContent = r.buf.Bytes()[:r.buf.Len()-1]
				break
			}
			if data == '[' {
				depth++
				continue
			}
			if data == ']' {
				depth--
				continue
			}
		}

		// Closing bracket without an opening one would be a malformed structured data block.
		if depth < 0 {
			return parsesyslog.ErrWrongSDFormat
		}
	}

	// message now holds the contiguous slice of SD bytes read from the stream.
	message := sdContent
	r.len = r.len + len(message)

	if len(message) < 2 || message[0] != '[' || message[len(message)-1] != ']' {
		// We have a malformed SD block.
		if len(message) != 0 {
			return parsesyslog.ErrWrongSDFormat
		}
		// We no structued data block at all.
		return nil
	}

	var sd parsesyslog.StructuredDataElement
	var sdp parsesyslog.StructuredDataParam
	start := 1
	insideValue := false

	for i := 1; i < len(message); i++ {
		b := message[i]

		// If we are inside a value a right bracket must be escaped.
		if b == ']' && insideValue {
			if len(message) >= i-2 {
				if message[i-1] != '\\' && message[i-2] != '\\' {
					return parsesyslog.ErrWrongSDFormat
				}
			}
		}

		if b == '"' {
			switch insideValue {
			case true:
				// Escaped quotes are allowed inside values.
				if len(message) >= i-1 && message[i-1] == '\\' {
					continue
				}

				// Parameters need a name and a value.
				if len(sdp.Name) == 0 {
					return parsesyslog.ErrWrongSDFormat
				}

				sdp.Value = message[start:i]
				sd.Param = append(sd.Param, sdp)
				sdp = parsesyslog.StructuredDataParam{}
				insideValue = false
				start = i + 1
			default:
				insideValue = true
				start = i + 1
			}
			continue
		}

		if !insideValue {
			if b == '=' {
				sdp.Name = message[start:i]
				start = i + 1
				continue
			}

			if b == ' ' || b == ']' {
				if b == ']' {
					if sd.ID == nil {
						sd.ID = message[start:i]
					}

					r.sds = append(r.sds, sd)
					sd = parsesyslog.StructuredDataElement{}
					start = i + 1

					// If content remains, it must be the start of a new element.
					if start < len(message) && message[start] == '[' {
						start++
						continue
					}
					break
				}

				if sd.ID != nil && len(sd.Param) == 0 {
					return parsesyslog.ErrWrongSDFormat
				}
				if sd.ID == nil {
					sd.ID = message[start:i]
					start = i + 1
					continue
				}
				start = i + 1
				continue
			}
		}
	}

	logMessage.StructuredData = r.sds
	_, err = reader.ReadByte()
	r.len++
	return err
}

// parseBOM will try to parse the BOM (if any) of the RFC54524 header
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.4
func (r *rfc5424) parseBOM(reader *bufio.Reader, lm *parsesyslog.LogMsg) error {
	bom, err := reader.Peek(3)
	if err != nil {
		return err
	}
	if bytes.Equal(bom, []byte{0xEF, 0xBB, 0xBF}) {
		lm.HasBOM = true
	}
	return nil
}

// parseMessageLength will try to parse the message length prefix of the log message
func (r *rfc5424) parseMessageLength(reader *bufio.Reader) (int, error) {
	start := r.offset
	if err := r.readUntil(reader, space, false); err != nil {
		return 0, fmt.Errorf("failed to read hostname: %w", err)
	}
	val := r.sliceFrom(start)
	r.len = r.len - len(val) - 1
	return parsesyslog.ParseUintBytes(val)
}

// parsePriority will try to parse the proto version part of the RFC54524 header
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.2
func (r *rfc5424) parsePriority(reader *bufio.Reader, lm *parsesyslog.LogMsg) error {
	start := r.offset
	if err := r.readUntil(reader, greaterThan, true); err != nil {
		return fmt.Errorf("failed to read hostname: %w", err)
	}
	val := r.sliceFrom(start)

	// We need to make sure the priority is valid.
	if val[0] != lowerThan || val[len(val)-1] != greaterThan {
		return parsesyslog.ErrInvalidPrio
	}

	prio, err := parsesyslog.ParseUintBytes(val[1 : len(val)-1])
	if err != nil {
		return fmt.Errorf("failed to parse priority: %w", err)
	}
	if prio < 0 || prio > 191 {
		return parsesyslog.ErrInvalidPrio
	}

	lm.Priority = parsesyslog.Priority(prio)
	lm.Facility = parsesyslog.FacilityFromPrio(lm.Priority)
	lm.Severity = parsesyslog.SeverityFromPrio(lm.Priority)
	return nil
}

// parseProtoVersion will try to parse the proto version part of the RFC54524 header
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.2
func (r *rfc5424) parseProtoVersion(reader *bufio.Reader, lm *parsesyslog.LogMsg) error {
	start := r.offset
	if err := r.readUntil(reader, space, false); err != nil {
		return fmt.Errorf("failed to read hostname: %w", err)
	}
	version := r.sliceFrom(start)
	pv, err := parsesyslog.ParseUintBytes(version)
	if err != nil || pv != 1 {
		return parsesyslog.ErrInvalidProtoVersion
	}
	lm.ProtoVersion = parsesyslog.ProtoVersion(pv)
	return nil
}

// parseTimestamp will try to parse the timestamp (or NILVALUE) part of the
// RFC54524 header
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.3
func (r *rfc5424) parseTimestamp(reader *bufio.Reader, lm *parsesyslog.LogMsg) error {
	start := r.offset
	if err := r.readUntil(reader, space, false); err != nil {
		return fmt.Errorf("failed to read hostname: %w", err)
	}
	tsBytes := r.sliceFrom(start)
	if len(tsBytes) == 0 || (len(tsBytes) == 1 && tsBytes[0] == dash) {
		r.offset = start
		return nil
	}
	ts, err := time.Parse(time.RFC3339, string(tsBytes))
	if err != nil {
		return parsesyslog.ErrInvalidTimestamp
	}
	lm.Timestamp = ts
	return nil
}

// parseHostname will try to read the hostname part of the RFC54524 header
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.4
func (r *rfc5424) parseHostname(reader *bufio.Reader, lm *parsesyslog.LogMsg) error {
	start := r.offset
	if err := r.readUntil(reader, space, false); err != nil {
		return fmt.Errorf("failed to read hostname: %w", err)
	}
	host := r.sliceFrom(start)
	if len(host) == 0 || (len(host) == 1 && host[0] == dash) {
		r.offset = start
		return nil
	}
	lm.Host = host
	return nil
}

// parseAppName will try to read the app name part of the RFC54524 header
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.5
func (r *rfc5424) parseAppName(reader *bufio.Reader, lm *parsesyslog.LogMsg) error {
	start := r.offset
	if err := r.readUntil(reader, space, false); err != nil {
		return fmt.Errorf("failed to read hostname: %w", err)
	}
	app := r.sliceFrom(start)
	if len(app) == 0 || (len(app) == 1 && app[0] == dash) {
		r.offset = start
		return nil
	}
	lm.App = app
	return nil
}

// parseProcID will try to read the process ID part of the RFC54524 header
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.6
func (r *rfc5424) parseProcID(reader *bufio.Reader, lm *parsesyslog.LogMsg) error {
	start := r.offset
	if err := r.readUntil(reader, space, false); err != nil {
		return fmt.Errorf("failed to read hostname: %w", err)
	}
	pid := r.sliceFrom(start)
	if len(pid) == 0 || (len(pid) == 1 && pid[0] == dash) {
		r.offset = start
		return nil
	}
	lm.PID = pid
	return nil
}

// parseMsgID will try to read the message ID part of the RFC54524 header
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.7
func (r *rfc5424) parseMsgID(reader *bufio.Reader, lm *parsesyslog.LogMsg) error {
	start := r.offset
	if err := r.readUntil(reader, space, false); err != nil {
		return fmt.Errorf("failed to read hostname: %w", err)
	}
	msgid := r.sliceFrom(start)
	if len(msgid) == 0 || (len(msgid) == 1 && msgid[0] == dash) {
		r.offset = start
		return nil
	}
	lm.MsgID = msgid
	return nil
}

func (r *rfc5424) sliceFrom(start int) []byte {
	return r.arena[start:r.offset]
}

func (r *rfc5424) readUntil(reader *bufio.Reader, until byte, include bool) error {
	for {
		p, err := reader.Peek(1)
		if err != nil {
			return err
		}
		c := p[0]

		if c == until {
			if !include {
				_, err = reader.ReadByte()
				if err != nil {
					return err
				}
				r.len++
				break
			}

			if err = r.readByte(reader); err != nil {
				return err
			}
			break
		}

		if err = r.readByte(reader); err != nil {
			return err
		}
	}
	return nil
}

func (r *rfc5424) readByte(reader *bufio.Reader) error {
	c, err := reader.ReadByte()
	if err != nil {
		return err
	}

	if r.offset >= cap(r.arena) {
		return parsesyslog.ErrWrongFormat
	}

	r.arena = r.arena[:r.offset+1]
	r.arena[r.offset] = c
	r.offset++
	r.len++
	return nil
}
