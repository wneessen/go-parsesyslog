// SPDX-FileCopyrightText: 2021-2023 Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

// Package rfc5424 implements a go-parsesyslog parser for the syslog format
// as described in RFC5424
package rfc5424

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/wneessen/go-parsesyslog"
)

// msg represents a log message in that matches RFC5424
type msg struct {
	buf bytes.Buffer
}

// Type represents the ParserType for this Parser
const Type parsesyslog.ParserType = "rfc5424"

// init registers the Parser
func init() {
	fn := func() (parsesyslog.Parser, error) {
		return &msg{}, nil
	}
	parsesyslog.Register(Type, fn)
}

// ParseString returns the parsed log message read from a string (as buffered i/o)
func (m *msg) ParseString(s string) (parsesyslog.LogMsg, error) {
	sr := strings.NewReader(s)
	br := bufio.NewReader(sr)
	return m.ParseReader(br)
}

// ParseReader is the parser function that is able to interpret RFC5424 and
// satisfies the Parser interface
func (m *msg) ParseReader(r io.Reader) (parsesyslog.LogMsg, error) {
	l := parsesyslog.LogMsg{
		Type: parsesyslog.RFC5424,
	}

	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
	}
	ml, err := parsesyslog.ReadMsgLength(br)
	if err != nil {
		return l, err
	}

	lr := io.LimitReader(br, int64(ml))
	br = bufio.NewReaderSize(lr, ml)
	if err := m.parseHeader(br, &l); err != nil {
		switch {
		case errors.Is(err, io.EOF):
			return l, parsesyslog.ErrPrematureEOF
		default:
			return l, err
		}
	}
	if err := m.parseStructuredData(br, &l); err != nil {
		switch {
		case errors.Is(err, io.EOF):
			return l, parsesyslog.ErrPrematureEOF
		default:
			return l, err
		}
	}

	if err := m.parseBOM(br, &l); err != nil {
		return l, nil
	}

	// rb := make([]byte, ml - l.Message.Len())
	md, err := io.ReadAll(br)
	if err != nil {
		return l, err
	}
	l.Message.Write(md)
	l.MsgLength = l.Message.Len()

	return l, nil
}

// parseHeader will try to parse the header of a RFC5424 syslog message and store
// it in the provided LogMsg pointer
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.2
func (m *msg) parseHeader(r *bufio.Reader, lm *parsesyslog.LogMsg) error {
	if err := parsesyslog.ParsePriority(r, &m.buf, lm); err != nil {
		return err
	}
	if err := m.parseProtoVersion(r, lm); err != nil {
		return err
	}
	if err := m.parseTimestamp(r, lm); err != nil {
		return err
	}
	if err := m.parseHostname(r, lm); err != nil {
		return err
	}
	if err := m.parseAppName(r, lm); err != nil {
		return err
	}
	if err := m.parseProcID(r, lm); err != nil {
		return err
	}
	if err := m.parseMsgID(r, lm); err != nil {
		return err
	}

	return nil
}

// parseStructuredData will try to parse the SD of a RFC5424 syslog message and
// store it in the provided LogMsg pointer
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.2
// We are using a simple finite state machine here to parse through the different
// states of the parameters and elements
func (m *msg) parseStructuredData(r *bufio.Reader, lm *parsesyslog.LogMsg) error {
	m.buf.Reset()

	nb, err := r.ReadByte()
	if err != nil {
		return err
	}
	if nb == '-' {
		_, err = r.ReadByte()
		if err != nil {
			return err
		}
		return nil
	}
	if nb != '[' {
		return parsesyslog.ErrWrongSDFormat
	}

	var sds []parsesyslog.StructuredDataElement
	var sd parsesyslog.StructuredDataElement
	var sdp parsesyslog.StructuredDataParam
	insideelem := true
	insideparam := false
	readname := false
	for {
		b, err := r.ReadByte()
		if err != nil {
			return err
		}
		if b == ']' {
			insideelem = false
			sds = append(sds, sd)
			sd = parsesyslog.StructuredDataElement{}
			m.buf.Reset()
			continue
		}
		if b == '[' {
			insideelem = true
			readname = false
			continue
		}
		if b == ' ' && !readname {
			readname = true
			sd.ID = m.buf.String()
			m.buf.Reset()
		}
		if b == '=' && !insideparam {
			sdp.Name = m.buf.String()
			m.buf.Reset()
			continue
		}
		if b == '"' && !insideparam {
			insideparam = true
			continue
		}
		if b == '"' && insideparam {
			insideparam = false
			sdp.Value = m.buf.String()
			m.buf.Reset()
			sd.Param = append(sd.Param, sdp)
			sdp = parsesyslog.StructuredDataParam{}
			continue
		}
		if b == ' ' && !insideelem {
			break
		}
		if b == ' ' && !insideparam {
			continue
		}
		m.buf.WriteByte(b)
	}
	lm.StructuredData = sds

	return nil
}

// parseBOM will try to parse the BOM (if any) of the RFC54524 header
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.4
func (m *msg) parseBOM(r *bufio.Reader, lm *parsesyslog.LogMsg) error {
	bom, err := r.Peek(3)
	if err != nil {
		return err
	}
	if bytes.Equal(bom, []byte{0xEF, 0xBB, 0xBF}) {
		lm.HasBOM = true
	}
	return nil
}

// parseProtoVersion will try to parse the proto version part of the RFC54524 header
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.2
func (m *msg) parseProtoVersion(r *bufio.Reader, lm *parsesyslog.LogMsg) error {
	b, _, err := parsesyslog.ReadBytesUntilSpace(r)
	if err != nil {
		return err
	}
	pv, err := parsesyslog.Atoi(b)
	if err != nil {
		return parsesyslog.ErrInvalidProtoVersion
	}
	lm.ProtoVersion = parsesyslog.ProtoVersion(pv)
	return nil
}

// parseTimestamp will try to parse the timestamp (or NILVALUE) part of the
// RFC54524 header
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.3
func (m *msg) parseTimestamp(r *bufio.Reader, lm *parsesyslog.LogMsg) error {
	_, err := parsesyslog.ReadBytesUntilSpaceOrNilValue(r, &m.buf)
	if err != nil {
		return err
	}
	if m.buf.Len() == 0 {
		return nil
	}
	if m.buf.Bytes()[0] == '-' {
		return nil
	}
	ts, err := time.Parse(time.RFC3339, m.buf.String())
	if err != nil {
		return parsesyslog.ErrInvalidTimestamp
	}
	lm.Timestamp = ts
	return nil
}

// parseHostname will try to read the hostname part of the RFC54524 header
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.4
func (m *msg) parseHostname(r *bufio.Reader, lm *parsesyslog.LogMsg) error {
	_, err := parsesyslog.ReadBytesUntilSpaceOrNilValue(r, &m.buf)
	if err != nil {
		return err
	}
	if m.buf.Len() == 0 {
		return nil
	}
	if m.buf.Bytes()[0] == '-' {
		return nil
	}
	lm.Hostname = m.buf.String()
	return nil
}

// parseAppName will try to read the app name part of the RFC54524 header
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.5
func (m *msg) parseAppName(r *bufio.Reader, lm *parsesyslog.LogMsg) error {
	_, err := parsesyslog.ReadBytesUntilSpaceOrNilValue(r, &m.buf)
	if err != nil {
		return err
	}
	if m.buf.Len() == 0 {
		return nil
	}
	if m.buf.Bytes()[0] == '-' {
		return nil
	}
	lm.AppName = m.buf.String()
	return nil
}

// parseProcID will try to read the process ID part of the RFC54524 header
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.6
func (m *msg) parseProcID(r *bufio.Reader, lm *parsesyslog.LogMsg) error {
	_, err := parsesyslog.ReadBytesUntilSpaceOrNilValue(r, &m.buf)
	if err != nil {
		return err
	}
	if m.buf.Len() == 0 {
		return nil
	}
	if m.buf.Bytes()[0] == '-' {
		return nil
	}
	lm.ProcID = m.buf.String()
	return nil
}

// parseMsgID will try to read the message ID part of the RFC54524 header
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.7
func (m *msg) parseMsgID(r *bufio.Reader, lm *parsesyslog.LogMsg) error {
	_, err := parsesyslog.ReadBytesUntilSpaceOrNilValue(r, &m.buf)
	if err != nil {
		return err
	}
	if m.buf.Len() == 0 {
		return nil
	}
	if m.buf.Bytes()[0] == '-' {
		return nil
	}
	lm.MsgID = m.buf.String()
	return nil
}
