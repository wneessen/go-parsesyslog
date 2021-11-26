package parsesyslog

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"time"
)

var (
	ErrWrongFormat         = errors.New("log message does not conform the RFC5424 logging format")
	ErrInvalidPrio         = errors.New("PRI header not a valid priority string")
	ErrInvalidProtoVersion = errors.New("protocol version string invalid")
	ErrInvalidTimestamp    = errors.New("timestamp does not conform the RFC5424 logging format")
	ErrWrongSDFormat       = errors.New("structured data does not conform the RFC5424 format")
	ErrInvalidLength       = errors.New("provided length does not conform the RFC5424 format")
	ErrPrematureEOF        = errors.New("log message is shorter than the provided length")
)

// RFC5424Msg represents a log message in that matches RFC5424
type RFC5424Msg struct{}

// ParseReader is the parser function that is able to interpret RFC5424 and
// satisfies the Parser interface
func (m *RFC5424Msg) ParseReader(r io.Reader) (LogMsg, error) {
	l := LogMsg{
		Type: RFC5424,
	}
	ml, err := readMsgLength(r)
	if err != nil {
		return l, ErrInvalidLength
	}
	lr := io.LimitReader(r, int64(ml))
	if err := m.parseHeader(lr, &l); err != nil {
		switch {
		case errors.Is(err, io.EOF):
			return l, ErrPrematureEOF
		default:
			return l, err
		}
	}
	if err := m.parseStructuredData(lr, &l); err != nil {
		switch {
		case errors.Is(err, io.EOF):
			return l, ErrPrematureEOF
		default:
			return l, err
		}
	}
	bb, bbc, err := m.parseBOM(lr, &l)
	if err != nil {
		return l, err
	}
	l.Message = append(l.Message, bb...)

	md, err := io.ReadAll(r)
	if err != nil {
		switch {
		case errors.Is(err, io.EOF):
			return l, ErrPrematureEOF
		default:
			return l, err
		}
	}
	l.Message = append(l.Message, md...)
	l.MsgLength = len(md) + bbc

	return l, nil
}

// parseHeader will try to parse the header of a RFC5424 syslog message and store
// it in the provided LogMsg pointer
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.2
func (m *RFC5424Msg) parseHeader(r io.Reader, lm *LogMsg) error {
	if err := m.parsePriority(r, lm); err != nil {
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
func (m *RFC5424Msg) parseStructuredData(r io.Reader, lm *LogMsg) error {
	var b [1]byte
	var rd []byte
	var sds []StructuredDataElement
	var sd StructuredDataElement
	var sdp StructuredDataParam

	_, err := r.Read(b[:])
	if err != nil {
		return err
	}
	if b[0] == '-' {
		_, err = r.Read(b[:])
		if err != nil {
			return err
		}
		return nil
	}
	if b[0] != '[' {
		return ErrWrongSDFormat
	}
	insideelem := true
	insideparam := false
	readname := false
	for {
		_, err := r.Read(b[:])
		if err != nil {
			return err
		}
		if b[0] == ']' {
			insideelem = false
			sds = append(sds, sd)
			sd = StructuredDataElement{}
			rd = []byte{}
			continue
		}
		if b[0] == '[' {
			insideelem = true
			readname = false
			continue
		}
		if b[0] == ' ' && !readname {
			readname = true
			sd.ID = string(rd)
			rd = []byte{}
		}
		if b[0] == '=' && !insideparam {
			sdp.Name = string(rd)
			rd = []byte{}
			continue
		}
		if b[0] == '"' && !insideparam {
			insideparam = true
			continue
		}
		if b[0] == '"' && insideparam {
			insideparam = false
			sdp.Value = string(rd)
			rd = []byte{}
			sd.Param = append(sd.Param, sdp)
			sdp = StructuredDataParam{}
			continue
		}
		if b[0] == ' ' && !insideelem {
			break
		}
		if b[0] == ' ' && !insideparam {
			continue
		}
		rd = append(rd, b[0])
	}
	lm.StructuredData = sds

	return nil
}

// parseBOM will try to parse the BOM (if any) of the RFC54524 header
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.4
func (m *RFC5424Msg) parseBOM(r io.Reader, lm *LogMsg) ([]byte, int, error) {
	var b [3]byte
	n, err := r.Read(b[:])
	if err != nil {
		return b[:], 0, err
	}
	if bytes.Equal(b[:], []byte{0xEF, 0xBB, 0xBF}) {
		lm.HasBOM = true
		return b[:], 3, nil
	}
	return b[:], n, nil
}

// parsePriority will try to parse the priority part of the RFC54524 header
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.1
func (m *RFC5424Msg) parsePriority(r io.Reader, lm *LogMsg) error {
	var b [1]byte
	var ps []byte
	_, err := r.Read(b[:])
	if err != nil {
		return err
	}
	if b[0] != '<' {
		return ErrWrongFormat
	}
	for {
		_, err := r.Read(b[:])
		if err != nil {
			return err
		}
		if b[0] == '>' {
			break
		}
		ps = append(ps, b[0])
	}
	p, err := strconv.Atoi(string(ps))
	if err != nil {
		return ErrInvalidPrio
	}
	lm.Priority = Priority(p)
	lm.Facility = FacilityFromPrio(lm.Priority)
	lm.Severity = SeverityFromPrio(lm.Priority)
	return nil
}

// parseProtoVersion will try to parse the protocol version part of the RFC54524
// header
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.2
func (m *RFC5424Msg) parseProtoVersion(r io.Reader, lm *LogMsg) error {
	b, _, err := readBytesUntilSpace(r)
	if err != nil {
		return err
	}
	pv, err := strconv.Atoi(string(b))
	if err != nil {
		return ErrInvalidProtoVersion
	}
	lm.ProtoVersion = ProtoVersion(pv)
	return nil
}

// parseTimestamp will try to parse the timestamp (or NILVALUE) part of the
// RFC54524 header
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.3
func (m *RFC5424Msg) parseTimestamp(r io.Reader, lm *LogMsg) error {
	b, _, err := readBytesUntilSpaceOrNilValue(r)
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return nil
	}
	if b[0] == '-' {
		return nil
	}
	ts, err := time.Parse(time.RFC3339, string(b))
	if err != nil {
		return ErrInvalidTimestamp
	}
	lm.Timestamp = ts
	return nil
}

// parseHostname will try to read the hostname part of the RFC54524 header
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.4
func (m *RFC5424Msg) parseHostname(r io.Reader, lm *LogMsg) error {
	b, _, err := readBytesUntilSpaceOrNilValue(r)
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return nil
	}
	if b[0] == '-' {
		return nil
	}
	lm.Hostname = string(b)
	return nil
}

// parseAppName will try to read the app name part of the RFC54524 header
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.5
func (m *RFC5424Msg) parseAppName(r io.Reader, lm *LogMsg) error {
	b, _, err := readBytesUntilSpaceOrNilValue(r)
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return nil
	}
	if b[0] == '-' {
		return nil
	}
	lm.AppName = string(b)
	return nil
}

// parseProcID will try to read the process ID part of the RFC54524 header
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.6
func (m *RFC5424Msg) parseProcID(r io.Reader, lm *LogMsg) error {
	b, _, err := readBytesUntilSpaceOrNilValue(r)
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return nil
	}
	if b[0] == '-' {
		return nil
	}
	lm.ProcID = string(b)
	return nil
}

// parseMsgID will try to read the message ID part of the RFC54524 header
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.7
func (m *RFC5424Msg) parseMsgID(r io.Reader, lm *LogMsg) error {
	b, _, err := readBytesUntilSpaceOrNilValue(r)
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return nil
	}
	if b[0] == '-' {
		return nil
	}
	lm.MsgID = string(b)
	return nil
}
