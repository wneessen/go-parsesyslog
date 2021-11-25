package syslog

import (
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
		return l, err
	}
	lr := io.LimitReader(r, int64(ml))
	if err := m.parseHeader(lr, &l); err != nil {
		return l, err
	}

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
	//fmt.Printf("%+v\n", lm)

	return nil
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
