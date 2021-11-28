package parsesyslog

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"time"
)

// RFC3164Msg represents a log message in that matches RFC3164
type RFC3164Msg struct {
	buf  bytes.Buffer
	app  bytes.Buffer
	pid  bytes.Buffer
	reol bool
}

// parseReader is the parser function that is able to interpret RFC3164 and
// satisfies the Parser interface
func (m *RFC3164Msg) parseReader(r io.Reader) (LogMsg, error) {
	l := LogMsg{
		Type: RFC3164,
	}
	m.reol = false

	bufr := bufio.NewReaderSize(r, 1024)
	if err := m.parseHeader(bufr, &l); err != nil {
		switch {
		case errors.Is(err, io.EOF):
			return l, ErrPrematureEOF
		default:
			return l, err
		}
	}

	if !m.reol {
		rd, err := bufr.ReadSlice('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return l, err
		}
		_, err = l.Message.Write(rd)
		if err != nil {
			return l, err
		}
	}
	l.MsgLength = l.Message.Len()

	return l, nil
}

// parseHeader will try to parse the header of a RFC3164 syslog message and store
// it in the provided LogMsg pointer
// See: https://tools.ietf.org/search/rfc3164#section-4.1.2
func (m *RFC3164Msg) parseHeader(r *bufio.Reader, lm *LogMsg) error {
	if err := parsePriority(r, &m.buf, lm); err != nil {
		return err
	}
	if err := m.parseTimestamp(r, lm); err != nil {
		return err
	}
	if err := m.parseHostname(r, lm); err != nil {
		return err
	}
	if err := m.parseTag(r, lm); err != nil {
		return err
	}

	return nil
}

// parseTimestamp will try to parse the timestamp part of the RFC3164 header
// See: https://tools.ietf.org/search/rfc3164#section-4.1.2
func (m *RFC3164Msg) parseTimestamp(r *bufio.Reader, lm *LogMsg) error {
	m.buf.Reset()
	for m.buf.Len() < 16 {
		b, err := r.ReadByte()
		if err != nil {
			return err
		}
		m.buf.WriteByte(b)
	}
	ts, err := time.Parse(`Jan _2 15:04:05 `, m.buf.String())
	if err != nil {
		return ErrInvalidTimestamp
	}

	if ts.Year() == 0 {
		ts = time.Date(time.Now().Year(), ts.Month(), ts.Day(), ts.Hour(), ts.Minute(),
			ts.Second(), ts.Nanosecond(), ts.Location())
		lm.Timestamp = ts
		return nil
	}

	lm.Timestamp = ts
	return nil
}

// parseHostname will try to parse the hostname part of the RFC3164 header
// See: https://tools.ietf.org/search/rfc3164#section-4.1.2
func (m *RFC3164Msg) parseHostname(r *bufio.Reader, lm *LogMsg) error {
	m.buf.Reset()
	h, _, err := readBytesUntilSpace(r)
	if err != nil {
		return err
	}
	lm.Hostname = string(h)
	return nil
}

// parseTag will try to parse the tag part of the RFC3164 header
// See: https://tools.ietf.org/search/rfc3164#section-4.1.2
func (m *RFC3164Msg) parseTag(r *bufio.Reader, lm *LogMsg) error {
	m.buf.Reset()
	m.app.Reset()
	m.pid.Reset()

	hascolon, inpid := false, false
	sb := 0
	for c := 0; c < 32; c++ {
		b, err := r.ReadByte()
		if err != nil {
			return err
		}
		m.buf.WriteByte(b)
		if b == '\n' {
			sb++
			m.reol = true
			break
		}
		if b == ' ' {
			sb++
			break
		}
		if b == ':' {
			hascolon = true
			sb++
			continue
		}
		if b == '[' && !inpid {
			inpid = true
			sb++
			continue
		}
		if b == ']' && inpid {
			inpid = false
			sb++
			continue
		}
		if !inpid {
			m.app.WriteByte(b)
		}
		if inpid {
			m.pid.WriteByte(b)
		}
	}
	if hascolon && m.app.Len() > 0 {
		if m.app.Len() > 0 {
			lm.AppName = m.app.String()
			sb += m.app.Len()
		}
		if m.pid.Len() > 0 {
			lm.ProcID = m.pid.String()
			sb += m.pid.Len()
		}
		for x := sb; x < 32; x++ {
			b, err := r.ReadByte()
			if err != nil {
				switch {
				case errors.Is(err, io.EOF):
					return nil
				default:
					return err
				}
			}
			lm.Message.WriteByte(b)
			if b == '\n' {
				m.reol = true
				break
			}
		}

		return nil
	}

	if m.buf.Len() > 0 {
		_, err := lm.Message.Write(m.buf.Bytes())
		if err != nil {
			return err
		}
	}
	for c := m.buf.Len(); c < 32; c++ {
		b, err := r.ReadByte()
		if err != nil {
			switch {
			case errors.Is(err, io.EOF):
				return nil
			default:
				return err
			}
		}
		lm.Message.WriteByte(b)
		if b == '\n' {
			m.reol = true
			break
		}
	}
	return nil
}
