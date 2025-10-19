// SPDX-FileCopyrightText: 2021-2023 Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package parsesyslog

import (
	"bufio"
	"bytes"
	"strconv"
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

// ReadBytesUntilSpace is a helper method that takes a io.Reader and reads all bytes until it hits
// a Space character. It returns the read bytes, the amount of bytes read and an error if one
// occurred
func ReadBytesUntilSpace(r *bufio.Reader) ([]byte, int, error) {
	buf, err := r.ReadSlice(' ')
	if err != nil {
		return buf, len(buf), err
	}
	if len(buf) > 0 {
		return buf[:len(buf)-1], len(buf), nil
	}
	return buf, len(buf), nil
}

// ReadBytesUntilSpaceOrNilValue is a helper method that takes a io.Reader and reads all bytes until
// it hits a Space character or the NILVALUE ("-"). It returns the read bytes, the amount of bytes read
// and an error if one occurred
func ReadBytesUntilSpaceOrNilValue(r *bufio.Reader, buf *bytes.Buffer) (int, error) {
	buf.Reset()
	tb := 0
	for {
		b, err := r.ReadByte()
		if err != nil {
			return tb, err
		}
		tb++
		if b == ' ' {
			return tb, nil
		}
		if b == '-' && (buf.Len() > 0 && buf.Bytes()[tb-2] == ' ') {
			return tb, nil
		}
		buf.WriteByte(b)
	}
}

// ParsePriority will try to parse the priority part of the RFC3164 header
// See: https://tools.ietf.org/search/rfc3164#section-4.1.1
func ParsePriority(r *bufio.Reader, buf *bytes.Buffer, lm *LogMsg) error {
	buf.Reset()
	b, err := r.ReadByte()
	if err != nil {
		return err
	}
	if b != '<' {
		return ErrWrongFormat
	}
	for {
		b, err = r.ReadByte()
		if err != nil {
			return err
		}
		if b == '>' {
			break
		}
		buf.WriteByte(b)
	}
	p, err := strconv.Atoi(buf.String())
	if err != nil {
		return ErrInvalidPrio
	}
	lm.Priority = Priority(p)
	lm.Facility = FacilityFromPrio(lm.Priority)
	lm.Severity = SeverityFromPrio(lm.Priority)
	return nil
}
