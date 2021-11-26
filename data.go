package parsesyslog

import (
	"io"
	"strconv"
)

// readMsgLength reads the first bytes of the log message which represent the total length of
// the log message
func readMsgLength(r io.Reader) (int, error) {
	ls, _, err := readBytesUntilSpace(r)
	if err != nil {
		return 0, err
	}
	ml, err := strconv.Atoi(string(ls))
	return ml, err
}

// readBytesUntilSpace is a helper method that takes a io.Reader and reads all bytes until it hits
// a Space character. It returns the read bytes, the amount of bytes read and an error if one
// occured
func readBytesUntilSpace(r io.Reader) ([]byte, int, error) {
	var buf []byte
	var b [1]byte
	tb := 0
	for {
		n, err := r.Read(b[:])
		if err != nil {
			return buf, tb, err
		}
		tb += n
		if b[0] == ' ' {
			return buf, tb, nil
		}
		buf = append(buf, b[0])
	}
}

// readBytesUntilSpaceOrNilValue is a helper method that takes a io.Reader and reads all bytes until
// it hits a Space character or the NILVALUE ("-"). It returns the read bytes, the amount of bytes read
// and an error if one occured
func readBytesUntilSpaceOrNilValue(r io.Reader) ([]byte, int, error) {
	var buf []byte
	var b [1]byte
	tb := 0
	for {
		n, err := r.Read(b[:])
		if err != nil {
			return buf, tb, err
		}
		tb += n
		if b[0] == ' ' {
			return buf, tb, nil
		}
		if b[0] == '-' && (len(buf) > 0 && buf[tb-2] == ' ') {
			return buf, tb, nil
		}
		buf = append(buf, b[0])
	}
}
