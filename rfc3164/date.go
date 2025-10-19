package rfc3164

import (
	"errors"
	"time"
)

// timestampLength defines the fixed length of the timestamp in the RFC 3164 syslog message format.
const timestampLength = 15

var (
	// ErrBadLength indicates the timestamp does not match the expected length.
	ErrBadLength = errors.New("timestamp does not match expected length")
	// ErrBadFormat indicates the timestamp does not match the expected format: Mmm dd HH:MM:SS.
	ErrBadFormat = errors.New("timestamp does not match expected format: Mmm dd HH:MM:SS")
	// ErrBadMonth indicates the timestamp does not match the expected month format.
	ErrBadMonth = errors.New("timestamp does not match expected month format")
	// ErrBadNumber indicates an invalid number in the timestamp, such as day or numeric values out of range.
	ErrBadNumber = errors.New("invalid number in timestamp: must be 1..31 or 1..9")
	// ErrOutOfRange indicates the minutes in the timestamp are out of range (must be 0 to 59).
	ErrOutOfRange = errors.New("timestamp minutes out of range: must be 0..59")
)

// ParseTimestamp parses an RFC3164 timestamp of the form "Mmm dd HH:MM:SS".
// Example: "Oct 19 14:32:01"
// - b must be at least 15 bytes and match the exact layout.
// - now is used to infer the year (RFC3164 omits the year).
// - loc is the time zone to use (often time.Local).
// On the hot success path, this function performs zero allocations.
// See: https://tools.ietf.org/search/rfc3164#section-4.1.2
func ParseTimestamp(b []byte) (time.Time, error) {
	// Expected fixed layout: "Mmm dd HH:MM:SS" -> len 15
	// 012345678901234
	// Mmm d d HH:MM:SS  (day may be space-padded)
	if len(b) != timestampLength {
		return time.Time{}, ErrBadLength
	}
	// Structural checks
	if b[3] != ' ' || b[6] != ' ' || b[9] != ':' || b[12] != ':' {
		return time.Time{}, ErrBadFormat
	}

	// Month (b[0:3])
	mon, ok := parseMonth(b[0], b[1], b[2])
	if !ok {
		return time.Time{}, ErrBadMonth
	}

	// Day (b[4:6]) where b[4] may be ' ' for 1..9
	day, ok := parseDay(b[4], b[5])
	if !ok {
		return time.Time{}, ErrBadNumber
	}
	if day < 1 || day > 31 {
		return time.Time{}, ErrOutOfRange
	}

	// Hour, Min, Sec (must be digits)
	hh, ok := parse2(b[7], b[8])
	if !ok || hh > 23 {
		return time.Time{}, ErrOutOfRange
	}
	mm, ok := parse2(b[10], b[11])
	if !ok || mm > 59 {
		return time.Time{}, ErrOutOfRange
	}
	ss, ok := parse2(b[13], b[14])
	if !ok || ss > 60 { // allow leap second 60
		return time.Time{}, ErrOutOfRange
	}

	// Infer year from 'now' (common syslog heuristic):
	// start with current year in loc; if parsed time is more than ~31 days in the future,
	// assume it was from the previous year (handles Jan logs for Dec events).
	now := time.Now()
	loc := time.Local
	year := now.In(loc).Year()
	t := time.Date(year, time.Month(mon), day, hh, mm, ss, 0, loc)

	// If this appears unreasonably in the future relative to 'now', roll back a year.
	const futureSkew = 31 * 24 * time.Hour
	if t.After(now.Add(futureSkew)) {
		t = time.Date(year-1, time.Month(mon), day, hh, mm, ss, 0, loc)
	}

	return t, nil
}

func parseMonth(a, b, c byte) (int, bool) {
	// Compare ASCII directly; avoids any allocation or strings.
	switch a {
	case 'J':
		if b == 'a' && c == 'n' { // Jan
			return 1, true
		}
		if b == 'u' && c == 'n' { // Jun
			return 6, true
		}
		if b == 'u' && c == 'l' { // Jul
			return 7, true
		}
	case 'F':
		if b == 'e' && c == 'b' { // Feb
			return 2, true
		}
	case 'M':
		if b == 'a' && c == 'r' { // Mar
			return 3, true
		}
		if b == 'a' && c == 'y' { // May
			return 5, true
		}
	case 'A':
		if b == 'p' && c == 'r' { // Apr
			return 4, true
		}
		if b == 'u' && c == 'g' { // Aug
			return 8, true
		}
	case 'S':
		if b == 'e' && c == 'p' { // Sep
			return 9, true
		}
	case 'O':
		if b == 'c' && c == 't' { // Oct
			return 10, true
		}
	case 'N':
		if b == 'o' && c == 'v' { // Nov
			return 11, true
		}
	case 'D':
		if b == 'e' && c == 'c' { // Dec
			return 12, true
		}
	}
	return 0, false
}

func parse2(a, b byte) (int, bool) {
	if a < '0' || a > '9' || b < '0' || b > '9' {
		return 0, false
	}
	return int(a-'0')*10 + int(b-'0'), true
}

func parseDay(a, b byte) (int, bool) {
	// day is space-padded for 1..9: " 1".." 9" or "10".."31"
	if a == ' ' {
		if b < '0' || b > '9' {
			return 0, false
		}
		return int(b - '0'), true
	}
	// both digits
	return parse2(a, b)
}
