// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

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
	ErrBadNumber = errors.New("invalid number in timestamp")
	// ErrOutOfRange indicates that a timestamp value exceeds acceptable bounds, such as day, hour, minute,
	// or second limits.
	ErrOutOfRange = errors.New("timestamp value out of range")
)

// ParseTimestamp parses a timestamp in the fixed RFC3164 format and returns a time.Time instance and error
// if applicable.
//
// The input must strictly match the expected format and length (15 bytes), or it returns ErrBadLength or
// ErrBadFormat. It validates components like month, day, hour, minute, and second, returning specific errors for
// format or range issues. The year is inferred based on the current time to handle logs near the beginning of
// a new year.
func ParseTimestamp(b []byte) (time.Time, error) {
	if len(b) != timestampLength {
		return time.Time{}, ErrBadLength
	}
	if b[3] != ' ' || b[6] != ' ' || b[9] != ':' || b[12] != ':' {
		return time.Time{}, ErrBadFormat
	}

	// Parse the month (b[0:2])
	mon := parseMonth(b[0], b[1], b[2])
	if mon == -1 {
		return time.Time{}, ErrBadMonth
	}

	// Day (b[4:6]) where b[4] may be ' ' for 1..9
	day := parseDay(b[4], b[5])
	if day == -1 {
		return time.Time{}, ErrBadNumber
	}
	if day < 1 || day > 31 {
		return time.Time{}, ErrOutOfRange
	}

	// Hour, Min, Sec (must be digits)
	hh := parseDoubleDigit(b[7], b[8])
	if hh <= -1 || hh > 23 {
		return time.Time{}, ErrOutOfRange
	}
	mm := parseDoubleDigit(b[10], b[11])
	if mm <= -1 || mm > 59 {
		return time.Time{}, ErrOutOfRange
	}
	ss := parseDoubleDigit(b[13], b[14])
	if ss <= -1 || ss > 60 { // Allow leap seconds
		return time.Time{}, ErrOutOfRange
	}

	// Infer year from current local time (common syslog heuristic):
	// if parsed time is more than ~31 days in the future, assume it was from the previous year (handles Jan
	// logs for Dec events).
	now := time.Now().Local()
	year := now.Year()
	t := time.Date(year, time.Month(mon), day, hh, mm, ss, 0, time.Local)

	// If this appears unreasonably in the future relative to 'testNow', roll back a year.
	const futureSkew = 31 * 24 * time.Hour
	if t.After(now.Add(futureSkew)) {
		t = time.Date(year-1, time.Month(mon), day, hh, mm, ss, 0, time.Local)
	}

	return t, nil
}

// parseMonth parses three byte inputs representing the abbreviated month name and returns the numeric month (1-12).
// Returns -1 if the input does not match any valid month abbreviation.
func parseMonth(a, b, c byte) int {
	switch a {
	case 'J':
		if b == 'a' && c == 'n' { // Jan
			return 1
		}
		if b == 'u' && c == 'n' { // Jun
			return 6
		}
		if b == 'u' && c == 'l' { // Jul
			return 7
		}
	case 'F':
		if b == 'e' && c == 'b' { // Feb
			return 2
		}
	case 'M':
		if b == 'a' && c == 'r' { // Mar
			return 3
		}
		if b == 'a' && c == 'y' { // May
			return 5
		}
	case 'A':
		if b == 'p' && c == 'r' { // Apr
			return 4
		}
		if b == 'u' && c == 'g' { // Aug
			return 8
		}
	case 'S':
		if b == 'e' && c == 'p' { // Sep
			return 9
		}
	case 'O':
		if b == 'c' && c == 't' { // Oct
			return 10
		}
	case 'N':
		if b == 'o' && c == 'v' { // Nov
			return 11
		}
	case 'D':
		if b == 'e' && c == 'c' { // Dec
			return 12
		}
	}
	return -1
}

// parseDay parses two byte inputs representing a day (space-padded for 1-9 or both digits for 10-31).
// Returns -1 if the inputs are invalid.
func parseDay(a, b byte) int {
	// day is space-padded for 1..9: " 1".." 9" or "10".."31"
	if a == ' ' {
		if b < '0' || b > '9' {
			return -1
		}
		return int(b - '0')
	}

	// both digits
	return parseDoubleDigit(a, b)
}

// parseDoubleDigit parses two byte inputs representing a two-digit number (00-69). Returns -1 for invalid inputs.
func parseDoubleDigit(a, b byte) int {
	if a < '0' || a > '6' || b < '0' || b > '9' {
		return -1
	}
	return int(a-'0')*10 + int(b-'0')
}
