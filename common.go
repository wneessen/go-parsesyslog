// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package parsesyslog

// ParseUintBytes parses a byte slice containing only numeric characters into an integer, returning
// an error for invalid input.
func ParseUintBytes(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, ErrInvalidNumber
	}
	n := 0
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, ErrInvalidNumber
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
