// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package rfc3164

import (
	"errors"
	"testing"
)

func TestParseTimestamp(t *testing.T) {
	t.Run("parsing valid timestamp succeeds", func(t *testing.T) {
		val, err := ParseTimestamp([]byte(testTimestamp))
		if err != nil {
			t.Errorf("failed to parse timestamp: %s", err)
		}
		if !val.Equal(now) {
			t.Errorf("expected timestamp to be: %s, got: %s", now, val)
		}
	})
	t.Run("parsing valid timestamp with year inferance succeeds", func(t *testing.T) {
		future := now.AddDate(0, 2, 0)
		expect := now.AddDate(-1, 2, 0)
		testTimestamp = future.Format("Jan") + " " + future.Format("_2") + " " +
			future.Format("15") + ":" + future.Format("04") + ":" + future.Format("05")
		val, err := ParseTimestamp([]byte(testTimestamp))
		if err != nil {
			t.Errorf("failed to parse timestamp: %s", err)
		}
		if !val.Equal(expect) {
			t.Errorf("expected timestamp to be: %s, got: %s", expect, val)
		}
	})
	t.Run("parsing too short timestamp fails", func(t *testing.T) {
		_, err := ParseTimestamp([]byte(testTimestamp[:len(testTimestamp)-1]))
		if err == nil {
			t.Errorf("parsing too short timestamp should have failed, but it didn't")
		}
		if !errors.Is(err, ErrBadLength) {
			t.Errorf("expected error to be: %s, got: %s", ErrBadLength, err)
		}
	})
	t.Run("parsing invalid format timestamp fails", func(t *testing.T) {
		_, err := ParseTimestamp([]byte("Jan 00 03.04:05"))
		if err == nil {
			t.Errorf("parsing invalid format timestamp should have failed, but it didn't")
		}
		if !errors.Is(err, ErrBadFormat) {
			t.Errorf("expected error to be: %s, got: %s", ErrBadFormat, err)
		}
	})
	t.Run("parsing invalid month timestamp fails", func(t *testing.T) {
		_, err := ParseTimestamp([]byte("Bad 20 03:04:05"))
		if err == nil {
			t.Errorf("parsing invalid month timestamp should have failed, but it didn't")
		}
		if !errors.Is(err, ErrBadMonth) {
			t.Errorf("expected error to be: %s, got: %s", ErrBadMonth, err)
		}
	})
	t.Run("parsing invalid day of month timestamp fails", func(t *testing.T) {
		_, err := ParseTimestamp([]byte("Jan 99 03:04:05"))
		if err == nil {
			t.Errorf("parsing invalid day of month timestamp should have failed, but it didn't")
		}
		if !errors.Is(err, ErrBadNumber) {
			t.Errorf("expected error to be: %s, got: %s", ErrBadNumber, err)
		}
	})
	t.Run("parsing invalid hour in timestamp fails", func(t *testing.T) {
		_, err := ParseTimestamp([]byte("Jan 13 25:04:05"))
		if err == nil {
			t.Errorf("parsing invalid hour in timestamp should have failed, but it didn't")
		}
		if !errors.Is(err, ErrOutOfRange) {
			t.Errorf("expected error to be: %s, got: %s", ErrOutOfRange, err)
		}
	})
	t.Run("parsing invalid minute in timestamp fails", func(t *testing.T) {
		_, err := ParseTimestamp([]byte("Jan 13 18:61:05"))
		if err == nil {
			t.Errorf("parsing invalid minute in timestamp should have failed, but it didn't")
		}
		if !errors.Is(err, ErrOutOfRange) {
			t.Errorf("expected error to be: %s, got: %s", ErrOutOfRange, err)
		}
	})
	t.Run("parsing invalid second in timestamp fails", func(t *testing.T) {
		_, err := ParseTimestamp([]byte("Jan 13 18:00:99"))
		if err == nil {
			t.Errorf("parsing invalid second in timestamp should have failed, but it didn't")
		}
		if !errors.Is(err, ErrOutOfRange) {
			t.Errorf("expected error to be: %s, got: %s", ErrOutOfRange, err)
		}
	})
}

func TestParseTimestamp_parseMonth(t *testing.T) {
	t.Run("parsing valid month succeeds", func(t *testing.T) {
		month := []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
		for _, m := range month {
			val := parseMonth(m[0], m[1], m[2])
			if val == -1 {
				t.Errorf("failed to parse month: %s, got: -1", m)
			}
		}
	})
	t.Run("parsing invalid month fails", func(t *testing.T) {
		if val := parseMonth('B', 'a', 'd'); val != -1 {
			t.Errorf("expected parseMonth to return -1 for invalid month, got: %d", val)
		}
	})
}

func TestParseTimestamp_parseDay(t *testing.T) {
	t.Run("parsing space-padded day succeeds", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			val := parseDay(' ', byte(i+48))
			if val != i {
				t.Errorf("expected parseDay to return %d for padded day, got: %d", i, val)
			}
		}
	})
	t.Run("parsing zero-padded day succeeds", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			val := parseDay('0', byte(i+48))
			if val != i {
				t.Errorf("expected parseDay to return %d for padded day, got: %d", i, val)
			}
		}
	})
	t.Run("invalid space-padded day fails", func(t *testing.T) {
		if val := parseDay(' ', 58); val != -1 {
			t.Errorf("expected parseDay to return -1 for invalid day, got: %d", val)
		}
	})
}
