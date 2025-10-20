// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package rfc3164

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/wneessen/go-parsesyslog"
)

var (
	tests = []struct {
		Name  string
		Line  string
		Valid bool
	}{
		{"basic_tag_pid", "<34>Oct 20 12:34:56 myhost app[123]: hello world", true},
		{"single_digit_day_space_padded", "<13>Jan  2 03:04:05 host tag: message", true},
		{"double_digit_day", "<13>Jan 12 03:04:05 host tag: message", true},
		{"ipv4_hostname", "<13>Mar 15 11:22:33 192.0.2.1 app: payload", true},
		{"ipv6_hostname", "<13>Apr 01 00:00:00 2001:db8::1 app: boot", true},
		{"tag_without_pid", "<11>May 31 23:59:59 gw tag: done", true},
		{"unicode_in_msg", "<14>Jun 07 07:08:09 srv app: wärme ✓", true},
		{"maxish_tag_length_32", "<14>Jul 10 10:10:10 host AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA: x", true},
		{"pri_with_leading_zero", "<013>Aug 09 09:09:09 host app: ok", true},
		{"missing_pri_closer", "<13Sep 09 09:09:09 host app: nope", false},
		{"non_numeric_pri", "<ab>Sep 09 09:09:09 host app: nope", false},
		{"pri_out_of_range_192", "<192>Sep 09 09:09:09 host app: nope", false},
		{"invalid_month_token", "<13>Foo 12 03:04:05 host app: nope", false},
		{"day_zero", "<13>Jan 00 03:04:05 host app: nope", false},
		{"hour_24", "<13>Jan 12 24:00:00 host app: nope", false},
		{"missing_hostname", "<13>Jan 12 03:04:05 app: nope", false},
		{"no_space_after_colon", "<13>Jan 12 03:04:05 host app:message", false},
	}

	testNow = time.Now()
	now     = time.Date(testNow.Year(), testNow.Month(), testNow.Day(), testNow.Hour(), testNow.Minute(),
		testNow.Second(), 0, time.Local)
	testMessage = `<165>` + testNow.Format("Jan") + " " + testNow.Format("_2") + " " +
		testNow.Format("15") + ":" + testNow.Format("04") + ":" + testNow.Format("05") + " " +
		`mymachine myproc[10]: %% It's time to make the do-nuts.  %%  Ingredients: Mix=OK, Jelly=OK # Devices: ` +
		`Mixer=OK, Jelly_Injector=OK, Frier=OK # Transport: Conveyer1=OK, Conveyer2=OK # %%` + "\n"
)

func TestRfc3164_ParseReader(t *testing.T) {
	parser, initErr := parsesyslog.New(Type)
	if initErr != nil {
		t.Fatalf("failed to create new RFC3164 parser: %s", initErr)
	}
	t.Run("parse different valid and invalid log messages", func(t *testing.T) {
		for _, tc := range tests {
			stringReader := strings.NewReader(tc.Line)
			bufReader := bufio.NewReader(stringReader)
			t.Run(tc.Name, func(t *testing.T) {
				_, err := parser.ParseReader(bufReader)
				if err != nil && tc.Valid {
					t.Errorf("failed to parse message: %s", err)
				}
				if err == nil && !tc.Valid {
					t.Errorf("log message should have caused an error, but it didn't")
				}
			})
		}
	})
	t.Run("parsing short log message should fail", func(t *testing.T) {
		stringReader := strings.NewReader("<13>Jan 12 03:04:05 ")
		bufReader := bufio.NewReader(stringReader)
		_, err := parser.ParseReader(bufReader)
		if err == nil {
			t.Errorf("log message should have caused an error, but it didn't")
		}
		if !errors.Is(err, parsesyslog.ErrPrematureEOF) {
			t.Errorf("expected error to be: %s, got: %s", parsesyslog.ErrPrematureEOF, err)
		}
	})
	t.Run("parsing empty message should fail", func(t *testing.T) {
		stringReader := strings.NewReader("")
		bufReader := bufio.NewReader(stringReader)
		_, err := parser.ParseReader(bufReader)
		if err == nil {
			t.Errorf("log message should have caused an error, but it didn't")
		}
		if !errors.Is(err, parsesyslog.ErrPrematureEOF) {
			t.Errorf("expected error to be: %s, got: %s", parsesyslog.ErrPrematureEOF, err)
		}
	})
	t.Run("parsing message with incomplete timestamp should fail", func(t *testing.T) {
		stringReader := strings.NewReader("<13>Jan 12 03:04")
		bufReader := bufio.NewReader(stringReader)
		_, err := parser.ParseReader(bufReader)
		if err == nil {
			t.Errorf("log message should have caused an error, but it didn't")
		}
		if !errors.Is(err, parsesyslog.ErrPrematureEOF) {
			t.Errorf("expected error to be: %s, got: %s", parsesyslog.ErrPrematureEOF, err)
		}
	})
	t.Run("parsing message with no trailing space after timestamp should fail", func(t *testing.T) {
		stringReader := strings.NewReader("<13>Jan 12 03:04:59")
		bufReader := bufio.NewReader(stringReader)
		_, err := parser.ParseReader(bufReader)
		if err == nil {
			t.Errorf("log message should have caused an error, but it didn't")
		}
		if !strings.EqualFold(err.Error(), "failed to discard space") {
			t.Errorf("expected error to be: %s, got: %s", "failed to discard space", err)
		}
	})
	t.Run("parsing message with newline in tag should interpret it as message", func(t *testing.T) {
		stringReader := strings.NewReader("<13>Jan 12 03:04:59 mymachine mypro\n")
		bufReader := bufio.NewReader(stringReader)
		logMessage, err := parser.ParseReader(bufReader)
		if err != nil {
			t.Errorf("failed to parse message: %s", err)
		}
		expect := "mypro"
		if !strings.EqualFold(logMessage.Message.String(), expect) {
			t.Errorf("expected message to be: %q, got: %q", expect, logMessage.Message.String())
		}
	})
	t.Run("parsing message fails with non io.EOF error", func(t *testing.T) {
		stringReader := newMockReader(testMessage)
		bufReader := bufio.NewReader(stringReader)
		_, err := parser.ParseReader(bufReader)
		if err == nil {
			t.Errorf("log message should have caused an error, but it didn't")
		}
		if !errors.Is(err, ErrFinished) {
			t.Errorf("expected error to be: %s, got: %s", ErrFinished, err)
		}
	})
	t.Run("parsing tag fails with non io.EOF error", func(t *testing.T) {
		stringReader := newMockReader("<13>Jan 12 03:04:59 mymachine mypro foo")
		bufReader := bufio.NewReader(stringReader)
		_, err := parser.ParseReader(bufReader)
		if err == nil {
			t.Errorf("log message should have caused an error, but it didn't")
		}
		if !errors.Is(err, ErrFinished) {
			t.Errorf("expected error to be: %s, got: %s", ErrFinished, err)
		}
	})
	t.Run("parsing valid message should provide the correct values", func(t *testing.T) {
		stringReader := strings.NewReader(testMessage)
		bufReader := bufio.NewReader(stringReader)
		logMessage, err := parser.ParseReader(bufReader)
		if err != nil {
			t.Fatalf("failed to parse message: %s", err)
		}

		if !strings.EqualFold(logMessage.Message.String(), testMessage[43:]) {
			t.Errorf("expected message to be: %s, got: %s", testMessage[43:], logMessage.Message.String())
		}
		if logMessage.Facility != 20 {
			t.Errorf("expected facility to be: %d, got: %d", 20, logMessage.Facility)
		}
		if logMessage.Severity != 5 {
			t.Errorf("expected severity to be: %d, got: %d", 5, logMessage.Severity)
		}
		if !logMessage.Timestamp.Equal(now) {
			t.Errorf("expected timestamp to be: %s, got: %s", now, logMessage.Timestamp)
		}

		appname := "myproc"
		if !strings.EqualFold(logMessage.AppName(), appname) {
			t.Errorf("expected app name to be: %s, got: %s", appname, logMessage.AppName())
		}

		hostname := "mymachine"
		if !strings.EqualFold(logMessage.Hostname(), hostname) {
			t.Errorf("expected hostname to be: %s, got: %s", hostname, logMessage.Hostname())
		}

		pid := "10"
		if !strings.EqualFold(logMessage.ProcID(), pid) {
			t.Errorf("expected pid to be: %s, got: %s", pid, logMessage.ProcID())
		}

		facility := "LOCAL4"
		if !strings.EqualFold(logMessage.Facility.String(), facility) {
			t.Errorf("expected facility to be: %s, got: %s", facility, logMessage.Facility.String())
		}

		severity := "NOTICE"
		if !strings.EqualFold(logMessage.Severity.String(), severity) {
			t.Errorf("expected severity to be: %s, got: %s", severity, logMessage.Severity.String())
		}
	})
}

func TestRfc3164_ParseString(t *testing.T) {
	parser, err := parsesyslog.New(Type)
	if err != nil {
		t.Fatalf("failed to create new RFC3164 parser: %s", err)
	}
	t.Run("parse different valid and invalid log messages", func(t *testing.T) {
		for _, tc := range tests {
			t.Run(tc.Name, func(t *testing.T) {
				_, err = parser.ParseString(tc.Line)
				if err != nil && tc.Valid {
					t.Errorf("failed to parse message: %s", err)
				}
				if err == nil && !tc.Valid {
					t.Errorf("log message should have caused an error, but it didn't")
				}
			})
		}
	})
}

// BenchmarkRFC3164Msg_ParseReader benchmarks the ParseReader method of the rfc3164 type
func BenchmarkRFC3164Msg_ParseReader(b *testing.B) {
	msg := "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8\n"
	sr := strings.NewReader(msg)
	br := bufio.NewReader(sr)

	p, err := parsesyslog.New(Type)
	if err != nil {
		b.Errorf("failed to create new RFC3164 parser")
		return
	}
	b.Run("ParseReader", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err = p.ParseReader(br)
			if err != nil && !errors.Is(err, io.EOF) {
				b.Errorf("failed to read bytes: %s", err)
				break
			}
			_, _ = sr.Seek(0, io.SeekStart)
		}
	})
}

// BenchmarkParseStringRFC3164 benchmarks the ParseReader method of the RFC3164Msg type
func BenchmarkParseStringRFC3164(b *testing.B) {
	msg := `<165>Aug 24 05:34:00 mymachine myproc[10]: %% It's time to make the do-nuts.  %%  Ingredients: Mix=OK, Jelly=OK # Devices: Mixer=OK, Jelly_Injector=OK, Frier=OK # Transport: Conveyer1=OK, Conveyer2=OK # %%` + "\n"

	p, err := parsesyslog.New(Type)
	if err != nil {
		b.Errorf("failed to create new RFC3164 parser")
		return
	}
	b.Run("ParseString", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err = p.ParseString(msg)
			if err != nil {
				b.Errorf("failed to read bytes: %s", err)
				break
			}
		}
	})
}

// ErrFinished is returned when the mock reader runs out of data.
// It is distinct from io.EOF so you can detect it in tests.
var ErrFinished = errors.New("mock reader finished")

// MockReader implements io.Reader and returns ErrFinished when done.
type mockReader struct {
	data []byte
	pos  int
}

// NewMockReader creates a new MockReader with the given data.
func newMockReader(data string) *mockReader {
	return &mockReader{data: []byte(data[:len(data)-1])}
}

func (r *mockReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, ErrFinished // custom error instead of io.EOF
	}

	n := copy(p, r.data[r.pos:])
	r.pos += n
	if r.pos >= len(r.data) {
		return n, ErrFinished
	}
	return n, nil
}
