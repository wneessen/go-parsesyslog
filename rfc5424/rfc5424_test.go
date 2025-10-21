package rfc5424

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/wneessen/go-parsesyslog"
)

var (
	valid = []string{
		// Classic full example
		`151 <34>1 2025-10-21T15:30:00Z mymachine app 12345 ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] An application event log entry`,

		// NIL SD, IPv4 host, BOM-prefixed message (BOM = 3 bytes)
		`82 <165>1 2003-10-11T22:14:15.003Z 192.0.2.1 evntslog - ID47 - ` + string([]byte{0xEF, 0xBB, 0xBF}) + `BOM-prefixed message`,

		// Multiple SD elements + tz offset + microseconds
		`120 <165>1 2003-08-24T05:14:15.000003-07:00 myhost su - ID47 [meta@123 foo="bar"][example@9999 a="b" c="d"] multi-SD message`,

		// NIL timestamp/host/app/proc/msgid but with SD and MSG
		`34 <14>1 - - - - - [id@1 k="v"] hello`,

		// Escaped quotes, backslash, and closing bracket inside SD param
		`99 <190>1 2024-12-31T23:59:59Z host app 111 msg42 [x@999 q="quote: \" backslash: \\ bracket: \"]"] end`,

		// Minimal header + single SD + short MSG
		`46 <0>1 2020-01-01T00:00:00Z h a p m [id k="v"] m`,

		// Dash for SD, non-empty message
		`72 <13>1 2022-06-01T12:00:00+02:00 host app - mid - No structured data here`,
	}

	invalid = []string{
		`XX <34>1 2025-10-21T15:30:00Z h a p m - bad`, // Missing space separator
		`39<34>1 2025-10-21T15:30:00Z h a p m - bad`,
		`39 34>1 2025-10-21T15:30:00Z h a p m - bad`,                     // missing '<'
		`38 <>1 2025-10-21T15:30:00Z h a p m - bad`,                      // empty PRI
		`40 <3x>1 2025-10-21T15:30:00Z h a p m - bad`,                    // non-digit in PRI
		`39 <34> 2025-10-21T15:30:00Z h a p m - bad`,                     // missing VERSION
		`40 <34>0 2025-10-21T15:30:00Z h a p m - bad`,                    // version 0
		`40 <34>1 2025-13-01T00:00:00Z h a p m - bad`,                    // bad timestamp
		`40 <34>1 2025-10-21 15:30:00Z h a p m - bad`,                    // no 'T'
		`39 <34>1 2025-10-21T15:30:00Z h a p m- bad`,                     // missing SP
		`59 <34>1 2025-10-21T15:30:00Z h a p m [id k="oops ] here"] bad`, // unescaped ']'
		`53 <34>1 2025-10-21T15:30:00Z h a p m [bad id k="v"] bad`,       // space in SD-ID
		`48 <34>1 2025-10-21T15:30:00Z h a p m [id k="v" bad`,            // unclosed SD
		`48 <34>1 2025-10-21T15:30:00Z h a p m [id ="v"] bad`,            // empty param name
	}
)

func TestRfc5424_ParseReader(t *testing.T) {
	type testCase struct {
		name      string
		input     string
		isInvalid bool
	}

	var tests []testCase
	for i, s := range valid {
		tests = append(tests, testCase{
			name:      fmt.Sprintf("valid/%d", i),
			input:     s,
			isInvalid: false,
		})
	}
	for i, s := range invalid {
		tests = append(tests, testCase{
			name:      fmt.Sprintf("invalid/%d", i),
			input:     s,
			isInvalid: true,
		})
	}
	parser, err := parsesyslog.New(Type)
	if err != nil {
		t.Errorf("failed to create new RFC5424 parser")
		return
	}

	t.Run("parse different log valid/invalid log messages", func(t *testing.T) {
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				sr := strings.NewReader(tc.input)
				_, err := parser.ParseReader(sr)
				if err != nil && !tc.isInvalid {
					t.Errorf("failed to parse log message: %s", err)
				}
				if err == nil && tc.isInvalid {
					t.Errorf("log message %q should have caused an error, but it didn't", tc.input)
				}
			})
		}
	})

	t.Run("parsing valid message should provide the correct values", func(t *testing.T) {
		logMessage, err := parser.ParseReader(strings.NewReader(valid[0]))
		if err != nil {
			t.Fatalf("failed to parse message: %s", err)
		}
		expectMsg := "An application event log entry"
		if !strings.EqualFold(logMessage.Message.String(), expectMsg) {
			t.Errorf("expected message to be: %q, got: %q", expectMsg, logMessage.Message.String())
		}

		//mymachine app 12345 ID47
		expectApp := "app"
		if !strings.EqualFold(logMessage.AppName(), expectApp) {
			t.Errorf("expected app name to be: %q, got: %q", expectApp, logMessage.AppName())
		}
		expectHost := "mymachine"
		if !strings.EqualFold(logMessage.Hostname(), expectHost) {
			t.Errorf("expected hostname to be: %q, got: %q", expectHost, logMessage.Hostname())
		}
		expectProc := "12345"
		if !strings.EqualFold(logMessage.ProcID(), expectProc) {
			t.Errorf("expected proc id to be: %q, got: %q", expectProc, logMessage.ProcID())
		}

		expectMsgID := []byte("ID47")
		if !bytes.Equal(logMessage.MsgID, expectMsgID) {
			t.Errorf("expected proc id to be: %q, got: %q", expectMsgID, logMessage.MsgID)
		}
	})
}

// BenchmarkRFC3164Msg_ParseReader benchmarks the ParseReader method of the rfc3164 type
func BenchmarkRFC5424Msg_ParseReader(b *testing.B) {
	msg := `151 <34>1 2025-10-21T15:30:00Z mymachine app 12345 ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] An application event log entry`
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
