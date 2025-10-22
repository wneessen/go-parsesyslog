// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

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
		`83 <165>1 2003-10-11T22:14:15.003Z 192.0.2.1 evntslog - ID47 - ` + string([]byte{0xEF, 0xBB, 0xBF}) + `BOM-prefixed message`,

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
		`46 <34>1 2025-10-21T15:30:00Z h a p m [v="]"]] bad`,             // unopened SD
		`48 <34>1 2025-10-21T15:30:00Z h a p m [id ="v"] bad`,            // empty param name
		`35 <14>1 - - - - - [id@1 k="v"] hello`,                          // message too short
	}
)

func TestRfc5424_ParseString(t *testing.T) {
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
				_, err := parser.ParseString(tc.input)
				if err != nil && !tc.isInvalid {
					t.Errorf("failed to parse log message: %s", err)
				}
				if err == nil && tc.isInvalid {
					t.Errorf("log message %q should have caused an error, but it didn't", tc.input)
				}
			})
		}
	})
}

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
		if logMessage.MsgLength != len(expectMsg) {
			t.Errorf("expected message length to be: %d, got: %d", len(expectMsg), logMessage.MsgLength)
		}

		// mymachine app 12345 ID47
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

		if logMessage.StructuredData == nil {
			t.Fatalf("expected structured data to be set")
		}
		if len(logMessage.StructuredData) != 1 {
			t.Fatalf("expected structured data to have 1 element, got: %d", len(logMessage.StructuredData))
		}
		if len(logMessage.StructuredData[0].Param) != 3 {
			t.Fatalf("expected structured data to have 3 elements, got: %d",
				len(logMessage.StructuredData[0].Param))
		}

		expectSDID := []byte("exampleSDID@32473")
		if !bytes.Equal(logMessage.StructuredData[0].ID, expectSDID) {
			t.Errorf("expected structured data ID to be: %q, got: %q", expectSDID,
				logMessage.StructuredData[0].ID)
		}
		expectSDParam := map[string]string{
			"iut":         "3",
			"eventSource": "Application",
			"eventID":     "1011",
		}
		found := 0
		for _, p := range logMessage.StructuredData[0].Param {
			if _, ok := expectSDParam[string(p.Name)]; ok {
				if !bytes.Equal(p.Value, []byte(expectSDParam[string(p.Name)])) {
					t.Errorf("expected param %q to be: %q, got: %q", p.Name, string(p.Value),
						expectSDParam[string(p.Name)])
				}
				found++
				continue
			}
			t.Errorf("unexpected param: %q", p.Name)
		}
		if found != len(expectSDParam) {
			t.Errorf("expected %d params, got: %d", len(expectSDParam), found)
		}
	})
}

func TestRfc5424_parseBOM(t *testing.T) {
	t.Run("parsing BOM with broken reader should fail", func(t *testing.T) {
		reader := failReader{}
		brokenReader := bufio.NewReader(reader)
		parser := testRFC5424Parser(t)
		logMessage := &parsesyslog.LogMsg{}

		if err := parser.parseBOM(brokenReader, logMessage); err == nil {
			t.Errorf("expected error to be returned, but it was nil")
		}
	})
}

func TestRfc5424_parseMessageLength(t *testing.T) {
	t.Run("parsing length with broken reader should fail", func(t *testing.T) {
		reader := failReader{}
		brokenReader := bufio.NewReader(reader)
		parser := testRFC5424Parser(t)

		if _, err := parser.parseMessageLength(brokenReader); err == nil {
			t.Errorf("expected error to be returned, but it was nil")
		}
	})
}

func TestRfc5424_parsePriority(t *testing.T) {
	t.Run("parsing priority with broken reader should fail", func(t *testing.T) {
		reader := failReader{}
		brokenReader := bufio.NewReader(reader)
		parser := testRFC5424Parser(t)
		logMessage := &parsesyslog.LogMsg{}

		if err := parser.parsePriority(brokenReader, logMessage); err == nil {
			t.Errorf("expected error to be returned, but it was nil")
		}
	})
	t.Run("parsing priority with invalid value should fail", func(t *testing.T) {
		reader := bufio.NewReader(strings.NewReader("<193>"))
		parser := testRFC5424Parser(t)
		logMessage := &parsesyslog.LogMsg{}

		err := parser.parsePriority(reader, logMessage)
		if err == nil {
			t.Errorf("expected error to be returned, but it was nil")
		}
		if err != nil && !errors.Is(err, parsesyslog.ErrInvalidPrio) {
			t.Errorf("expected error to be: %s, got: %s", parsesyslog.ErrInvalidPrio, err)
		}
	})
}

func TestRfc5424_parseProtoVersion(t *testing.T) {
	t.Run("parsing protocol version with broken reader should fail", func(t *testing.T) {
		reader := failReader{}
		brokenReader := bufio.NewReader(reader)
		parser := testRFC5424Parser(t)
		logMessage := &parsesyslog.LogMsg{}

		if err := parser.parseProtoVersion(brokenReader, logMessage); err == nil {
			t.Errorf("expected error to be returned, but it was nil")
		}
	})
	t.Run("parsing protocol version with invalid value should fail", func(t *testing.T) {
		reader := bufio.NewReader(strings.NewReader("0 "))
		parser := testRFC5424Parser(t)
		logMessage := &parsesyslog.LogMsg{}

		err := parser.parseProtoVersion(reader, logMessage)
		if err == nil {
			t.Errorf("expected error to be returned, but it was nil")
		}
		if err != nil && !errors.Is(err, parsesyslog.ErrInvalidProtoVersion) {
			t.Errorf("expected error to be: %s, got: %s", parsesyslog.ErrInvalidProtoVersion, err)
		}
	})
}

func TestRfc5424_parseTimestamp(t *testing.T) {
	t.Run("parsing timestamp with broken reader should fail", func(t *testing.T) {
		reader := failReader{}
		brokenReader := bufio.NewReader(reader)
		parser := testRFC5424Parser(t)
		logMessage := &parsesyslog.LogMsg{}

		if err := parser.parseTimestamp(brokenReader, logMessage); err == nil {
			t.Errorf("expected error to be returned, but it was nil")
		}
	})
	t.Run("parsing timestamp with invalid value should fail", func(t *testing.T) {
		reader := bufio.NewReader(strings.NewReader("2025-10-21T15:30 "))
		parser := testRFC5424Parser(t)
		logMessage := &parsesyslog.LogMsg{}

		err := parser.parseTimestamp(reader, logMessage)
		if err == nil {
			t.Errorf("expected error to be returned, but it was nil")
		}
		if err != nil && !errors.Is(err, parsesyslog.ErrInvalidTimestamp) {
			t.Errorf("expected error to be: %s, got: %s", parsesyslog.ErrInvalidTimestamp, err)
		}
	})
}

func TestRfc5424_parseHostname(t *testing.T) {
	t.Run("parsing hostname with broken reader should fail", func(t *testing.T) {
		reader := failReader{}
		brokenReader := bufio.NewReader(reader)
		parser := testRFC5424Parser(t)
		logMessage := &parsesyslog.LogMsg{}

		if err := parser.parseHostname(brokenReader, logMessage); err == nil {
			t.Errorf("expected error to be returned, but it was nil")
		}
	})
}

func TestRfc5424_parseAppName(t *testing.T) {
	t.Run("parsing app name with broken reader should fail", func(t *testing.T) {
		reader := failReader{}
		brokenReader := bufio.NewReader(reader)
		parser := testRFC5424Parser(t)
		logMessage := &parsesyslog.LogMsg{}

		if err := parser.parseAppName(brokenReader, logMessage); err == nil {
			t.Errorf("expected error to be returned, but it was nil")
		}
	})
}

func TestRfc5424_parseProcID(t *testing.T) {
	t.Run("parsing proc ID with broken reader should fail", func(t *testing.T) {
		reader := failReader{}
		brokenReader := bufio.NewReader(reader)
		parser := testRFC5424Parser(t)
		logMessage := &parsesyslog.LogMsg{}

		if err := parser.parseProcID(brokenReader, logMessage); err == nil {
			t.Errorf("expected error to be returned, but it was nil")
		}
	})
}

func TestRfc5424_parseMsgID(t *testing.T) {
	t.Run("parsing message ID with broken reader should fail", func(t *testing.T) {
		reader := failReader{}
		brokenReader := bufio.NewReader(reader)
		parser := testRFC5424Parser(t)
		logMessage := &parsesyslog.LogMsg{}

		if err := parser.parseMsgID(brokenReader, logMessage); err == nil {
			t.Errorf("expected error to be returned, but it was nil")
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

func testRFC5424Parser(t *testing.T) *rfc5424 {
	t.Helper()
	return &rfc5424{
		buf:   bytes.NewBuffer(nil),
		arena: make([]byte, 0, 2048),
		sds:   make([]parsesyslog.StructuredDataElement, 0),
	}
}

// failReader is a reader that always returns an error on Read.
type failReader struct{}

// Read returns an error on every call. It satisfies the io.Reader interface.
func (f failReader) Read([]byte) (n int, err error) {
	return 0, errors.New("intentionally failing")
}
