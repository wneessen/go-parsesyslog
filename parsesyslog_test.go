package parsesyslog

import (
	"bufio"
	"strings"
	"testing"
)

// TestParseStringRFC5424 tests the NewRFC5424Parser method together with the ParseString
// method (which implies ParseReader as well)
func TestParseStringRFC5424(t *testing.T) {
	p := NewRFC5424Parser()
	if p == nil {
		t.Error("failed to create new RFC5424 parser")
		return
	}
	msg := `107 <7>1 2016-02-28T09:57:10.804642398-05:00 myhostname someapp - - [foo@1234 Revision="1.2.3.4"] Hello, World!`
	l, err := ParseString(p, msg)
	if err != nil {
		t.Errorf("failed to parse message: %s", err)
	}
	if l.MsgLength != 13 {
		t.Errorf("ParseString() wrong msg length => expected: %d, got: %d", 13, l.MsgLength)
	}
	if l.MsgID != "" {
		t.Errorf("ParseString() wrong msg ID => expected: %s, got: %s", "", l.MsgID)
	}
	if l.ProcID != "" {
		t.Errorf("ParseString() wrong proc ID => expected: %s, got: %s", "", l.ProcID)
	}
	if string(l.Message) != "Hello, World!" {
		t.Errorf("ParseString() wrong message => expected: %s, got: %s", "Hello, World!",
			string(l.Message))
	}
	if l.Priority != 7 {
		t.Errorf("ParseString() wrong priority => expected: %d, got: %d", 7, l.Priority)
	}
	if l.Facility != 0 {
		t.Errorf("ParseString() wrong facility => expected: %d, got: %d", 0, l.Facility)
	}
	if l.Severity != 7 {
		t.Errorf("ParseString() wrong severity => expected: %d, got: %d", 7, l.Severity)
	}
	if l.ProtoVersion != 1 {
		t.Errorf("ParseString() wrong protocol version => expected: %d, got: %d", 7, l.ProtoVersion)
	}
	if l.Timestamp.UTC().Format("2006-01-02 15:04:05") != "2016-02-28 14:57:10" {
		t.Errorf("ParseString() wrong timestamp => expected: %s, got: %s", "2016-02-28 14:57:10",
			l.Timestamp.UTC().Format("2006-01-02 15:04:05"))
	}
}

// TestParseReaderRFC5424 tests the NewRFC5424Parser method together with a ParseReader call
func TestParseReaderRFC5424(t *testing.T) {
	p := NewRFC5424Parser()
	if p == nil {
		t.Error("failed to create new RFC5424 parser")
		return
	}
	msg := `107 <7>1 2016-02-28T09:57:10.804642398-05:00 myhostname someapp - - [foo@1234 Revision="1.2.3.4"] Hello, World!`
	sr := strings.NewReader(msg)
	br := bufio.NewReader(sr)
	l, err := ParseReader(p, br)
	if err != nil {
		t.Errorf("failed to parse message: %s", err)
	}
	if l.MsgLength != 13 {
		t.Errorf("ParseString() wrong msg length => expected: %d, got: %d", 13, l.MsgLength)
	}
	if l.MsgID != "" {
		t.Errorf("ParseString() wrong msg ID => expected: %s, got: %s", "", l.MsgID)
	}
	if l.ProcID != "" {
		t.Errorf("ParseString() wrong proc ID => expected: %s, got: %s", "", l.ProcID)
	}
	if string(l.Message) != "Hello, World!" {
		t.Errorf("ParseString() wrong message => expected: %s, got: %s", "Hello, World!",
			string(l.Message))
	}
	if l.Priority != 7 {
		t.Errorf("ParseString() wrong priority => expected: %d, got: %d", 7, l.Priority)
	}
	if l.Facility != 0 {
		t.Errorf("ParseString() wrong facility => expected: %d, got: %d", 0, l.Facility)
	}
	if l.Severity != 7 {
		t.Errorf("ParseString() wrong severity => expected: %d, got: %d", 7, l.Severity)
	}
	if l.ProtoVersion != 1 {
		t.Errorf("ParseString() wrong protocol version => expected: %d, got: %d", 7, l.ProtoVersion)
	}
	if l.Timestamp.UTC().Format("2006-01-02 15:04:05") != "2016-02-28 14:57:10" {
		t.Errorf("ParseString() wrong timestamp => expected: %s, got: %s", "2016-02-28 14:57:10",
			l.Timestamp.UTC().Format("2006-01-02 15:04:05"))
	}
}

// BenchmarkParseStringRFC5424 benchmarks the ParseReader method of the RFC5424Msg type
func BenchmarkParseStringRFC5424(b *testing.B) {
	b.ReportAllocs()
	msg := `107 <7>1 2016-02-28T09:57:10.804642398-05:00 myhostname someapp - - [foo@1234 Revision="1.2.3.4"] Hello, World!`
	var lm LogMsg
	var err error

	p := NewRFC5424Parser()
	if p == nil {
		b.Error("failed to create RFC5424 parser")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lm, err = ParseString(p, msg)
		if err != nil {
			b.Errorf("failed to read bytes: %s", err)
			break
		}
	}
	_ = lm
}
