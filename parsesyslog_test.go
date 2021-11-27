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
	if l.Message.String() != "Hello, World!" {
		t.Errorf("ParseString() wrong message => expected: %s, got: %s", "Hello, World!",
			l.Message.String())
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
	if l.Message.String() != "Hello, World!" {
		t.Errorf("ParseString() wrong message => expected: %s, got: %s", "Hello, World!",
			l.Message.String())
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

// TestParseStringRFC3164 tests the NewRFC3164Parser method together with the ParseString
// method (which implies ParseReader as well)
/*
func TestParseStringRFC3164(t *testing.T) {
	p := NewRFC3164Parser()
	if p == nil {
		t.Error("failed to create new RFC3164 parser")
		return
	}
	msg := "<13>Nov 27 16:00:35 arch-vm wneessen[1130275]: test\n"
	l, err := ParseString(p, msg)
	if err != nil {
		t.Errorf("failed to parse message: %s", err)
	}
	if l.MsgLength != 4 {
		t.Errorf("ParseString() wrong msg length => expected: %d, got: %d", 4, l.MsgLength)
	}
	if l.MsgID != "" {
		t.Errorf("ParseString() wrong msg ID => expected: %s, got: %s", "", l.MsgID)
	}
	if l.ProcID != "1130275" {
		t.Errorf("ParseString() wrong proc ID => expected: %s, got: %s", "1130275", l.ProcID)
	}
	if string(l.Message) != `test` {
		t.Errorf("ParseString() wrong message => expected: %q, got: %q", `test`, string(l.Message))
	}
	if l.Priority != 13 {
		t.Errorf("ParseString() wrong priority => expected: %d, got: %d", 13, l.Priority)
	}
	if l.Facility != 1 {
		t.Errorf("ParseString() wrong facility => expected: %d, got: %d", 1, l.Facility)
	}
	if l.Severity != 5 {
		t.Errorf("ParseString() wrong severity => expected: %d, got: %d", 5, l.Severity)
	}
	if l.Timestamp.UTC().Format("01-02 15:04:05") != "11-27 16:00:35" {
		t.Errorf("ParseString() wrong timestamp => expected: %s, got: %s", "11-27 16:00:35",
			l.Timestamp.UTC().Format("01-02 15:04:05"))
	}
}

*/

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

/*
// BenchmarkParseStringRFC3164 benchmarks the ParseReader method of the RFC3164Msg type
func BenchmarkParseStringRFC3164(b *testing.B) {
	b.ReportAllocs()
	msg := `<165>Aug 24 05:34:00 mymachine myproc[10]: %% It's time to make the do-nuts.  %%  Ingredients: Mix=OK, Jelly=OK # Devices: Mixer=OK, Jelly_Injector=OK, Frier=OK # Transport: Conveyer1=OK, Conveyer2=OK # %%
`
	var lm LogMsg
	var err error

	p := NewRFC3164Parser()
	if p == nil {
		b.Error("failed to create RFC3164 parser")
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
*/
