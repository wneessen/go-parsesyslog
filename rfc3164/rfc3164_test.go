// SPDX-FileCopyrightText: 2021-2023 Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package rfc3164

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/wneessen/go-parsesyslog"
)

// TestParseStringRFC3164 tests the NewRFC3164Parser method together with the ParseString
// method (which implies ParseReader as well)
func TestParseStringRFC3164(t *testing.T) {
	p, err := parsesyslog.New(Type)
	if err != nil {
		t.Errorf("failed to create new RFC3164 parser")
		return
	}
	message := "<13>Nov 27 16:00:35 arch-vm wneessen[1130275]: test\n"
	l, err := p.ParseString(message)
	if err != nil {
		t.Errorf("failed to parse message: %s", err)
	}
	if l.MsgLength != 5 {
		t.Errorf("ParseString() wrong message length => expected: %d, got: %d", 5, l.MsgLength)
	}
	if !bytes.Equal(l.MsgID, []byte("")) {
		t.Errorf("ParseString() wrong message ID => expected: %s, got: %s", "", l.MsgID)
	}
	if !bytes.Equal(l.PID, []byte("1130275")) {
		t.Errorf("ParseString() wrong proc ID => expected: %s, got: %s", "1130275", l.PID)
	}
	if l.Message.String() != "test\n" {
		t.Errorf("ParseString() wrong message => expected: %q, got: %q", "test\n", l.Message.String())
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

// TestRFC3164Msg_parseTag tests the parseTag method of the msg type
func TestRFC3164Msg_parseTag(t *testing.T) {
	tests := []struct {
		name     string
		msg      string
		want     string
		wantpid  string
		wantErr  bool
		wantText string
	}{
		{
			"valid tag with pid", `syslog-ng[1122680]: Test123`, `syslog-ng`, `1122680`,
			false, `Test123`,
		},
		{"valid tag no pid", `su: Test123`, `su`, ``, false, `Test123`},
		{"no tag", `This is a test `, ``, ``, false, `This is a test `},
		{"mark", "-- MARK --\n", ``, ``, false, "-- MARK --\n"},
	}
	for _, tt := range tests {
		sr := strings.NewReader(tt.msg)
		br := bufio.NewReader(sr)
		t.Run(tt.name, func(t *testing.T) {
			m := &msg{appBuffer: bytes.NewBuffer(nil), pidBuffer: bytes.NewBuffer(nil)}
			lm := &parsesyslog.LogMsg{}
			if err := m.parseTag(br, lm); (err != nil) != tt.wantErr {
				t.Errorf("parseTag() error = %v, wantErr %v", err, tt.wantErr)
			}
			if lm.Message.String() != tt.wantText {
				t.Errorf("parseTag() wrong msg => want: %q, got: %q", tt.wantText, lm.Message.String())
			}
			if !bytes.Equal(lm.App, []byte(tt.want)) {
				t.Errorf("parseTag() wrong app => want: %q, got: %q", tt.want, lm.App)
			}
			if !bytes.Equal(lm.PID, []byte(tt.wantpid)) {
				t.Errorf("parseTag() wrong pid => want: %s, got: %s", tt.wantpid, lm.PID)
			}
		})
	}
}

// TestRFC3164Msg_ParseReader tests the ParseReader method of the msg type
func TestRFC3164Msg_ParseReader(t *testing.T) {
	sr := strings.NewReader("<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8\n<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8")
	br := bufio.NewReader(sr)
	m := &msg{appBuffer: bytes.NewBuffer(nil), pidBuffer: bytes.NewBuffer(nil)}

	lm, err := m.ParseReader(br)
	if err != nil {
		t.Errorf("failed to parse RFC3164 message: %s", err)
	}
	_ = lm
}

// BenchmarkRFC3164Msg_ParseReader benchmarks the ParseReader method of the msg type
func BenchmarkRFC3164Msg_ParseReader(b *testing.B) {
	b.ReportAllocs()
	sr := strings.NewReader("<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8\n")
	br := bufio.NewReader(sr)
	var lm parsesyslog.LogMsg
	var err error

	p, err := parsesyslog.New(Type)
	if err != nil {
		b.Errorf("failed to create new RFC3164 parser")
		return
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lm, err = p.ParseReader(br)
		if err != nil && !errors.Is(err, io.EOF) {
			b.Errorf("failed to read bytes: %s", err)
			break
		}
		_, err := sr.Seek(0, io.SeekStart)
		if err != nil {
			b.Errorf("failed to seek back to start: %s", err)
			break
		}
		br.Reset(sr)
	}
	_ = lm
}

// BenchmarkParseStringRFC3164 benchmarks the ParseReader method of the RFC3164Msg type
func BenchmarkParseStringRFC3164(b *testing.B) {
	b.ReportAllocs()
	msg := `<165>Aug 24 05:34:00 mymachine myproc[10]: %% It's time to make the do-nuts.  %%  Ingredients: Mix=OK, Jelly=OK # Devices: Mixer=OK, Jelly_Injector=OK, Frier=OK # Transport: Conveyer1=OK, Conveyer2=OK # %%
`
	var lm parsesyslog.LogMsg
	var err error

	p, err := parsesyslog.New(Type)
	if err != nil {
		b.Errorf("failed to create new RFC3164 parser")
		return
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lm, err = p.ParseString(msg)
		if err != nil {
			b.Errorf("failed to read bytes: %s", err)
			break
		}
	}
	_ = lm
}
