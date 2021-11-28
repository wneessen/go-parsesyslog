package parsesyslog

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
)

// TestRFC3164Msg_parseTag tests the parseTag method of the RFC3164Msg type
func TestRFC3164Msg_parseTag(t *testing.T) {
	tests := []struct {
		name     string
		msg      string
		want     string
		wantpid  string
		wantErr  bool
		wantText string
	}{
		{"valid tag with pid", `syslog-ng[1122680]: Test123`, `syslog-ng`, `1122680`,
			false, `Test123`},
		{"valid tag no pid", `su: Test123`, `su`, ``, false, `Test123`},
		{"no tag", `This is a test `, ``, ``, false, `This is a test `},
		{"mark", "-- MARK --\n", ``, ``, false, "-- MARK --\n"},
	}
	for _, tt := range tests {
		sr := strings.NewReader(tt.msg)
		br := bufio.NewReader(sr)
		t.Run(tt.name, func(t *testing.T) {
			m := &RFC3164Msg{}
			lm := &LogMsg{}
			if err := m.parseTag(br, lm); (err != nil) != tt.wantErr {
				t.Errorf("parseTag() error = %v, wantErr %v", err, tt.wantErr)
			}
			if lm.Message.String() != tt.wantText {
				t.Errorf("parseTag() wrong msg => want: %q, got: %q", tt.wantText, lm.Message.String())
			}
			if lm.AppName != tt.want {
				t.Errorf("parseTag() wrong app => want: %q, got: %q", tt.want, lm.AppName)
			}
			if lm.ProcID != tt.wantpid {
				t.Errorf("parseTag() wrong pid => want: %s, got: %s", tt.wantpid, lm.ProcID)
			}
		})
	}
}

// TestRFC3164Msg_ParseReader tests the ParseReader method of the RFC3164Msg type
func TestRFC3164Msg_ParseReader(t *testing.T) {
	sr := strings.NewReader("<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8\n<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8")
	br := bufio.NewReader(sr)
	m := RFC3164Msg{}

	lm, err := m.parseReader(br)
	if err != nil {
		t.Errorf("failed to parse RFC3164 message: %s", err)
	}
	_ = lm
}

// BenchmarkRFC3164Msg_ParseReader benchmarks the ParseReader method of the RFC3164Msg type
func BenchmarkRFC3164Msg_ParseReader(b *testing.B) {
	b.ReportAllocs()
	sr := strings.NewReader("<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8\n")
	br := bufio.NewReader(sr)
	m := RFC3164Msg{}
	var lm LogMsg
	var err error

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lm, err = m.parseReader(br)
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
