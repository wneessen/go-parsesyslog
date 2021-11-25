package syslog

import (
	"bufio"
	"io"
	"strings"
	"testing"
)

// TestRFC5424Msg_ParseReader tests the ParseReader method of the RFC5424Msg type
func TestRFC5424Msg_ParseReader(t *testing.T) {
	msg := `120 <45>1 2021-12-23T01:23:45+01:00 test-mbp syslog-ng 53198 - [meta sequenceId="1"] syslog-ng starting up; version='3.34.1'`
	sr := strings.NewReader(msg)
	br := bufio.NewReader(sr)
	m := &RFC5424Msg{}
	l, err := m.ParseReader(br)
	if err != nil {
		t.Errorf("failed to parse log message: %s", err)
		return
	}
	if l.MsgLength <= 0 {
		t.Error("failed to parse log message: empty message returned")
	}
	if len(l.Message) != l.MsgLength {
		t.Errorf("failed to parse log message: returned message does not match retured length => msg: %d, l: %d",
			len(l.Message), l.MsgLength)
	}
}

// TestRFC5424Msg_parsePriority tests the parsePriority method of the RFC5424Msg parser
func TestRFC5424Msg_parsePriority(t *testing.T) {
	tests := []struct {
		name         string
		msg          string
		wantPrio     Priority
		wantFacility Facility
		wantSeverity Severity
		wantErr      bool
	}{
		{"Syslog/Notice is 5 and 5", `<45>1`, Syslog | Notice, 5, 5, false},
		{"Kern/Emergency is 0 and 0", `<0>1`, Kern | Emergency, 0, 0, false},
		{"Mail/Alert is 2 and 1", `<17>1`, Mail | Alert, 2, 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := strings.NewReader(tt.msg)
			br := bufio.NewReader(sr)
			m := &RFC5424Msg{}
			lm := &LogMsg{}
			if err := m.parsePriority(br, lm); (err != nil) != tt.wantErr {
				t.Errorf("parseHeader() error = %v, wantErr %v", err, tt.wantErr)
			}
			if lm.Priority != tt.wantPrio {
				t.Errorf("parseHeader() wrong prio = want: %d, got: %d", tt.wantPrio, lm.Priority)
			}
			if lm.Facility != tt.wantFacility {
				t.Errorf("parseHeader() wrong facility = want: %d, got: %d", tt.wantFacility, lm.Facility)
			}
			if lm.Severity != tt.wantSeverity {
				t.Errorf("parseHeader() wrong severity = want: %d, got: %d", tt.wantSeverity, lm.Severity)
			}
		})
	}
}

// TestRFC5424Msg_parseTimestamp tests the parseTimestamp method of the RFC5424Msg parser
func TestRFC5424Msg_parseTimestamp(t *testing.T) {
	tf := `2006-01-02 15:04:05.000 -07`
	tests := []struct {
		name    string
		msg     string
		want    string
		wantErr bool
	}{
		{`1985-04-12T23:20:50.52Z`, `1985-04-12T23:20:50.52Z `,
			`1985-04-12 23:20:50.520 +00`, false},
		{`1985-04-12T19:20:50.52-04:00`, `1985-04-12T23:20:50.52Z `,
			`1985-04-12 23:20:50.520 +00`, false},
		{`2003-10-11T22:14:15.003Z`, `2003-10-11T22:14:15.003Z `,
			`2003-10-11 22:14:15.003 +00`, false},
		{`2003-08-24T05:14:15.000003-07:00`, `2003-08-24T05:14:15.000003-07:00 `,
			`2003-08-24 12:14:15.000 +00`, false},
		{`NILVALUE`, `- `, `0001-01-01 00:00:00.000 +00`, false},
		{`Invalid TS`, `20211112345 `, `0001-01-01 00:00:00.000 +00`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := strings.NewReader(tt.msg)
			br := bufio.NewReader(sr)
			m := &RFC5424Msg{}
			lm := &LogMsg{}
			if err := m.parseTimestamp(br, lm); (err != nil) != tt.wantErr {
				t.Errorf("parseTimestamp() error = %v, wantErr %v", err, tt.wantErr)
			}
			if lm.Timestamp.UTC().Format(tf) != tt.want {
				t.Errorf("parseTimestamp() wrong timestamp = want %s, got: %s",
					tt.want, lm.Timestamp.UTC().Format(tf))
			}
		})
	}
}

// TestRFC5424Msg_parseHostname tests the parseHostname method of the RFC5424Msg parser
func TestRFC5424Msg_parseHostname(t *testing.T) {
	tests := []struct {
		name    string
		msg     string
		want    string
		wantErr bool
	}{
		{`FQDN`, `host.domain.tld `, `host.domain.tld`, false},
		{`IPv4`, `10.0.1.2 `, `10.0.1.2`, false},
		{`IPv6`, `2345:0425:2CA1:0000:0000:0567:5673:23b5 `, `2345:0425:2CA1:0000:0000:0567:5673:23b5`,
			false},
		{`Host`, `test-machine `, `test-machine`, false},
		{`NILVALUE`, `- `, ``, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := strings.NewReader(tt.msg)
			br := bufio.NewReader(sr)
			m := &RFC5424Msg{}
			lm := &LogMsg{}
			if err := m.parseHostname(br, lm); (err != nil) != tt.wantErr {
				t.Errorf("parseHostname() error = %v, wantErr %v", err, tt.wantErr)
			}
			if lm.Hostname != tt.want {
				t.Errorf("parseHostname() wrong = expected: %s, got: %s", tt.want, lm.Hostname)
			}
		})
	}
}

// BenchmarkRFC5424Msg_ParseReader benchmarks the ParseReader method of the RFC5424Msg type
func BenchmarkRFC5424Msg_ParseReader(b *testing.B) {
	b.ReportAllocs()
	sr := strings.NewReader(`107 <7>1 2016-02-28T09:57:10.804642398-05:00 myhostname someapp - - [foo@1234 Revision="1.2.3.4"] Hello, World!`)
	br := bufio.NewReader(sr)
	m := RFC5424Msg{}
	var lm LogMsg
	var err error

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lm, err = m.ParseReader(br)
		if err != nil {
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
