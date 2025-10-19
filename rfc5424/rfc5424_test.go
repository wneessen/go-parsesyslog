// SPDX-FileCopyrightText: 2021-2023 Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package rfc5424

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/wneessen/go-parsesyslog"
)

// TestParseStringRFC5424 tests the NewRFC5424Parser method together with the ParseString
// method (which implies ParseReader as well)
func TestParseStringRFC5424(t *testing.T) {
	p, err := parsesyslog.New(Type)
	if err != nil {
		t.Errorf("failed to create new RFC5424 parser")
		return
	}
	msg := `107 <7>1 2016-02-28T09:57:10.804642398-05:00 myhostname someapp - - [foo@1234 Revision="1.2.3.4"] Hello, World!`
	l, err := p.ParseString(msg)
	if err != nil {
		t.Errorf("failed to parse message: %s", err)
	}
	if l.MsgLength != 13 {
		t.Errorf("ParseString() wrong msg length => expected: %d, got: %d", 13, l.MsgLength)
	}
	if !bytes.Equal(l.MsgID, []byte("")) {
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
	p, err := parsesyslog.New(Type)
	if err != nil {
		t.Errorf("failed to create new RFC5424 parser")
		return
	}
	msg := `107 <7>1 2016-02-28T09:57:10.804642398-05:00 myhostname someapp - - [foo@1234 Revision="1.2.3.4"] Hello, World!`
	sr := strings.NewReader(msg)
	br := bufio.NewReader(sr)
	l, err := p.ParseReader(br)
	if err != nil {
		t.Errorf("failed to parse message: %s", err)
	}
	if l.MsgLength != 13 {
		t.Errorf("ParseString() wrong msg length => expected: %d, got: %d", 13, l.MsgLength)
	}
	if !bytes.Equal(l.MsgID, []byte("")) {
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

// TestRFC5424Msg_parseTimestamp tests the parseTimestamp method of the msg parser
func TestRFC5424Msg_parseTimestamp(t *testing.T) {
	tf := `2006-01-02 15:04:05.000 -07`
	tests := []struct {
		name    string
		msg     string
		want    string
		wantErr bool
	}{
		{
			`1985-04-12T23:20:50.52Z`, `1985-04-12T23:20:50.52Z `,
			`1985-04-12 23:20:50.520 +00`, false,
		},
		{
			`1985-04-12T19:20:50.52-04:00`, `1985-04-12T23:20:50.52Z `,
			`1985-04-12 23:20:50.520 +00`, false,
		},
		{
			`2003-10-11T22:14:15.003Z`, `2003-10-11T22:14:15.003Z `,
			`2003-10-11 22:14:15.003 +00`, false,
		},
		{
			`2003-08-24T05:14:15.000003-07:00`, `2003-08-24T05:14:15.000003-07:00 `,
			`2003-08-24 12:14:15.000 +00`, false,
		},
		{`NILVALUE`, `- `, `0001-01-01 00:00:00.000 +00`, false},
		{`Invalid TS`, `20211112345 `, `0001-01-01 00:00:00.000 +00`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := strings.NewReader(tt.msg)
			br := bufio.NewReader(sr)
			m := &msg{}
			lm := &parsesyslog.LogMsg{}
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

// TestRFC5424Msg_parseHostname tests the parseHostname method of the msg parser
func TestRFC5424Msg_parseHostname(t *testing.T) {
	tests := []struct {
		name    string
		msg     string
		want    string
		wantErr bool
	}{
		{`FQDN`, `host.domain.tld `, `host.domain.tld`, false},
		{`IPv4`, `10.0.1.2 `, `10.0.1.2`, false},
		{
			`IPv6`, `2345:0425:2CA1:0000:0000:0567:5673:23b5 `, `2345:0425:2CA1:0000:0000:0567:5673:23b5`,
			false,
		},
		{`Host`, `test-machine `, `test-machine`, false},
		{`NILVALUE`, `- `, ``, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := strings.NewReader(tt.msg)
			br := bufio.NewReader(sr)
			m := &msg{}
			lm := &parsesyslog.LogMsg{}
			if err := m.parseHostname(br, lm); (err != nil) != tt.wantErr {
				t.Errorf("parseHostname() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !bytes.Equal(lm.Host, []byte(tt.want)) {
				t.Errorf("parseHostname() wrong = expected: %s, got: %s", tt.want, lm.Hostname())
			}
		})
	}
}

// TestRFC5424Msg_parseAppName tests the parseAppName method of the msg parser
func TestRFC5424Msg_parseAppName(t *testing.T) {
	tests := []struct {
		name    string
		msg     string
		want    string
		wantErr bool
	}{
		{`test app`, `test-app `, `test-app`, false},
		{`empty`, ` `, ``, false},
		{`NILVALUE`, `- `, ``, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := strings.NewReader(tt.msg)
			br := bufio.NewReader(sr)
			m := &msg{}
			lm := &parsesyslog.LogMsg{}
			if err := m.parseAppName(br, lm); (err != nil) != tt.wantErr {
				t.Errorf("parseHostname() error = %v, wantErr %v", err, tt.wantErr)
			}
			if lm.AppName != tt.want {
				t.Errorf("parseHostname() wrong = expected: %s, got: %s", tt.want, lm.AppName)
			}
		})
	}
}

// TestRFC5424Msg_parseMsgID tests the parseMsgID method of the msg parser
func TestRFC5424Msg_parseMsgID(t *testing.T) {
	tests := []struct {
		name    string
		msg     string
		want    string
		wantErr bool
	}{
		{`testID`, `testID `, `testID`, false},
		{`empty`, ` `, ``, false},
		{`NILVALUE`, `- `, ``, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := strings.NewReader(tt.msg)
			br := bufio.NewReader(sr)
			m := &msg{}
			lm := &parsesyslog.LogMsg{}
			if err := m.parseMsgID(br, lm); (err != nil) != tt.wantErr {
				t.Errorf("parseHostname() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !bytes.Equal(lm.MsgID, []byte(tt.want)) {
				t.Errorf("parseHostname() wrong = expected: %s, got: %s", tt.want, lm.MsgID)
			}
		})
	}
}

// TestRFC5424Msg_parseProcID tests the parseProcID method of the msg parser
func TestRFC5424Msg_parseProcID(t *testing.T) {
	tests := []struct {
		name    string
		msg     string
		want    string
		wantErr bool
	}{
		{`testID`, `testID `, `testID`, false},
		{`empty`, ` `, ``, false},
		{`NILVALUE`, `- `, ``, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := strings.NewReader(tt.msg)
			br := bufio.NewReader(sr)
			m := &msg{}
			lm := &parsesyslog.LogMsg{}
			if err := m.parseProcID(br, lm); (err != nil) != tt.wantErr {
				t.Errorf("parseHostname() error = %v, wantErr %v", err, tt.wantErr)
			}
			if lm.ProcID != tt.want {
				t.Errorf("parseHostname() wrong = expected: %s, got: %s", tt.want, lm.ProcID)
			}
		})
	}
}

// TestRFC5424Msg_parseStructuredData tests the parseStructuredData method of the msg parser
func TestRFC5424Msg_parseStructuredData(t *testing.T) {
	tests := []struct {
		name           string
		msg            string
		wantName       []string
		wantElemCount  int
		wantParamCount int
		wantElemID     []string
		wantErr        bool
	}{
		{
			`foo@1234 with 1 element`, `[foo@1234 Revision="1.2.3.4"] `,
			[]string{`foo@1234`},
			1, 1,
			[]string{"Revision"},
			false,
		},
		{
			`foo@1234 with 3 elements`, `[foo@1234 Revision="1.2 3.4" intu="4" foo="bar"] `,
			[]string{`foo@1234`},
			1, 3,
			[]string{"Revision", "intu", "foo"},
			false,
		},
		{
			`foo@1234 and bar@1234`, `[foo@1234 Revision="1.2.3.4"][bar@1234 Revision="1.2.3.4"] `,
			[]string{`foo@1234`, `bar@1234`},
			2, 1,
			[]string{"Revision"},
			false,
		},
		{
			`NILVALUE`, `- `,
			[]string{``},
			0, 0,
			[]string{},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := strings.NewReader(tt.msg)
			br := bufio.NewReader(sr)
			m := &msg{}
			lm := &parsesyslog.LogMsg{}
			if err := m.parseStructuredData(br, lm); (err != nil) != tt.wantErr {
				t.Errorf("parseStructuredData() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(lm.StructuredData) != tt.wantElemCount {
				t.Errorf("parseStructuredData() element count = expected: %d, got: %d",
					tt.wantElemCount, len(lm.StructuredData))
				return
			}
			if len(lm.StructuredData) == 0 {
				return
			}
			pn := false
			for _, en := range tt.wantName {
				for _, e := range lm.StructuredData {
					if en == e.ID {
						pn = true
					}
				}
			}
			if !pn {
				t.Error("parseStructuredData() element names = not all element names found")
			}
			for e := 0; e < tt.wantElemCount; e++ {
				if len(lm.StructuredData[e].Param) != tt.wantParamCount {
					t.Errorf("parseStructuredData() param count = expected: %d, got: %d",
						tt.wantParamCount, len(lm.StructuredData[e].Param))
				}
				pf := false
				for _, ei := range tt.wantElemID {
					for _, p := range lm.StructuredData[e].Param {
						if p.Name == ei {
							pf = true
						}
					}
				}
				if !pf {
					t.Error("parseStructuredData() param names = not all parameters found")
				}
			}
		})
	}
}

// BenchmarkRFC5424Msg_ParseReader benchmarks the ParseReader method of the msg type
func BenchmarkRFC5424Msg_ParseReader(b *testing.B) {
	b.ReportAllocs()
	sr := strings.NewReader(`107 <7>1 2016-02-28T09:57:10.804642398-05:00 myhostname someapp - - [foo@1234 Revision="1.2.3.4"] Hello, World!`)
	br := bufio.NewReader(sr)
	var lm parsesyslog.LogMsg
	var err error

	p, err := parsesyslog.New(Type)
	if err != nil {
		b.Errorf("failed to create new RFC5424 parser")
		return
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lm, err = p.ParseReader(br)
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

// BenchmarkParseStringRFC5424 benchmarks the ParseReader method of the RFC5424Msg type
func BenchmarkParseStringRFC5424(b *testing.B) {
	b.ReportAllocs()
	msg := `107 <7>1 2016-02-28T09:57:10.804642398-05:00 myhostname someapp - - [foo@1234 Revision="1.2.3.4"] Hello, World!`
	var lm parsesyslog.LogMsg
	var err error

	p, err := parsesyslog.New(Type)
	if err != nil {
		b.Errorf("failed to create new RFC5424 parser")
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
