// SPDX-FileCopyrightText: 2021-2023 Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package parsesyslog

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseUintBytes(t *testing.T) {
	t.Run("parse one digit number", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			raw := []byte(fmt.Sprintf("%d", i))
			val, err := ParseUintBytes(raw)
			if err != nil {
				t.Errorf("failed to parse uint bytes: %s", err)
			}
			if val != i {
				t.Errorf("expected value to be: %d, got: %d", i, val)
			}
		}
	})
	t.Run("parse big number", func(t *testing.T) {
		want := 1234567890
		raw := []byte(fmt.Sprintf("%d", want))
		val, err := ParseUintBytes(raw)
		if err != nil {
			t.Errorf("failed to parse uint bytes: %s", err)
		}
		if val != want {
			t.Errorf("expected value to be: %d, got: %d", want, val)
		}
	})
	t.Run("no number should fail", func(t *testing.T) {
		if _, err := ParseUintBytes([]byte("")); err == nil {
			t.Errorf("parsing empty string should have failed, but it didn't")
		}
	})
	t.Run("non-number should fail", func(t *testing.T) {
		if _, err := ParseUintBytes([]byte("a")); err == nil {
			t.Errorf("parsing a non-number string should have failed, but it didn't")
		}
	})
}

func TestLogMsg_AppName(t *testing.T) {
	want := "app_name"
	logMessage := LogMsg{
		App: []byte(want),
	}
	if !strings.EqualFold(logMessage.AppName(), want) {
		t.Errorf("expected app name to be: %s, got: %s", want, logMessage.AppName())
	}
}

func TestLogMsg_Hostname(t *testing.T) {
	want := "hostname"
	logMessage := LogMsg{
		Host: []byte(want),
	}
	if !strings.EqualFold(logMessage.Hostname(), want) {
		t.Errorf("expected hostname to be: %s, got: %s", want, logMessage.Hostname())
	}
}

func TestLogMsg_ProcID(t *testing.T) {
	want := "proc_id"
	logMessage := LogMsg{
		PID: []byte(want),
	}
	if !strings.EqualFold(logMessage.ProcID(), want) {
		t.Errorf("expected proc id to be: %s, got: %s", want, logMessage.ProcID())
	}
}

// TestFacilityFromPrio tests the FacilityFromPrio method
func TestFacilityFromPrio(t *testing.T) {
	tests := []struct {
		name string
		prio Priority
		want Facility
	}{
		{"Kern/Notice", Kern | Notice, 0},
		{"User/Notice", User | Notice, 1},
		{"Mail/Notice", Mail | Notice, 2},
		{"Daemon/Notice", Daemon | Notice, 3},
		{"Auth/Notice", Auth | Notice, 4},
		{"Syslog/Notice", Syslog | Notice, 5},
		{"LPR/Notice", LPR | Notice, 6},
		{"News/Notice", News | Notice, 7},
		{"UUCP/Notice", UUCP | Notice, 8},
		{"Cron/Notice", Cron | Notice, 9},
		{"AuthPriv/Notice", AuthPriv | Notice, 10},
		{"FTP/Notice", FTP | Notice, 11},
		{"NTP/Notice", NTP | Notice, 12},
		{"Security/Notice", Security | Notice, 13},
		{"Console/Notice", Console | Notice, 14},
		{"SolarisCron/Notice", SolarisCron | Notice, 15},
		{"Local0/Notice", Local0 | Notice, 16},
		{"Local1/Notice", Local1 | Notice, 17},
		{"Local2/Notice", Local2 | Notice, 18},
		{"Local3/Notice", Local3 | Notice, 19},
		{"Local4/Notice", Local4 | Notice, 20},
		{"Local5/Notice", Local5 | Notice, 21},
		{"Local6/Notice", Local6 | Notice, 22},
		{"Local7/Notice", Local7 | Notice, 23},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FacilityFromPrio(tt.prio); got != tt.want {
				t.Errorf("FacilityFromPrio() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSeverityFromPrio tests the SeverityFromPrio method
//
//nolint:staticcheck
func TestSeverityFromPrio(t *testing.T) {
	tests := []struct {
		name string
		prio Priority
		want Severity
	}{
		{"Mail/Emergency", Mail | Emergency, 0},
		{"Mail/Alert", Mail | Alert, 1},
		{"Mail/Crit", Mail | Crit, 2},
		{"Mail/Error", Mail | Error, 3},
		{"Mail/Warning", Mail | Warning, 4},
		{"Mail/Notice", Mail | Notice, 5},
		{"Mail/Info", Mail | Info, 6},
		{"Mail/Debug", Mail | Debug, 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SeverityFromPrio(tt.prio); got != tt.want {
				t.Errorf("SeverityFromPrio() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestFacilityStringFromPrio tests the FacilityStringFromPrio method
func TestFacilityStringFromPrio(t *testing.T) {
	tests := []struct {
		name string
		prio Priority
		want string
	}{
		{"Kern/Notice", Kern | Notice, "KERN"},
		{"User/Notice", User | Notice, "USER"},
		{"Mail/Notice", Mail | Notice, "MAIL"},
		{"Daemon/Notice", Daemon | Notice, "DAEMON"},
		{"Auth/Notice", Auth | Notice, "AUTH"},
		{"Syslog/Notice", Syslog | Notice, "SYSLOG"},
		{"LPR/Notice", LPR | Notice, "LPR"},
		{"News/Notice", News | Notice, "NEWS"},
		{"UUCP/Notice", UUCP | Notice, "UUCP"},
		{"Cron/Notice", Cron | Notice, "CRON"},
		{"AuthPriv/Notice", AuthPriv | Notice, "AUTHPRIV"},
		{"FTP/Notice", FTP | Notice, "FTP"},
		{"NTP/Notice", NTP | Notice, "NTP"},
		{"Security/Notice", Security | Notice, "SECURITY"},
		{"Console/Notice", Console | Notice, "CONSOLE"},
		{"SolarisCron/Notice", SolarisCron | Notice, "SOLARISCRON"},
		{"Local0/Notice", Local0 | Notice, "LOCAL0"},
		{"Local1/Notice", Local1 | Notice, "LOCAL1"},
		{"Local2/Notice", Local2 | Notice, "LOCAL2"},
		{"Local3/Notice", Local3 | Notice, "LOCAL3"},
		{"Local4/Notice", Local4 | Notice, "LOCAL4"},
		{"Local5/Notice", Local5 | Notice, "LOCAL5"},
		{"Local6/Notice", Local6 | Notice, "LOCAL6"},
		{"Local7/Notice", Local7 | Notice, "LOCAL7"},
		{"Unknown", 194 | Notice, "UNKNOWN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FacilityStringFromPrio(tt.prio); got != tt.want {
				t.Errorf("FacilityStringFromPrio() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSeverityStringFromPrio tests the SeverityStringFromPrio method
//
//nolint:staticcheck
func TestSeverityStringFromPrio(t *testing.T) {
	tests := []struct {
		name string
		prio Priority
		want string
	}{
		{"Mail/Emergency", Mail | Emergency, "EMERGENCY"},
		{"Mail/Alert", Mail | Alert, "ALERT"},
		{"Mail/Crit", Mail | Crit, "CRIT"},
		{"Mail/Error", Mail | Error, "ERROR"},
		{"Mail/Warning", Mail | Warning, "WARNING"},
		{"Mail/Notice", Mail | Notice, "NOTICE"},
		{"Mail/Info", Mail | Info, "INFO"},
		{"Mail/Debug", Mail | Debug, "DEBUG"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SeverityStringFromPrio(tt.prio); got != tt.want {
				t.Errorf("FacilityStringFromPrio() = %v, want %v", got, tt.want)
			}
		})
	}
	t.Run("Unknown severity", func(t *testing.T) {
		val := Severity(8)
		if got := val.String(); got != "UNKNOWN" {
			t.Errorf("FacilityStringFromPrio() = %s, want %s", got, "UNKNOWN")
		}
	})
}

func TestNew(t *testing.T) {
	t.Run("new parser from a registered type", func(t *testing.T) {
		pType := ParserType("example")
		Register(pType, func() (Parser, error) {
			return nil, nil
		})
		_, err := New(pType)
		if err != nil {
			t.Errorf("failed to create new parser: %s", err)
		}
	})
	t.Run("new parser from an unregistered type", func(t *testing.T) {
		pType := ParserType("non-existing")
		_, err := New(pType)
		if err == nil {
			t.Errorf("expected error to be returned, but it didn't")
		}
	})
	t.Run("new parser with double registered type", func(t *testing.T) {
		pType := ParserType("example")
		Register(pType, func() (Parser, error) {
			return nil, nil
		})
		Register(pType, func() (Parser, error) {
			return nil, nil
		})
		_, err := New(pType)
		if err != nil {
			t.Errorf("failed to create new parser: %s", err)
		}
	})
}
