package parsesyslog

import "testing"

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
}
