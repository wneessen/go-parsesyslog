package syslog

// SeverityMask is the bitmask representing the Severity in the Priority
const SeverityMask = 0x07

// FacilityMask is the bitmask representing the Facility in the Priority
const FacilityMask = 0xf8

// Severity represents the serverity part of the Syslog PRI header
type Severity int

// Facility represents the facility part of the Syslog PRI header
type Facility int

// Priority represents the Syslog PRI header
type Priority int

// Severities
const (
	Emergency Priority = iota // System is unusable
	Alert                     // Action must be taken immediately
	Crit                      // Critical conditions
	Error                     // Error conditions
	Warning                   // Warning conditions
	Notice                    // Normal but significant conditions
	Info                      // Informational messages
	Debug                     // Debug-level messages
)

// Facilities
const (
	Kern        Priority = iota << 3 // Kernel messages
	User                             // User-level messages
	Mail                             // Mail system
	Daemon                           // System daemons
	Auth                             // Security/authentication messages
	Syslog                           // Messages generated internally by the syslog daemon
	LPR                              // Printer subsystem
	News                             // Network News subsystem
	UUCP                             // UUCP subsystem
	Cron                             // Cron subsystem
	AuthPriv                         // Security/authentication messages
	FTP                              // FTP daemon
	NTP                              // NTP subsystem
	Security                         // Log audit
	Console                          // Log alert
	SolarisCron                      // Scheduling daemon
	Local0                           // Locally used facilities
	Local1                           // Locally used facilities
	Local2                           // Locally used facilities
	Local3                           // Locally used facilities
	Local4                           // Locally used facilities
	Local5                           // Locally used facilities
	Local6                           // Locally used facilities
	Local7                           // Locally used facilities
)

// FacilityFromPrio extracts the Facility from a given Priority
func FacilityFromPrio(p Priority) Facility {
	return Facility(p >> 3)
}

// SeverityFromPrio extracts the Facility from a given Priority
func SeverityFromPrio(p Priority) Severity {
	return Severity(p & SeverityMask)
}

// FacilityStringFromPrio returns a string representation of the Facility of a given Priority
func FacilityStringFromPrio(p Priority) string {
	switch FacilityFromPrio(p) {
	case 0:
		return "KERN"
	case 1:
		return "USER"
	case 2:
		return "MAIL"
	case 3:
		return "DAEMON"
	case 4:
		return "AUTH"
	case 5:
		return "SYSLOG"
	case 6:
		return "LPR"
	case 7:
		return "NEWS"
	case 8:
		return "UUCP"
	case 9:
		return "CRON"
	case 10:
		return "AUTHPRIV"
	case 11:
		return "FTP"
	case 12:
		return "NTP"
	case 13:
		return "SECURITY"
	case 14:
		return "CONSOLE"
	case 15:
		return "SOLARISCRON"
	case 16:
		return "LOCAL0"
	case 17:
		return "LOCAL1"
	case 18:
		return "LOCAL2"
	case 19:
		return "LOCAL3"
	case 20:
		return "LOCAL4"
	case 21:
		return "LOCAL5"
	case 22:
		return "LOCAL6"
	case 23:
		return "LOCAL7"
	default:
		return "UNKNOWN"
	}
}

// SeverityStringFromPrio returns a string representation of the Severity of a given Priority
func SeverityStringFromPrio(p Priority) string {
	switch SeverityFromPrio(p) {
	case 0:
		return "EMERGENCY"
	case 1:
		return "ALERT"
	case 2:
		return "CRIT"
	case 3:
		return "ERROR"
	case 4:
		return "WARNING"
	case 5:
		return "NOTICE"
	case 6:
		return "INFO"
	case 7:
		return "DEBUG"
	default:
		return "UNKNOWN"
	}
}
