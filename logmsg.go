package syslog

import "time"

// LogMsgTypes
const (
	RFC3164 LogMsgType = "RFC3164" // RFC3164: legacy BSD-syslog
	RFC5424 LogMsgType = "RFC5424" // RFC5424: modern IETF-syslog
)

// LogMsg represents a parsed syslog message
type LogMsg struct {
	Facility     Facility
	Hostname     string
	Message      []byte
	MsgLength    int
	Priority     Priority
	ProtoVersion ProtoVersion
	Severity     Severity
	Timestamp    time.Time
	Type         LogMsgType
}

// LogMsgType represents the type of message
type LogMsgType string

// ProtoVersion represents the version of message
type ProtoVersion int
