// SPDX-FileCopyrightText: 2021-2023 Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package parsesyslog

import (
	"bytes"
	"time"
)

const (
	// RFC3164 represents the legacy BSD-syslog message type.
	RFC3164 LogMsgType = "RFC3164"
	// RFC5424 represents the modern IETF-syslog message type.
	RFC5424 LogMsgType = "RFC5424"
)

// LogMsg represents a Syslog message containing metadata and parsed log content based on RFC specifications.
type LogMsg struct {
	App            []byte
	Facility       Facility
	HasBOM         bool
	Host           []byte
	Message        bytes.Buffer
	MsgLength      int
	MsgID          []byte
	Priority       Priority
	PID            []byte
	ProtoVersion   ProtoVersion
	Severity       Severity
	StructuredData []StructuredDataElement
	Timestamp      time.Time
	Type           LogMsgType
}

// LogMsgType represents the type of a Syslog message, typically defined by RFC specifications such as
// RFC3164 or RFC5424.
type LogMsgType string

// ProtoVersion represents the version of the Syslog protocol as defined in RFC5424.
type ProtoVersion int

// StructuredDataElement represents a structured data element in an RFC5424 Syslog message.
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.3.1
type StructuredDataElement struct {
	ID    []byte
	Param []StructuredDataParam
}

// StructuredDataParam represents a key-value pair within a Structured Data element of an RFC5424 Syslog message.
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.3.3
type StructuredDataParam struct {
	Name  []byte
	Value []byte
}

func (l *LogMsg) Hostname() string {
	return string(l.Host)
}

func (l *LogMsg) AppName() string {
	return string(l.App)
}

func (l *LogMsg) ProcID() string {
	return string(l.PID)
}
