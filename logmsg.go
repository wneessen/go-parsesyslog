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
	AppName        string
	Facility       Facility
	HasBOM         bool
	Hostname       string
	Message        bytes.Buffer
	MsgLength      int
	MsgID          string
	Priority       Priority
	ProcID         string
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
	ID    string
	Param []StructuredDataParam
}

// StructuredDataParam represents a key-value pair within a Structured Data element of an RFC5424 Syslog message.
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.3.3
type StructuredDataParam struct {
	Name  string
	Value string
}
