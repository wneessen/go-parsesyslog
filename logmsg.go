// SPDX-FileCopyrightText: 2021-2023 Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package parsesyslog

import (
	"bytes"
	"time"
)

// LogMsgTypes
const (
	RFC3164 LogMsgType = "RFC3164" // RFC3164: legacy BSD-syslog
	RFC5424 LogMsgType = "RFC5424" // RFC5424: modern IETF-syslog
)

// LogMsg represents a parsed syslog message
type LogMsg struct {
	AppName  string
	Facility Facility
	HasBOM   bool
	Hostname string
	// Message        []byte
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

// LogMsgType represents the type of message
type LogMsgType string

// ProtoVersion represents the version of message
type ProtoVersion int

// StructuredDataElement represents a structured data elements as defined in
// RFC5424
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.3.1
type StructuredDataElement struct {
	ID    string
	Param []StructuredDataParam
}

// StructuredDataParam represents a structured data param pair as defined in
// RFC5424
// See: https://datatracker.ietf.org/doc/html/rfc5424#section-6.3.3
type StructuredDataParam struct {
	Name  string
	Value string
}
