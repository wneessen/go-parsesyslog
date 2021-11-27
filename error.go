package parsesyslog

import "errors"

var (
	ErrWrongFormat         = errors.New("log message does not conform the logging format")
	ErrInvalidPrio         = errors.New("PRI header not a valid priority string")
	ErrInvalidProtoVersion = errors.New("protocol version string invalid")
	ErrInvalidTimestamp    = errors.New("timestamp does not conform the logging format")
	ErrWrongSDFormat       = errors.New("structured data does not conform the format")
	ErrPrematureEOF        = errors.New("log message is shorter than the provided length")
)
