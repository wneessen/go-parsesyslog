# go-parsesyslog

`go-parsesyslog` implements a Go library to parse syslog message

## Supported formats
`go-parsesyslog` fully support the following syslog formats:

* BSD-syslog ([RFC3164](https://datatracker.ietf.org/doc/html/rfc3164)) // Currently WIP
* IETF-syslog ([RFC5424](https://datatracker.ietf.org/doc/html/rfc5424))

## Usage

`go-parsesyslog` implements an `Interface` for various syslog formats, which makes it easy to extend your own
log parser. As long as the `Parser` interface is satisfied, `go-parsesyslog` will be able to work.

The interface looks as following:

```go
type Parser interface {
	parseReader(io.Reader) (LogMsg, error)
}
```

### Parsing logs
As you can see, the `ParseReader()` method expects an `io.Reader` interface as argument. This allows you
to easily parse your logs from any kind of source (STDIN, a file, a network socket...)

#### Parsing RFC5424

This example code show how to parse a RFC5424 conformant message:

```go
package main

import (
	"fmt"
	"github.com/wneessen/go-syslog"
)

func main() {
	msg := `197 <165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"][foo@1234 foo="bar" blubb="bluh"] \xEF\xBB\xBFAn application event log entry..."`
	p := parsesyslog.NewRFC5424Parser()
	lm, err := parsesyslog.ParseString(p, msg)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Log message: %+v", lm)
}
```