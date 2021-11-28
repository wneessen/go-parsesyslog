# go-parsesyslog

`go-parsesyslog` implements a Go library to parse syslog message

## Supported formats

`go-parsesyslog` fully support the following syslog formats:

### BSD syslog format (RFC3164)

`go-parsesyslog` fully implements the [RFC3164](https://datatracker.ietf.org/doc/html/rfc3164) format including
timestamp parsing and optional tags.

**Please note**: the RFC is not providing any message length definition and explicity states that there
is "[no ending delimiter to this part](https://tools.ietf.org/search/rfc3164#section-4.1.3)"
for this reason we are using the newline (`\n` (ASCII: 10)) as delimiter. This will therefore truncate messages that
have a newline in it.

Available fields in the `LogMsg`:

* `AppName`: this represents the `TAG` part of `TAG[pid]:` format (if given in the message) that is often used for the
  name off the application or process logging
* `ProcID`: this represents the `pid` part of `TAG[pid]:` format (if given in the message) that is often used for the
  process ID
* `HostName`: this represents the hostname part of the RFC3164 message
* `Priority`: The `Priority` part of the message
* `Facility`: The facility calculated from the `Priority` part of the message
* `Severity`: The severity calculated from the `Priority` part of the message
* `Timestamp`: The parsed timestamp of the RFC3164 message as `time.Time` representation
* `Message`: The message part of the log message as `bytes.Buffer`
* `MsgLength`: The length of the `Message` (not including any header part)
* `Type`: This will be always set to `RFC3164`

### IETF-syslog 
`go-parsesyslog` is also fully ([RFC5424](https://datatracker.ietf.org/doc/html/rfc5424)) compliant. All available 
fields are parsed and represented accordingly in the `LogMsg` fields. Also the RFC5424 mandates a maximum length
of 2048 bytes for a log message, `go-parsesyslog` does only obey the message length given in the header of the 
message.

Available fields in the `LogMsg`:
* `Priority`: this represents the [PRI](https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.1) field of the header
* `ProtoVersion`: this represents the [VERSION](https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.2) field of the header
* `Timestamp`: this represents the [TIMESTAMP](https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.3) field of the header
* `Hostname`: this represents the [HOSTNAME](https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.4) field of the header
* `AppName`: this represents the [APP-NAME](https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.5) field of the header
* `ProcID`: this represents the [PROCID](https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.6) field of the header
* `MsgID`: this represents the [MSGID](https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.7) field of the header
* `StructuredData` this represents fully parsed structured data as described in
  the [STRUCTURED-DATA](https://datatracker.ietf.org/doc/html/rfc5424#section-6.3) section of the RFC
* `HasBOM`: is set to `true` if the log message starts with a BOM
* `Facility`: The facility calculated from the `Priority` part of the message
* `Severity`: The severity calculated from the `Priority` part of the message
* `Message`: The message part of the log message as `bytes.Buffer`
* `MsgLength`: The length of the `Message` (not including any header part)
* `Type`: This will be always set to `RFC5424`

## Usage

`go-parsesyslog` implements an `Interface` for various syslog formats, which makes it easy to extend your own log
parser. As long as the `Parser` interface is satisfied, `go-parsesyslog` will be able to work.

The interface looks as following:

```go
type Parser interface {
parseReader(io.Reader) (LogMsg, error)
}
```

### Parsing logs

As you can see, the `ParseReader()` method expects an `io.Reader` interface as argument. This allows you to easily parse
your logs from any kind of source (STDIN, a file, a network socket...)

#### Parsing RFC3164

This example code show how to parse a RFC5424 conformant message:

```go
package main

import (
	"fmt"
	"github.com/wneessen/go-syslog"
)

func main() {
	msg := "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8\n"
	p := parsesyslog.NewRFC3164Parser()
	lm, err := parsesyslog.ParseString(p, msg)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Log message: %+v", lm)
}
```

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

An example implementation can be found in [cmd/stdin-parser](cmd/stdin-parser)

```shell
$ $ echo -ne '197 <165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"][foo@1234 foo="bar" blubb="bluh"] \xEF\xBB\xBFAn application event log entry...' | go run github.com/wneessen/go-syslog/cmd/stdin-parser
```

This command will output:
```
Log message details:
+ Log format:         RFC5424
+ Header:
  - Priority:         165 (Facility: LOCAL4 / Severity: NOTICE)
  - Protocol Version: 1
  - Hostname:         mymachine.example.com
  - AppName:          evntslog
  - ProcID:
  - MsgID:            ID47
  - Timestamp (UTC):  2003-10-11 22:14:15.003 +0000 UTC
+ Structured Data:
  - ID:               exampleSDID@32473
    + Param 0:
      - Name:         iut
      - Value:        3
    + Param 1:
      - Name:         eventSource
      - Value:        Application
    + Param 2:
      - Name:         eventID
      - Value:        1011
  - ID:               foo@1234
    + Param 0:
      - Name:         foo
      - Value:        bar
    + Param 1:
      - Name:         blubb
      - Value:        bluh
+ Message has BOM:    true
+ Message Length:     25
+ Message:            An application event l

Log parsed in 18.745µs
```