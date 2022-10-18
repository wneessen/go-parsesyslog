package main

import (
	"bufio"
	"fmt"
	"os"
	"time"

	"github.com/wneessen/go-parsesyslog"
	"github.com/wneessen/go-parsesyslog/rfc5424"
)

func main() {
	br := bufio.NewReader(os.Stdin)
	p, err := parsesyslog.New(rfc5424.Type)
	if err != nil {
		fmt.Printf("failed to create RFC5424 parser: %s", err)
		os.Exit(1)
	}
	st := time.Now()
	lm, err := p.ParseReader(br)
	if err != nil {
		panic(err)
	}
	et := time.Since(st)
	fmt.Println("Log message details:")
	fmt.Printf("+ Log format:         %s\n", lm.Type)
	fmt.Println("+ Header:")
	fmt.Printf("  - Priority:         %d (Facility: %s / Severity: %s)\n", lm.Priority,
		parsesyslog.FacilityStringFromPrio(lm.Priority), parsesyslog.SeverityStringFromPrio(lm.Priority))
	fmt.Printf("  - Protocol Version: %d\n", lm.ProtoVersion)
	fmt.Printf("  - Hostname:         %s\n", lm.Hostname)
	fmt.Printf("  - AppName:          %s\n", lm.AppName)
	fmt.Printf("  - ProcID:           %s\n", lm.ProcID)
	fmt.Printf("  - MsgID:            %s\n", lm.MsgID)
	fmt.Printf("  - Timestamp (UTC):  %s\n", lm.Timestamp.UTC().String())
	if len(lm.StructuredData) > 0 {
		fmt.Println("+ Structured Data:")
		for _, se := range lm.StructuredData {
			fmt.Printf("  - ID:               %s\n", se.ID)
			pc := 0
			for _, sp := range se.Param {
				fmt.Printf("    + Param %d:               \n", pc)
				fmt.Printf("      - Name:         %s\n", sp.Name)
				fmt.Printf("      - Value:        %s\n", sp.Value)
				pc++
			}
		}
	}
	fmt.Printf("+ Message has BOM:    %t\n", lm.HasBOM)
	fmt.Printf("+ Message Length:     %d\n", lm.MsgLength)
	fmt.Printf("+ Message:            %s\n\n", lm.Message.String())
	fmt.Printf("Log parsed in %s\n", et.String())
}
