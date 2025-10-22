// SPDX-FileCopyrightText: 2021-2023 Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/wneessen/go-parsesyslog"
	"github.com/wneessen/go-parsesyslog/rfc5424"
)

func main() {
	log, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Printf("failed to read from stdin: %s", err)
		os.Exit(1)
	}
	br := bufio.NewReaderSize(strings.NewReader(string(log)), len(log))
	p, err := parsesyslog.New(rfc5424.Type)
	if err != nil {
		fmt.Printf("failed to create RFC5424 parser: %s", err)
		os.Exit(1)
	}
	st := time.Now()
	lm, err := p.ParseReader(br)
	et := time.Since(st)
	if err != nil {
		panic(err)
	}
	fmt.Println("Log message details:")
	fmt.Printf("+ Log format:         %s\n", lm.Type)
	fmt.Println("+ Header:")
	fmt.Printf("  - Priority:         %d (Facility: %s / Severity: %s)\n", lm.Priority,
		parsesyslog.FacilityStringFromPrio(lm.Priority), parsesyslog.SeverityStringFromPrio(lm.Priority))
	fmt.Printf("  - Protocol Version: %d\n", lm.ProtoVersion)
	fmt.Printf("  - Hostname:         %s\n", lm.Host)
	fmt.Printf("  - AppName:          %s\n", lm.App)
	fmt.Printf("  - ProcID:           %s\n", lm.PID)
	fmt.Printf("  - MsgID:            %s\n", lm.MsgID)
	fmt.Printf("  - Timestamp (UTC):  %s\n", lm.Timestamp.UTC().String())
	if len(lm.StructuredData) > 0 {
		fmt.Println("+ Structured Data:")
		for _, se := range lm.StructuredData {
			fmt.Printf("  - ID:               %s\n", se.ID)
			pc := 0
			for _, sp := range se.Param {
				fmt.Printf("    + Param %d:               \n", pc)
				fmt.Printf("      - Key:         %s\n", sp.Key)
				fmt.Printf("      - Val:        %s\n", sp.Val)
				pc++
			}
		}
	}
	fmt.Printf("+ Message has BOM:    %t\n", lm.HasBOM)
	fmt.Printf("+ Message Length:     %d\n", lm.MsgLength)
	fmt.Printf("+ Message:            %s\n\n", lm.Message.String())
	fmt.Printf("Log parsed in %s\n", et.String())
}
