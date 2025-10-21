// SPDX-FileCopyrightText: 2021-2023 Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package parsesyslog

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"
)

// Test_readBytesUntilSpace tests the ReadBytesUntilSpace helper method
func Test_readBytesUntilSpace(t *testing.T) {
	tests := []struct {
		name    string
		msg     string
		bytes   []byte
		length  int
		wantErr bool
	}{
		{"successfully read 3 bytes", `123 test`, []byte("123"), 4, false},
		{"successfully read 1 bytes", `1 test`, []byte("1"), 2, false},
		{"empty read to EOF", ``, []byte{}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := strings.NewReader(tt.msg)
			br := bufio.NewReader(sr)
			got, got1, err := ReadBytesUntilSpace(br)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadBytesUntilSpace() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !bytes.Equal(got, tt.bytes) {
				t.Errorf("ReadBytesUntilSpace() got = %v, want %v", got, tt.bytes)
			}
			if got1 != tt.length {
				t.Errorf("ReadBytesUntilSpace() got1 = %v, want %v", got1, tt.length)
			}
		})
	}
}

// Benchmark_readBytesUntilSpace benchmarks the ReadBytesUntilSpace helper method
func Benchmark_readBytesUntilSpace(b *testing.B) {
	b.ReportAllocs()
	sr := strings.NewReader("1234 ")
	br := bufio.NewReader(sr)
	var ba []byte
	var l int
	var err error

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ba, l, err = ReadBytesUntilSpace(br)
		if err != nil {
			b.Errorf("failed to read bytes: %s", err)
			break
		}
		_, err := sr.Seek(0, io.SeekStart)
		if err != nil {
			b.Errorf("failed to seek back to start: %s", err)
			break
		}
	}
	_, _ = ba, l
}
