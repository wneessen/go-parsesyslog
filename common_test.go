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
			if string(got) != string(tt.bytes) {
				t.Errorf("ReadBytesUntilSpace() got = %v, want %v", got, tt.bytes)
			}
			if got1 != tt.length {
				t.Errorf("ReadBytesUntilSpace() got1 = %v, want %v", got1, tt.length)
			}
		})
	}
}

// Test_readBytesUntilSpaceOrNilValue tests the ReadBytesUntilSpaceOrNilValue helper method
func Test_readBytesUntilSpaceOrNilValue(t *testing.T) {
	tests := []struct {
		name    string
		msg     string
		bytes   []byte
		length  int
		wantErr bool
	}{
		{"test1", `123-test - blubb`, []byte("123-test"), 9, false},
		{"timestamp", `2016-02-28T09:57:10.804642398-05:00 - - `,
			[]byte("2016-02-28T09:57:10.804642398-05:00"), 36, false},
		{"NILVAL", ` - foo bar`, []byte{}, 1, false},
		{"empty", ``, []byte{}, 0, true},
	}
	var bb bytes.Buffer
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := strings.NewReader(tt.msg)
			br := bufio.NewReader(sr)
			got1, err := ReadBytesUntilSpaceOrNilValue(br, &bb)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadBytesUntilSpaceOrNilValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if bb.String() != string(tt.bytes) {
				t.Errorf("ReadBytesUntilSpaceOrNilValue() got = %s, want %s", bb.String(), string(tt.bytes))
			}
			if got1 != tt.length {
				t.Errorf("ReadBytesUntilSpaceOrNilValue() got1 = %d, want %d", got1, tt.length)
			}
		})
	}
}

// Test_readMsgLength tests the ReadMsgLength method
func Test_readMsgLength(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int
		wantErr bool
	}{
		{"input 123", `123 <12>1 Test`, 123, false},
		{"input 12345", `12345 <12>1 Test`, 12345, false},
		{"input 1234567890", `1234567890 <12>1 Test`, 1234567890, false},
		{"empty", ``, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := strings.NewReader(tt.input)
			br := bufio.NewReader(sr)
			got, err := ReadMsgLength(br)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadMsgLength() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ReadMsgLength() got = %v, want %v", got, tt.want)
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

// Benchmark_readMsgLength benchmarks the ReadMsgLength helper method
func Benchmark_readMsgLength(b *testing.B) {
	b.ReportAllocs()
	sr := strings.NewReader(`123 <13>1 test`)
	br := bufio.NewReader(sr)
	var ml int
	var err error

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ml, err = ReadMsgLength(br)
		if err != nil {
			b.Errorf("failed to read bytes: %s", err)
			break
		}
		_, err := sr.Seek(0, io.SeekStart)
		if err != nil {
			b.Errorf("failed to seek back to start: %s", err)
			break
		}
		br.Reset(sr)
	}
	_ = ml
}
