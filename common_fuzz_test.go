// SPDX-FileCopyrightText: 2021-2023 Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

//go:build go1.18
// +build go1.18

package parsesyslog

import (
	"testing"
)

// FuzzAtoi performs a fuzzing test on Atoi
func FuzzAtoi(f *testing.F) {
	tests := [][]byte{[]byte("1"), []byte("123"), []byte("255"), []byte("-1"), []byte("A")}
	for _, t := range tests {
		f.Add(t)
	}
	f.Fuzz(func(t *testing.T, ns []byte) {
		_, err := Atoi(ns)
		if err != nil {
			return
		}
	})
}
