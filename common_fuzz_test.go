// SPDX-FileCopyrightText: 2022 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MI

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
