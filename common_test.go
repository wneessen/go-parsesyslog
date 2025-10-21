// SPDX-FileCopyrightText: 2021-2023 Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package parsesyslog

import (
	"fmt"
	"testing"
)

func TestParseUintBytes(t *testing.T) {
	t.Run("parse one digit number", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			raw := []byte(fmt.Sprintf("%d", i))
			val, err := ParseUintBytes(raw)
			if err != nil {
				t.Errorf("failed to parse uint bytes: %s", err)
			}
			if val != i {
				t.Errorf("expected value to be: %d, got: %d", i, val)
			}
		}
	})
	t.Run("parse big number", func(t *testing.T) {
		want := 1234567890
		raw := []byte(fmt.Sprintf("%d", want))
		val, err := ParseUintBytes(raw)
		if err != nil {
			t.Errorf("failed to parse uint bytes: %s", err)
		}
		if val != want {
			t.Errorf("expected value to be: %d, got: %d", want, val)
		}
	})
	t.Run("no number should fail", func(t *testing.T) {
		if _, err := ParseUintBytes([]byte("")); err == nil {
			t.Errorf("parsing empty string should have failed, but it didn't")
		}
	})
	t.Run("non-number should fail", func(t *testing.T) {
		if _, err := ParseUintBytes([]byte("a")); err == nil {
			t.Errorf("parsing a non-number string should have failed, but it didn't")
		}
	})
}
