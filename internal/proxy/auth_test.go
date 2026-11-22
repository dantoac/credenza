// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/base64"
	"testing"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestParseAndRewrite(t *testing.T) {
	cases := []struct {
		in, token, want string
		ok              bool
	}{
		{"token fbt_A", "fbt_A", "token REAL", true},
		{"Bearer sk-ant-oat01-B", "sk-ant-oat01-B", "Bearer REAL", true},
		{"bearer fbt_C", "fbt_C", "bearer REAL", true},
		{"Basic " + b64("x-access-token:fbt_D"), "fbt_D", "Basic " + b64("x-access-token:REAL"), true},
		{"Basic " + b64(":fbt_E"), "", "", false}, // empty user: GitHub rejects it (R: git item 4)
		{"Basic " + b64("fbt_F"), "", "", false},  // no colon
		{"Basic !!!", "", "", false},
		{"Digest x", "", "", false},
		{"token", "", "", false},
		{"token a b", "", "", false},
		// Cases beyond the plan list.
		{"TOKEN fbt_G", "fbt_G", "TOKEN REAL", true},
		{"basic " + b64("u:fbt_H"), "fbt_H", "basic " + b64("u:REAL"), true},
		{"Basic " + b64("u:a:b"), "a:b", "Basic " + b64("u:REAL"), true},                   // RFC 7617: split at the first colon
		{"Basic " + b64("x-access-token:"), "", "", false},                                 // empty password
		{"Basic " + b64("u:a b"), "", "", false},                                           // whitespace in the password
		{"Basic " + b64("u\r\n:fbt_I"), "", "", false},                                     // control bytes in the user
		{"Basic " + b64("x access:fbt_S"), "fbt_S", "Basic " + b64("x access:REAL"), true}, // RFC 7617 allows a space in the user
		{"Basic dTpm\r\nYnRfSw==", "", "", false},                                          // base64 decoding skips CR and LF
		{"Basic dTpmYnRfSx==", "", "", false},                                              // non-zero padding bits: Strict
		{"Basic " + b64("u\x7f:fbt_T"), "", "", false},                                     // DEL in the user
		{"Basic " + base64.RawStdEncoding.EncodeToString([]byte("u:fbt_J")), "", "", false},
		{"Basic", "", "", false},
		{"Basic ", "", "", false},
		{"Basic " + b64("u:fbt_K") + " x", "", "", false},
		{"token ", "", "", false},
		{"token  fbt_L", "", "", false},
		{" token fbt_M", "", "", false},
		{"token fbt_N ", "", "", false},
		{"token\tfbt_O", "", "", false},
		{"token fbt_P\x7f", "", "", false},
		{"Bearer fbt_Q\r\nX-Evil: 1", "", "", false},
		{"Bearerx fbt_R", "", "", false},
		{"", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			c, ok := ParseAuthorization(tc.in)
			if ok != tc.ok {
				t.Fatalf("ParseAuthorization(%q) ok = %v, want %v", tc.in, ok, tc.ok)
			}
			if !ok {
				if c != (Cred{}) {
					t.Fatalf("ParseAuthorization(%q) = %+v on failure, want zero Cred", tc.in, c)
				}
				return
			}
			if c.Token != tc.token {
				t.Fatalf("Token = %q, want %q", c.Token, tc.token)
			}
			if got := c.WithSecret("REAL"); got != tc.want {
				t.Fatalf("WithSecret = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseKeepsSchemeAndUser(t *testing.T) {
	cases := []struct {
		in   string
		want Cred
	}{
		{"token fbt_A", Cred{Scheme: "token", Token: "fbt_A"}},
		{"BeArEr fbt_B", Cred{Scheme: "BeArEr", Token: "fbt_B"}},
		{"Basic " + b64("x-access-token:fbt_C"), Cred{Scheme: "Basic", User: "x-access-token", Token: "fbt_C"}},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			c, ok := ParseAuthorization(tc.in)
			if !ok || c != tc.want {
				t.Fatalf("ParseAuthorization(%q) = %+v, %v, want %+v, true", tc.in, c, ok, tc.want)
			}
		})
	}
}
