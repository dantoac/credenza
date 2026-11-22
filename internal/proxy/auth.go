// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/base64"
	"strings"
)

// Cred is a credential found in one Authorization header value.
type Cred struct {
	Scheme string // as sent: "token", "Bearer" or "Basic" (case kept)
	User   string // Basic only
	Token  string // the candidate temporary token
}

// ParseAuthorization accepts "token T", "Bearer T" (scheme case-insensitive)
// and "Basic base64(user:T)" with a non-empty user; anything else returns false.
// The scheme and the credential are separated by exactly one space, stricter
// than the 1*SP of RFC 9110 section 11.4: gh, git and the Anthropic SDK send
// one, and anything else fails closed. The token holds no whitespace or
// control bytes; the Basic user holds no control bytes (RFC 7617).
func ParseAuthorization(v string) (Cred, bool) {
	scheme, rest, found := strings.Cut(v, " ")
	// Checked before decoding: base64 decoding skips CR and LF.
	if !found || !printable(rest) {
		return Cred{}, false
	}
	switch {
	case strings.EqualFold(scheme, "token"), strings.EqualFold(scheme, "Bearer"):
		return Cred{Scheme: scheme, Token: rest}, true
	case strings.EqualFold(scheme, "Basic"):
		raw, err := base64.StdEncoding.Strict().DecodeString(rest)
		if err != nil {
			return Cred{}, false
		}
		// RFC 7617: the user-id cannot contain a colon, the password can.
		user, token, found := strings.Cut(string(raw), ":")
		if !found || user == "" || hasControl(user) || !printable(token) {
			return Cred{}, false
		}
		return Cred{Scheme: scheme, User: user, Token: token}, true
	}
	return Cred{}, false
}

// WithSecret returns the header value with the token replaced by secret,
// same scheme; Basic keeps User and re-encodes user:secret with base64.StdEncoding.
func (c Cred) WithSecret(secret string) string {
	if strings.EqualFold(c.Scheme, "Basic") {
		return c.Scheme + " " + base64.StdEncoding.EncodeToString([]byte(c.User+":"+secret))
	}
	return c.Scheme + " " + secret
}

// printable reports whether s is non-empty and holds only bytes above space,
// other than DEL.
func printable(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			return false
		}
	}
	return !hasControl(s)
}

// hasControl reports whether s holds a byte below space or DEL.
func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < ' ' || s[i] == 0x7f {
			return true
		}
	}
	return false
}
