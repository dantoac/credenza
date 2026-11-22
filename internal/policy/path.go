// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"net/url"
	"strings"
)

// checkPolicyPath reports why p is not a usable policy path, or nil.
func checkPolicyPath(p string) error {
	switch {
	case !strings.HasPrefix(p, "/"):
		return errors.New(`must start with "/"`)
	case strings.ContainsAny(p, "?#") || hasUnsafeChar(p):
		return errors.New(`must not contain "?", "#", "%", "\", ";" or control characters`)
	case strings.Contains(p, "//"):
		return errors.New(`must not contain "//"`)
	case hasDotSegment(p):
		return errors.New(`must not contain a "." or ".." segment`)
	}
	return nil
}

// CleanRequestPath returns u.Path and true when it is safe to match
// against policy paths: absolute, no encoded slash or backslash, no empty
// segment and no "." or ".." segment. The decoded path also has no "%"
// (double encoding), "\", ";" (path parameters such as "..;") or control
// character, none of which a policy path can contain. Anything else is
// denied, never normalized, so the path matched is the path forwarded.
func CleanRequestPath(u *url.URL) (string, bool) {
	p := u.Path
	if !strings.HasPrefix(p, "/") || hasUnsafeChar(p) || strings.Contains(p, "//") || hasDotSegment(p) {
		return "", false
	}
	esc := strings.ToLower(u.EscapedPath())
	if strings.Contains(esc, "%2f") || strings.Contains(esc, "%5c") {
		return "", false
	}
	return p, true
}

func hasUnsafeChar(p string) bool {
	return strings.ContainsFunc(p, func(r rune) bool {
		return r == '%' || r == '\\' || r == ';' || r < 0x20 || r == 0x7f
	})
}

func hasDotSegment(p string) bool {
	for seg := range strings.SplitSeq(p, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}
