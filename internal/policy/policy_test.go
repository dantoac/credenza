// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: GPL-3.0-or-later

package policy

import (
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

func readValid(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseValid(t *testing.T) {
	p, err := Parse(readValid(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	grants, ok := p.Grants("example/app")
	if !ok || len(grants) != 2 {
		t.Fatalf("Grants(example/app) = %d grants, %v; want 2, true", len(grants), ok)
	}
	for i, g := range grants {
		if g.TTL != 8*time.Hour {
			t.Errorf("grant %d: TTL = %v, want 8h", i, g.TTL)
		}
		for _, r := range g.Allow {
			if slices.Contains(r.Methods, "PUT") || slices.Contains(r.Methods, "DELETE") {
				t.Errorf("grant %d: rule for %s lists PUT or DELETE: %v", i, r.Host, r.Methods)
			}
		}
	}
	if grants[0].Env != "GH_TOKEN" || grants[0].TokenPrefix != "" {
		t.Errorf("grant 0 = %q prefix %q, want GH_TOKEN with no prefix", grants[0].Env, grants[0].TokenPrefix)
	}
	if grants[1].Env != "CLAUDE_CODE_OAUTH_TOKEN" || grants[1].TokenPrefix != "sk-ant-oat01-" {
		t.Errorf("grant 1 = %q prefix %q, want CLAUDE_CODE_OAUTH_TOKEN with sk-ant-oat01-", grants[1].Env, grants[1].TokenPrefix)
	}
	if _, ok := p.Grants("example/other"); ok {
		t.Error("Grants(example/other) ok = true, want false")
	}
}

// doc returns a one-grant policy for project "o/r" with the given grant
// fields (raw JSON members) replacing the defaults of the same name.
func doc(fields map[string]string) string {
	g := map[string]string{
		"env":    `"GH_TOKEN"`,
		"secret": `"github-app"`,
		"ttl":    `"1h"`,
		"allow":  `[{"host": "api.github.com", "methods": ["GET"], "paths": ["/x/"]}]`,
	}
	for k, v := range fields {
		g[k] = v
	}
	var members []string
	for _, k := range []string{"env", "secret", "ttl", "token_prefix", "allow"} {
		if v, ok := g[k]; ok {
			members = append(members, `"`+k+`": `+v)
		}
	}
	return `{"version": 1, "projects": {"o/r": [{` + strings.Join(members, ", ") + `}]}}`
}

// rule returns a one-rule allow list with the given raw JSON members.
func rule(host, methods, paths string) string {
	return `[{"host": ` + host + `, "methods": ` + methods + `, "paths": ` + paths + `}]`
}

func TestParseRejects(t *testing.T) {
	okHost, okMethods, okPaths := `"api.github.com"`, `["GET"]`, `["/x/"]`
	tests := []struct {
		name, doc, want string
	}{
		{"version 2", `{"version": 2, "projects": {}}`, "version"},
		{"unknown field", `{"version": 1, "hosts": [], "projects": {}}`, `"hosts"`},
		{"project without slash", `{"version": 1, "projects": {"app": []}}`, `projects["app"]`},
		{"duplicate project", `{"version": 1, "projects": {"o/r": [], "o/r": []}}`, "duplicate"},
		{"case-variant key", doc(map[string]string{"allow": `[{"host": "api.github.com", "methods": ["GET"], "paths": ["/x/"], "Paths": ["/"]}]`}), `"Paths"`},
		{"duplicate key", doc(map[string]string{"allow": `[{"host": "api.github.com", "methods": ["GET"], "paths": ["/x/"], "paths": ["/"]}]`}), "duplicate"},
		{"trailing data", `{"version": 1, "projects": {}} {}`, "after top-level value"},
		{"env lowercase", doc(map[string]string{"env": `"gh_token"`}), `projects["o/r"][0].env`},
		{"duplicate env", `{"version": 1, "projects": {"o/r": [` +
			`{"env": "A", "secret": "s", "ttl": "1h", "allow": ` + rule(okHost, okMethods, okPaths) + `},` +
			`{"env": "A", "secret": "t", "ttl": "1h", "allow": ` + rule(okHost, okMethods, okPaths) + `}]}}`,
			`projects["o/r"][1].env`},
		{"secret uppercase", doc(map[string]string{"secret": `"Bad"`}), `projects["o/r"][0].secret`},
		{"ttl zero", doc(map[string]string{"ttl": `"0s"`}), `projects["o/r"][0].ttl: must be > 0 and <= 24h`},
		{"ttl 25h", doc(map[string]string{"ttl": `"25h"`}), `projects["o/r"][0].ttl: must be > 0 and <= 24h`},
		{"ttl negative", doc(map[string]string{"ttl": `"-1h"`}), `projects["o/r"][0].ttl`},
		{"ttl abc", doc(map[string]string{"ttl": `"abc"`}), `projects["o/r"][0].ttl`},
		{"token_prefix space", doc(map[string]string{"token_prefix": `"a b"`}), `projects["o/r"][0].token_prefix`},
		{"token_prefix too long", doc(map[string]string{"token_prefix": `"` + strings.Repeat("a", 33) + `"`}), `projects["o/r"][0].token_prefix`},
		{"empty allow", doc(map[string]string{"allow": `[]`}), `projects["o/r"][0].allow`},
		{"host uppercase", doc(map[string]string{"allow": rule(`"API.github.com"`, okMethods, okPaths)}), `projects["o/r"][0].allow[0].host`},
		{"host with port", doc(map[string]string{"allow": rule(`"api.github.com:443"`, okMethods, okPaths)}), `allow[0].host`},
		{"host without dot", doc(map[string]string{"allow": rule(`"localhost"`, okMethods, okPaths)}), `allow[0].host`},
		{"host IPv4 literal", doc(map[string]string{"allow": rule(`"140.82.112.6"`, okMethods, okPaths)}), `allow[0].host`},
		{"method CONNECT", doc(map[string]string{"allow": rule(okHost, `["GET", "CONNECT"]`, okPaths)}), `projects["o/r"][0].allow[0].methods[1]`},
		{"method lowercase", doc(map[string]string{"allow": rule(okHost, `["get"]`, okPaths)}), `allow[0].methods[0]`},
		{"empty methods", doc(map[string]string{"allow": rule(okHost, `[]`, okPaths)}), `allow[0].methods`},
		{"empty paths", doc(map[string]string{"allow": rule(okHost, okMethods, `[]`)}), `allow[0].paths`},
		{"path relative", doc(map[string]string{"allow": rule(okHost, okMethods, `["repos/x"]`)}), `projects["o/r"][0].allow[0].paths[0]`},
		{"path dotdot", doc(map[string]string{"allow": rule(okHost, okMethods, `["/ok/", "/a/../b"]`)}), `allow[0].paths[1]`},
		{"path dot", doc(map[string]string{"allow": rule(okHost, okMethods, `["/a/./b"]`)}), `allow[0].paths[0]`},
		{"path trailing dotdot", doc(map[string]string{"allow": rule(okHost, okMethods, `["/a/.."]`)}), `allow[0].paths[0]`},
		{"path double slash", doc(map[string]string{"allow": rule(okHost, okMethods, `["/a//b"]`)}), `allow[0].paths[0]`},
		{"path query", doc(map[string]string{"allow": rule(okHost, okMethods, `["/a?b"]`)}), `allow[0].paths[0]`},
		{"path fragment", doc(map[string]string{"allow": rule(okHost, okMethods, `["/a#b"]`)}), `allow[0].paths[0]`},
		{"path percent", doc(map[string]string{"allow": rule(okHost, okMethods, `["/a%2Fb"]`)}), `allow[0].paths[0]`},
		{"path backslash", doc(map[string]string{"allow": rule(okHost, okMethods, `["/a\\b"]`)}), `allow[0].paths[0]`},
		{"path semicolon", doc(map[string]string{"allow": rule(okHost, okMethods, `["/a;b"]`)}), `allow[0].paths[0]`},
		{"path control", doc(map[string]string{"allow": rule(okHost, okMethods, `["/a\u0000b"]`)}), `allow[0].paths[0]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Parse([]byte(tt.doc))
			if err == nil {
				t.Fatalf("Parse succeeded (%+v), want error containing %q", p, tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err, tt.want)
			}
			if !strings.HasPrefix(err.Error(), "policy: ") {
				t.Errorf("error %q lacks the policy: prefix", err)
			}
		})
	}
}

func TestParseAcceptsBoundaries(t *testing.T) {
	tests := []struct {
		name string
		doc  string
	}{
		{"ttl 24h", doc(map[string]string{"ttl": `"24h"`})},
		{"ttl 1ns", doc(map[string]string{"ttl": `"1ns"`})},
		{"token_prefix 32", doc(map[string]string{"token_prefix": `"` + strings.Repeat("a", 32) + `"`})},
		{"env 64", doc(map[string]string{"env": `"_` + strings.Repeat("A", 63) + `"`})},
		{"root prefix path", doc(map[string]string{"allow": rule(`"api.github.com"`, `["GET"]`, `["/"]`)})},
		{"all methods", doc(map[string]string{"allow": rule(`"a.b"`, `["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]`, `["/x"]`)})},
		{"no projects", `{"version": 1, "projects": {}}`},
		{"project without grants", `{"version": 1, "projects": {"o/r": []}}`}, // mint denies it (Task 9)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse([]byte(tt.doc)); err != nil {
				t.Errorf("Parse: %v", err)
			}
		})
	}
}

func TestRuleAllows(t *testing.T) {
	r := Rule{Host: "api.github.com", Methods: []string{"GET", "POST"}, Paths: []string{"/repos/example/app/", "/repos/example/app", "/graphql"}}
	cases := []struct {
		host, method, path string
		want               bool
	}{
		{"api.github.com", "GET", "/repos/example/app/pulls", true},
		{"api.github.com", "GET", "/repos/example/app", true},
		{"api.github.com", "POST", "/graphql", true},
		{"api.github.com", "GET", "/repos/example/app-evil/pulls", false},
		{"api.github.com", "GET", "/repos/example/appx", false},
		{"api.github.com", "GET", "/graphql/x", false},
		{"api.github.com", "DELETE", "/repos/example/app/pulls", false},
		{"github.com", "GET", "/repos/example/app/pulls", false},
	}
	for _, c := range cases {
		if got := r.Allows(c.host, c.method, c.path); got != c.want {
			t.Errorf("Allows(%q, %q, %q) = %v, want %v", c.host, c.method, c.path, got, c.want)
		}
	}
}

func TestCleanRequestPath(t *testing.T) {
	tests := []struct {
		raw  string
		want bool
	}{
		{"/a/b", true},
		{"/a/b/", true},
		{"/a/b?x=..", true},
		{"/a/../b", false},
		{"/a/%2e%2e/b", false},
		{"/a/%2E%2E", false},
		{"/a%2Fb", false},
		{"/a%2fb", false},
		{"/a%5cb", false},
		{"/a%5Cb", false},
		{"/a//b", false},
		{"/./a", false},
		{"/a/.", false},
		{"/a/..;/b", false},
		{"/a/%252e%252e/b", false},
		{"/a/%252F/b", false},
		{"/a/..%00/b", false},
		{"/a/%7F", false},
		{"/a/b%20c", true},
		{"", false},
	}
	for _, tt := range tests {
		u, err := url.Parse("https://h" + tt.raw)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", tt.raw, err)
		}
		got, ok := CleanRequestPath(u)
		if ok != tt.want {
			t.Errorf("CleanRequestPath(%q) ok = %v, want %v", tt.raw, ok, tt.want)
		}
		if ok && got != u.Path {
			t.Errorf("CleanRequestPath(%q) = %q, want %q", tt.raw, got, u.Path)
		}
	}
	// Build the URL directly so the decoded path holds a raw backslash.
	if _, ok := CleanRequestPath(&url.URL{Path: `/a\b`}); ok {
		t.Error(`CleanRequestPath(/a\b) ok = true, want false`)
	}
}

func writePolicy(t *testing.T, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, readValid(t), 0o600); err != nil {
		t.Fatal(err)
	}
	// Chmod after writing, so the umask does not mask the bits under test.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadPermissions(t *testing.T) {
	tests := []struct {
		mode os.FileMode
		want string // "" means success
	}{
		{0o644, ""},
		{0o600, ""},
		{0o664, "group or world writable"},
		{0o646, "group or world writable"},
	}
	for _, tt := range tests {
		p, err := Load(writePolicy(t, tt.mode))
		if tt.want == "" {
			if err != nil {
				t.Errorf("mode %o: Load: %v", tt.mode, err)
			} else if _, ok := p.Grants("example/app"); !ok {
				t.Errorf("mode %o: loaded policy has no example/app", tt.mode)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("mode %o: Load error = %v, want %q", tt.mode, err, tt.want)
		}
	}
}

func TestLoadRejects(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(filepath.Join(dir, "missing.json")); err == nil || !strings.HasPrefix(err.Error(), "policy: ") {
		t.Errorf("missing file: Load error = %v, want policy: prefix", err)
	}
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Errorf("directory: Load error = %v, want regular file error", err)
	}
	fifo := filepath.Join(dir, "fifo.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := Load(fifo)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Errorf("FIFO: Load error = %v, want regular file error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("FIFO: Load blocked")
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"version": 2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil || !strings.Contains(err.Error(), "version") {
		t.Errorf("version 2: Load error = %v, want version error", err)
	}
}

func TestHosts(t *testing.T) {
	p, err := Parse(readValid(t))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"api.anthropic.com", "api.github.com", "github.com"}
	if got := p.Hosts(); !slices.Equal(got, want) {
		t.Errorf("Hosts() = %v, want %v", got, want)
	}
}

func TestValidProject(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"example/app", true},
		{"a.b_c-d/E.F_9", true},
		{strings.Repeat("a", 100) + "/" + strings.Repeat("b", 100), true},
		{strings.Repeat("a", 101) + "/b", false},
		{"a/" + strings.Repeat("b", 101), false},
		{"app", false},
		{"/app", false},
		{"example/", false},
		{"a/b/c", false},
		{"a b/c", false},
		{"a/b\n", false},
	}
	for _, tt := range tests {
		if got := ValidProject(tt.s); got != tt.want {
			t.Errorf("ValidProject(%q) = %v, want %v", tt.s, got, tt.want)
		}
	}
}

func TestValidHost(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"api.github.com", true},
		{"github.com", true},
		{"a-b.c9.io", true},
		{"API.github.com", false},
		{"api.github.com:443", false},
		{"localhost", false},
		{"140.82.112.6", false},
		{"127.1", false},
		{"1.2.3", false},
		{"a.b1", true},
		{"::1", false},
		{"[::1]", false},
		{"github.com.", false},
		{".github.com", false},
		{"a..b", false},
		{"-a.com", false},
		{"a-.com", false},
		{"a_b.com", false},
		{"*.github.com", false},
		{strings.Repeat("a", 64) + ".com", false},
		{strings.Repeat("a", 63) + ".com", true},
		{strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("a", 61), true},  // 253 bytes
		{strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("a", 62), false}, // 254 bytes
		{"", false},
	}
	for _, tt := range tests {
		if got := ValidHost(tt.s); got != tt.want {
			t.Errorf("ValidHost(%q) = %v, want %v", tt.s, got, tt.want)
		}
	}
}
