// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: GPL-3.0-or-later

package control

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dantoac/credenza/internal/audit"
	"github.com/dantoac/credenza/internal/policy"
	"github.com/dantoac/credenza/internal/token"
)

// validPolicy is the Task 12 example: example/app has GH_TOKEN
// (github-app) and CLAUDE_CODE_OAUTH_TOKEN (claude-oauth).
const validPolicy = "../policy/testdata/valid.json"

// otherPolicy lists only other/repo, which reuses github-app.
const otherPolicy = `{"version": 1, "projects": {"other/repo": [
  {"env": "GH_TOKEN", "secret": "github-app", "ttl": "1h",
   "allow": [{"host": "api.github.com", "methods": ["GET"], "paths": ["/repos/other/repo/"]}]}]}}`

// emptyGrantsPolicy lists example/app with no grants.
const emptyGrantsPolicy = `{"version": 1, "projects": {"example/app": []}}`

var tokenLine = map[string]*regexp.Regexp{
	"CLAUDE_CODE_OAUTH_TOKEN": regexp.MustCompile(`^CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-[A-Za-z0-9_-]{43}$`),
	"GH_TOKEN":                regexp.MustCompile(`^GH_TOKEN=fbt_[A-Za-z0-9_-]{43}$`),
}

// broker is one Service served on a socket in a short temp directory.
type broker struct {
	dir, sock, adminSock, policyPath, auditPath string
	svc                                         *Service
	log                                         *audit.Log
	secrets                                     *fakeSecrets
}

// fakeSecrets is the secret store behind SetSecret and RemoveSecret.
type fakeSecrets struct {
	mu   sync.Mutex
	m    map[string]string
	fail error // returned by set and remove when not nil
}

func (f *fakeSecrets) has(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.m[name]
	return ok
}

func (f *fakeSecrets) get(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.m[name]
}

func (f *fakeSecrets) set(name, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.m[name] = value
	return nil
}

func (f *fakeSecrets) remove(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	if _, ok := f.m[name]; !ok {
		return fmt.Errorf("secret %s not found", name)
	}
	delete(f.m, name)
	return nil
}

// shortDir returns a directory whose paths fit the Unix socket path
// limit (104 bytes on macOS), which t.TempDir paths can exceed.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "fb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func writePolicy(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	// Chmod after writing so the umask does not hide the bits under test.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// newBroker serves a Service with the valid policy, both secrets in the
// store and a CA that permits every host.
func newBroker(t *testing.T) *broker {
	t.Helper()
	dir := shortDir(t)
	b := &broker{
		dir:        dir,
		sock:       filepath.Join(dir, "run", "broker.sock"),
		adminSock:  filepath.Join(dir, "run", "admin.sock"),
		policyPath: filepath.Join(dir, "policy.json"),
		auditPath:  filepath.Join(dir, "audit.log"),
	}
	writePolicy(t, b.policyPath, readFile(t, validPolicy), 0o600)
	log, err := audit.Open(b.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	b.log = log
	b.secrets = &fakeSecrets{m: map[string]string{"github-app": "ghp_x", "claude-oauth": "sk-x"}}
	b.svc = &Service{
		Policy:       func() (*policy.Policy, error) { return policy.Load(b.policyPath) },
		HasSecret:    b.secrets.has,
		CheckHost:    func(string) error { return nil },
		Tokens:       token.NewRegistry(nil),
		Audit:        log,
		SetSecret:    b.secrets.set,
		RemoveSecret: b.secrets.remove,
	}
	l, err := Listen(b.sock)
	if err != nil {
		t.Fatal(err)
	}
	al, err := Listen(b.adminSock)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 2)
	go func() { done <- Serve(l, b.svc) }()
	go func() { done <- ServeAdmin(al, b.svc) }()
	t.Cleanup(func() {
		l.Close()
		al.Close()
		for range 2 {
			if err := <-done; err != nil {
				t.Errorf("Serve: %v", err)
			}
		}
		log.Close()
	})
	return b
}

// call runs Call and splits stdout into lines.
func (b *broker) call(t *testing.T, args ...string) (int, []string, string) {
	t.Helper()
	var out bytes.Buffer
	code, errLine := Call(b.sock, args, &out)
	var lines []string
	if out.Len() > 0 {
		if !strings.HasSuffix(out.String(), "\n") {
			t.Fatalf("stdout %q does not end in a newline", out.String())
		}
		lines = strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	}
	return code, lines, errLine
}

// mint calls mint and returns the tokens, failing unless it exits 0.
func (b *broker) mint(t *testing.T, task, project string) []string {
	t.Helper()
	code, lines, errLine := b.call(t, "mint", task, project)
	if code != ExitOK {
		t.Fatalf("mint %s %s: exit %d, errLine %q", task, project, code, errLine)
	}
	var toks []string
	for _, l := range lines {
		_, tok, ok := strings.Cut(l, "=")
		if !ok {
			t.Fatalf("mint line %q is not NAME=VALUE", l)
		}
		toks = append(toks, tok)
	}
	return toks
}

func (b *broker) events(t *testing.T) []audit.Event {
	t.Helper()
	var evs []audit.Event
	for _, l := range strings.Split(strings.TrimSpace(string(readFile(t, b.auditPath))), "\n") {
		if l == "" {
			continue
		}
		var e audit.Event
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatalf("audit line %q: %v", l, err)
		}
		evs = append(evs, e)
	}
	return evs
}

func TestMintAndCall(t *testing.T) {
	b := newBroker(t)
	code, lines, errLine := b.call(t, "mint", "T1", "example/app")
	if code != ExitOK || errLine != "" {
		t.Fatalf("exit %d, errLine %q, want 0 and empty", code, errLine)
	}
	if len(lines) != 2 {
		t.Fatalf("stdout lines %q, want 2", lines)
	}
	for i, env := range []string{"CLAUDE_CODE_OAUTH_TOKEN", "GH_TOKEN"} {
		if !tokenLine[env].MatchString(lines[i]) {
			t.Errorf("line %d = %q, want %s", i, lines[i], tokenLine[env])
		}
	}
}

func TestMintTwiceKeepsOldTokens(t *testing.T) {
	b := newBroker(t)
	first := b.mint(t, "T1", "example/app")
	second := b.mint(t, "T1", "example/app")
	for _, tok := range append(first, second...) {
		if _, ok := b.svc.Tokens.Lookup(tok); !ok {
			t.Errorf("token %d chars long no longer valid", len(tok))
		}
	}
	if first[0] == second[0] || first[1] == second[1] {
		t.Error("second mint returned the same tokens")
	}
}

func TestRevoke(t *testing.T) {
	tests := []struct {
		name  string
		mint  bool
		count int
	}{
		{"after mint", true, 2},
		{"unknown task", false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newBroker(t)
			var toks []string
			if tt.mint {
				toks = b.mint(t, "T1", "example/app")
			}
			code, lines, errLine := b.call(t, "revoke", "T1")
			if code != ExitOK || errLine != "" || len(lines) != 0 {
				t.Fatalf("revoke: exit %d, errLine %q, stdout %q; want 0, empty, empty", code, errLine, lines)
			}
			for _, tok := range toks {
				if _, ok := b.svc.Tokens.Lookup(tok); ok {
					t.Error("token still valid after revoke")
				}
			}
			n, err := b.svc.Revoke("T1")
			if err != nil || n != 0 {
				t.Errorf("second Revoke = %d, %v; want 0, nil", n, err)
			}
		})
	}
}

func TestCallExitCodes(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T, b *broker)        // runs before the call
		sock    func(t *testing.T, b *broker) string // nil means b.sock
		args    []string
		code    int
		errLine string // substring
		denied  bool   // the audit log gets one deny line; otherwise no line
	}{
		{name: "no socket file", sock: func(_ *testing.T, b *broker) string { return filepath.Join(b.dir, "none.sock") },
			args: []string{"mint", "T1", "example/app"}, code: ExitLocked, errLine: "broker is locked or not running"},
		{name: "socket file but nobody listening", sock: func(t *testing.T, b *broker) string { return staleSocket(t, b.dir) },
			args: []string{"mint", "T1", "example/app"}, code: ExitLocked, errLine: "broker is locked or not running"},
		{name: "mint without project", args: []string{"mint", "T1"}, code: ExitUsage, errLine: "usage"},
		{name: "task id with a space", args: []string{"mint", "bad id", "example/app"}, code: ExitUsage, errLine: "usage"},
		{name: "project without owner", args: []string{"mint", "T1", "app"}, code: ExitUsage, errLine: "usage"},
		{name: "unknown command", args: []string{"frob"}, code: ExitUsage, errLine: "usage"},
		{name: "no args", args: nil, code: ExitUsage, errLine: "usage"},
		{name: "task id with a newline", args: []string{"revoke", "T1\nrevoke"}, code: ExitUsage, errLine: "usage"},
		{name: "revoke with extra arg", args: []string{"revoke", "T1", "x"}, code: ExitUsage, errLine: "usage"},
		{name: "renew without task", args: []string{"renew"}, code: ExitUsage, errLine: "usage"},
		{name: "renew with extra arg", args: []string{"renew", "T1", "x"}, code: ExitUsage, errLine: "usage: mint <task-id> <project> [<env>...] | renew <task-id> | revoke <task-id>"},
		{name: "renew with a slash in the task id", args: []string{"renew", "a/b"}, code: ExitUsage, errLine: "usage: invalid task id"},
		// The rows below pass Call's framing check, so the server must refuse them.
		{name: "task id with a dollar", args: []string{"mint", "T$1", "example/app"}, code: ExitUsage, errLine: "usage: invalid task id"},
		{name: "task id of 65 bytes on an unlisted project", args: []string{"mint", strings.Repeat("a", 65), "other/repo"}, code: ExitUsage, errLine: "usage: invalid task id"},
		{name: "revoke with a slash in the task id", args: []string{"revoke", "a/b"}, code: ExitUsage, errLine: "usage: invalid task id"},
		{name: "project not in policy", args: []string{"mint", "T1", "other/repo"}, code: ExitDenied, errLine: "policy denies the project", denied: true},
		{name: "project with no grants",
			setup: func(t *testing.T, b *broker) { writePolicy(t, b.policyPath, []byte(emptyGrantsPolicy), 0o600) },
			args:  []string{"mint", "T1", "example/app"}, code: ExitDenied, errLine: "policy denies the project", denied: true},
		{name: "deny audit write fails",
			setup: func(t *testing.T, b *broker) { b.log.Close() },
			args:  []string{"mint", "T1", "other/repo"}, code: ExitErr, errLine: "write audit log"},
		{name: "policy file invalid JSON",
			setup: func(t *testing.T, b *broker) { writePolicy(t, b.policyPath, []byte("{"), 0o600) },
			args:  []string{"mint", "T1", "example/app"}, code: ExitErr, errLine: "policy: "},
		{name: "policy file mode 0666",
			setup: func(t *testing.T, b *broker) { writePolicy(t, b.policyPath, readFile(t, validPolicy), 0o666) },
			args:  []string{"mint", "T1", "example/app"}, code: ExitErr, errLine: "group or world writable"},
		{name: "grant secret not in store",
			setup: func(t *testing.T, b *broker) { b.secrets.remove("claude-oauth") },
			args:  []string{"mint", "T1", "example/app"}, code: ExitErr, errLine: `secret "claude-oauth" not in store`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newBroker(t)
			if tt.setup != nil {
				tt.setup(t, b)
			}
			sock := b.sock
			if tt.sock != nil {
				sock = tt.sock(t, b)
			}
			var out bytes.Buffer
			code, errLine := Call(sock, tt.args, &out)
			if code != tt.code || !strings.Contains(errLine, tt.errLine) {
				t.Errorf("Call(%q) = %d, %q; want %d, containing %q", tt.args, code, errLine, tt.code, tt.errLine)
			}
			if strings.ContainsAny(errLine, "\r\n") {
				t.Errorf("errLine %q is not one line", errLine)
			}
			if out.Len() != 0 {
				t.Errorf("stdout %q, want empty", out.String())
			}
			if n := b.svc.Tokens.Revoke("T1"); n != 0 {
				t.Errorf("registry holds %d tokens of T1, want 0", n)
			}
			evs := b.events(t)
			if tt.denied {
				if len(evs) != 1 || evs[0].Decision != "deny" || evs[0].Reason != "project" {
					t.Errorf("audit events %+v, want one project deny", evs)
				}
			} else if len(evs) != 0 {
				t.Errorf("audit events %+v, want none", evs)
			}
		})
	}
}

// staleSocket leaves a socket file in dir that nobody listens on.
func staleSocket(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "stale.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("stale socket file missing: %v", err)
	}
	return path
}

func TestPolicyReloadedOnMint(t *testing.T) {
	b := newBroker(t)
	toks := b.mint(t, "T1", "example/app")
	writePolicy(t, b.policyPath, []byte(otherPolicy), 0o600)
	if code, _, errLine := b.call(t, "mint", "T1", "example/app"); code != ExitDenied {
		t.Fatalf("mint after reload: exit %d, errLine %q; want 4", code, errLine)
	}
	for _, tok := range toks {
		if _, ok := b.svc.Tokens.Lookup(tok); !ok {
			t.Error("token of the first mint no longer valid")
		}
	}
	if toks := b.mint(t, "T2", "other/repo"); len(toks) != 1 {
		t.Errorf("mint other/repo returned %d tokens, want 1", len(toks))
	}
}

func TestMintAudit(t *testing.T) {
	b := newBroker(t)
	toks := b.mint(t, "T1", "example/app")
	if code, _, _ := b.call(t, "mint", "T1", "other/repo"); code != ExitDenied {
		t.Fatalf("mint other/repo: exit %d, want 4", code)
	}
	if code, _, _ := b.call(t, "revoke", "T1"); code != ExitOK {
		t.Fatalf("revoke: exit %d, want 0", code)
	}
	want := []audit.Event{
		{Event: "mint", Task: "T1", Project: "example/app", Secret: "github-app", Decision: "allow"},
		{Event: "mint", Task: "T1", Project: "example/app", Secret: "claude-oauth", Decision: "allow"},
		{Event: "mint", Task: "T1", Project: "other/repo", Decision: "deny", Reason: "project"},
		{Event: "revoke", Task: "T1", Decision: "allow"},
	}
	got := b.events(t)
	if len(got) != len(want) {
		t.Fatalf("audit has %d events %+v, want %d", len(got), got, len(want))
	}
	for i := range want {
		got[i].Time = want[i].Time
		if got[i] != want[i] {
			t.Errorf("event %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	log := string(readFile(t, b.auditPath))
	for _, tok := range toks {
		if strings.Contains(log, tok) {
			t.Error("audit log contains a minted token")
		}
	}
}

func TestMintAuditFailureKeepsEarlierTokens(t *testing.T) {
	b := newBroker(t)
	toks := b.mint(t, "T1", "example/app")
	if err := b.log.Close(); err != nil {
		t.Fatal(err)
	}
	code, lines, errLine := b.call(t, "mint", "T1", "example/app")
	if code != ExitErr || errLine == "" || len(lines) != 0 {
		t.Fatalf("mint with closed audit: exit %d, errLine %q, stdout %q; want 1, a message, empty", code, errLine, lines)
	}
	for _, tok := range toks {
		if _, ok := b.svc.Tokens.Lookup(tok); !ok {
			t.Error("token of mint #1 no longer valid")
		}
	}
	if n := b.svc.Tokens.Revoke("T1"); n != 2 {
		t.Errorf("registry Revoke(T1) = %d, want 2 (mint #2 must insert nothing)", n)
	}
}

func TestRevokeAuditFailure(t *testing.T) {
	b := newBroker(t)
	toks := b.mint(t, "T1", "example/app")
	if err := b.log.Close(); err != nil {
		t.Fatal(err)
	}
	if code, _, errLine := b.call(t, "revoke", "T1"); code != ExitErr || errLine == "" {
		t.Fatalf("revoke with closed audit: exit %d, errLine %q; want 1 and a message", code, errLine)
	}
	for _, tok := range toks {
		if _, ok := b.svc.Tokens.Lookup(tok); ok {
			t.Error("token still valid after a revoke whose audit write failed")
		}
	}
}

func TestMintHostOutsideCA(t *testing.T) {
	b := newBroker(t)
	b.svc.CheckHost = func(host string) error {
		if host == "api.anthropic.com" {
			return errors.New("CA cannot serve api.anthropic.com")
		}
		return nil
	}
	code, lines, errLine := b.call(t, "mint", "T1", "example/app")
	if code != ExitErr || !strings.Contains(errLine, `host "api.anthropic.com" not permitted by the CA`) {
		t.Fatalf("exit %d, errLine %q; want 1 and the host message", code, errLine)
	}
	if len(lines) != 0 {
		t.Errorf("stdout %q, want empty", lines)
	}
	if n := b.svc.Tokens.Revoke("T1"); n != 0 {
		t.Errorf("registry holds %d tokens, want 0", n)
	}
	for _, e := range b.events(t) {
		if e.Event == "mint" && e.Decision == "allow" {
			t.Errorf("audit has a mint allow line: %+v", e)
		}
	}
}

func TestConcurrentMintRevoke(t *testing.T) {
	b := newBroker(t)
	var wg sync.WaitGroup
	errs := make(chan string, 32)
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			task := fmt.Sprintf("T%d", i)
			var out bytes.Buffer
			if code, errLine := Call(b.sock, []string{"mint", task, "example/app"}, &out); code != ExitOK {
				errs <- fmt.Sprintf("mint %s: exit %d, %q", task, code, errLine)
			}
			if code, errLine := Call(b.sock, []string{"revoke", task}, &out); code != ExitOK {
				errs <- fmt.Sprintf("revoke %s: exit %d, %q", task, code, errLine)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

func TestListenRemovesStaleSocket(t *testing.T) {
	dir := shortDir(t)
	path := filepath.Join(dir, "run", "broker.sock")
	if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("stale socket file missing: %v", err)
	}
	l, err = Listen(path)
	if err != nil {
		t.Fatalf("Listen over a stale socket: %v", err)
	}
	defer l.Close()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial the new socket: %v", err)
	}
	c.Close()
}

func TestListenRefusesLiveServer(t *testing.T) {
	dir := shortDir(t)
	path := filepath.Join(dir, "run", "broker.sock")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l2, err := Listen(path)
	if err == nil {
		l2.Close()
		t.Fatal("second Listen succeeded")
	}
	if !strings.Contains(err.Error(), "another credenza serve is running") {
		t.Errorf("error %q, want it to say another credenza serve is running", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Errorf("live socket removed: %v", err)
	}
}

func TestListenRefuses(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, path string)
		want  string
	}{
		{"regular file at the socket path", func(t *testing.T, path string) {
			if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, "not a socket"},
		{"missing parent directory", func(t *testing.T, path string) {
			if err := os.Remove(filepath.Dir(filepath.Dir(path))); err != nil {
				t.Fatal(err)
			}
		}, "no such file or directory"},
		{"socket directory open to others", func(t *testing.T, path string) {
			if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
		}, "want 0700"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(shortDir(t), "run", "broker.sock")
			tt.setup(t, path)
			l, err := Listen(path)
			if err == nil {
				l.Close()
				t.Fatal("Listen succeeded")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestSocketMode(t *testing.T) {
	dir := shortDir(t)
	path := filepath.Join(dir, "run", "broker.sock")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for _, c := range []struct {
		path string
		want os.FileMode
	}{{path, 0o600}, {filepath.Dir(path), 0o700}} {
		fi, err := os.Lstat(c.path)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != c.want {
			t.Errorf("%s mode %04o, want %04o", c.path, got, c.want)
		}
	}
	fi, _ := os.Lstat(path)
	if fi.Mode()&os.ModeSocket == 0 {
		t.Errorf("%s is not a socket", path)
	}
}

func TestCallBadResponses(t *testing.T) {
	tests := []struct {
		name, resp string
		code       int
		stdout     string
	}{
		{"ok with lines", "ok\nGH_TOKEN=fbt_x\n", ExitOK, "GH_TOKEN=fbt_x\n"},
		{"empty", "", ExitErr, ""},
		{"first line cut", "ok", ExitErr, ""},
		{"token line cut", "ok\nGH_TOKEN=fbt_x\nCLAUDE_CODE_OAUTH_TOKEN=sk-", ExitErr, ""},
		{"unknown kind", "frob x\n", ExitErr, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sock := filepath.Join(shortDir(t), "fake.sock")
			l, err := net.Listen("unix", sock)
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			go func() {
				c, err := l.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				bufio.NewReader(c).ReadString('\n')
				io.WriteString(c, tt.resp)
			}()
			var out bytes.Buffer
			code, errLine := Call(sock, []string{"mint", "T1", "example/app"}, &out)
			if code != tt.code || out.String() != tt.stdout {
				t.Errorf("Call = %d, %q, stdout %q; want %d, stdout %q", code, errLine, out.String(), tt.code, tt.stdout)
			}
			if (code == ExitOK) != (errLine == "") {
				t.Errorf("exit %d with errLine %q", code, errLine)
			}
		})
	}
}

func TestServeWaitsForHandlers(t *testing.T) {
	b := newBroker(t)
	started, release := make(chan struct{}), make(chan struct{})
	load := b.svc.Policy
	b.svc.Policy = func() (*policy.Policy, error) {
		close(started)
		<-release
		return load()
	}
	// A second Serve on its own listener, so the test controls when it ends.
	sock := filepath.Join(b.dir, "run", "second.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- Serve(l, b.svc) }()
	called := make(chan int, 1)
	go func() {
		code, _ := Call(sock, []string{"mint", "T1", "example/app"}, io.Discard)
		called <- code
	}()
	<-started
	l.Close()
	select {
	case err := <-served:
		t.Fatalf("Serve returned %v while a mint was in progress", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-served; err != nil {
		t.Errorf("Serve: %v", err)
	}
	if code := <-called; code != ExitOK {
		t.Errorf("mint in progress when the listener closed: exit %d, want 0", code)
	}
}

// TestMintTokenCap: a mint beyond the registry's cap exits 1 with one
// line and writes no audit allow.
func TestMintTokenCap(t *testing.T) {
	b := newBroker(t)
	p, err := policy.Load(b.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	grants, _ := p.Grants("example/app")
	for i := 0; i < token.MaxLive/len(grants); i++ {
		if _, err := b.svc.Tokens.Mint(fmt.Sprintf("fill-%d", i), "example/app", grants); err != nil {
			t.Fatalf("fill %d: %v", i, err)
		}
	}
	code, lines, errLine := b.call(t, "mint", "T1", "example/app")
	if code != ExitErr || len(lines) != 0 || !strings.Contains(errLine, "token limit reached") || strings.Contains(errLine, "\n") {
		t.Fatalf("mint at the cap: exit %d, stdout %q, errLine %q; want 1, empty, one token limit line", code, lines, errLine)
	}
	if evs := b.events(t); len(evs) != 0 {
		t.Fatalf("audit has %+v, want no event", evs)
	}
	b.svc.Tokens.Revoke("fill-0")
	b.mint(t, "T1", "example/app")
}

func TestRenewVerb(t *testing.T) {
	b := newBroker(t)
	c := &fakeClock{t: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)}
	b.svc.Tokens = token.NewRegistry(c.Now)
	b.svc.MaxSession = 24 * time.Hour
	toks := b.mint(t, "T1", "example/app")
	c.Advance(7 * time.Hour)
	code, lines, errLine := b.call(t, "renew", "T1")
	if code != ExitOK || errLine != "" || len(lines) != 0 {
		t.Fatalf("renew: exit %d, errLine %q, stdout %q; want 0, empty, empty", code, errLine, lines)
	}
	// The policy TTL is 8h: past the first expiry the tokens still work.
	c.Advance(2 * time.Hour)
	for _, tok := range toks {
		if _, ok := b.svc.Tokens.Lookup(tok); !ok {
			t.Error("token not renewed")
		}
	}
	// Past the renewed expiry: nothing left to renew.
	c.Advance(7 * time.Hour)
	if code, _, errLine := b.call(t, "renew", "T1"); code != ExitGone || !strings.Contains(errLine, "no live tokens") {
		t.Fatalf("renew after expiry: exit %d, errLine %q; want 5", code, errLine)
	}
	if code, _, _ := b.call(t, "renew", "T9"); code != ExitGone {
		t.Fatalf("renew of an unknown task: exit %d, want 5", code)
	}
	// Max session: the tokens are revoked.
	b.mint(t, "T2", "example/app")
	b.svc.MaxSession = time.Hour
	c.Advance(time.Hour)
	if code, _, errLine := b.call(t, "renew", "T2"); code != ExitGone || !strings.Contains(errLine, "max session") {
		t.Fatalf("renew past max session: exit %d, errLine %q; want 5", code, errLine)
	}
	if n := b.svc.Tokens.Revoke("T2"); n != 0 {
		t.Fatalf("max session left %d tokens", n)
	}
	want := []audit.Event{
		{Event: "renew", Task: "T1", Project: "example/app", Decision: "allow", Reason: "live=2"},
		{Event: "renew", Task: "T1", Project: "example/app", Decision: "deny", Reason: "gone"},
		{Event: "renew", Task: "T9", Decision: "deny", Reason: "gone"},
		{Event: "renew", Task: "T2", Project: "example/app", Decision: "deny", Reason: "max-session"},
	}
	var got []audit.Event
	for _, e := range b.events(t) {
		if e.Event == "renew" {
			e.Time = time.Time{}
			got = append(got, e)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("renew events %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("event %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestRenewAppliesPolicy: renew re-reads the policy, so a narrowed rule
// reaches a live token without a new mint.
func TestRenewAppliesPolicy(t *testing.T) {
	b := newBroker(t)
	toks := b.mint(t, "T1", "example/app")
	narrow := `{"version": 1, "projects": {"example/app": [
  {"env": "GH_TOKEN", "secret": "github-app", "ttl": "5m",
   "allow": [{"host": "api.github.com", "methods": ["GET"], "paths": ["/repos/example/app/"]}]}]}}`
	writePolicy(t, b.policyPath, []byte(narrow), 0o600)
	if code, _, errLine := b.call(t, "renew", "T1"); code != ExitOK {
		t.Fatalf("renew: exit %d, errLine %q", code, errLine)
	}
	live := 0
	for _, tok := range toks {
		if s, ok := b.svc.Tokens.Lookup(tok); ok {
			live++
			if s.Env != "GH_TOKEN" || len(s.Rules) != 1 || s.Rules[0].Host != "api.github.com" {
				t.Errorf("scope after renew = %+v", s)
			}
		}
	}
	if live != 1 {
		t.Fatalf("%d tokens live after renew, want 1 (CLAUDE_CODE_OAUTH_TOKEN dropped)", live)
	}
	// A broken policy changes nothing.
	writePolicy(t, b.policyPath, []byte("{"), 0o600)
	if code, _, errLine := b.call(t, "renew", "T1"); code != ExitErr || !strings.Contains(errLine, "policy: ") {
		t.Fatalf("renew with a broken policy: exit %d, errLine %q; want 1", code, errLine)
	}
	// A secret missing from the store fails like mint and changes nothing.
	writePolicy(t, b.policyPath, []byte(narrow), 0o600)
	b.svc.HasSecret = func(string) bool { return false }
	if code, _, errLine := b.call(t, "renew", "T1"); code != ExitErr || !strings.Contains(errLine, "not in store") {
		t.Fatalf("renew with a missing secret: exit %d, errLine %q; want 1", code, errLine)
	}
	if n := b.svc.Tokens.Revoke("T1"); n != 1 {
		t.Fatalf("Revoke = %d, want 1", n)
	}
}

func TestRenewProjectRemovedRevokes(t *testing.T) {
	b := newBroker(t)
	toks := b.mint(t, "T1", "example/app")
	writePolicy(t, b.policyPath, []byte(otherPolicy), 0o600)
	code, lines, errLine := b.call(t, "renew", "T1")
	if code != ExitDenied || !strings.Contains(errLine, "policy denies the project") || len(lines) != 0 {
		t.Fatalf("renew: exit %d, errLine %q, stdout %q; want 4", code, errLine, lines)
	}
	for _, tok := range toks {
		if _, ok := b.svc.Tokens.Lookup(tok); ok {
			t.Error("token still valid after the project left the policy")
		}
	}
	evs := b.events(t)
	last := evs[len(evs)-1]
	last.Time = time.Time{}
	if want := (audit.Event{Event: "renew", Task: "T1", Project: "example/app", Decision: "deny", Reason: "project"}); last != want {
		t.Fatalf("last event %+v, want %+v", last, want)
	}
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// TestMintOtherProjectRefused: a task id with live tokens of one project
// cannot mint for another, and the refusal writes no allow line.
func TestMintOtherProjectRefused(t *testing.T) {
	b := newBroker(t)
	writePolicy(t, b.policyPath, []byte(`{"version": 1, "projects": {
  "example/app": [{"env": "GH_TOKEN", "secret": "github-app", "ttl": "1h",
    "allow": [{"host": "api.github.com", "methods": ["GET"], "paths": ["/repos/example/app/"]}]}],
  "other/repo": [{"env": "GH_TOKEN", "secret": "github-app", "ttl": "1h",
    "allow": [{"host": "api.github.com", "methods": ["GET"], "paths": ["/repos/other/repo/"]}]}]}}`), 0o600)
	b.mint(t, "T1", "example/app")
	code, lines, errLine := b.call(t, "mint", "T1", "other/repo")
	if code != ExitErr || !strings.Contains(errLine, "another project") || len(lines) != 0 {
		t.Fatalf("mint for another project: exit %d, errLine %q, stdout %q; want 1", code, errLine, lines)
	}
	allows := 0
	for _, e := range b.events(t) {
		if e.Event == "mint" && e.Decision == "allow" {
			allows++
		}
	}
	if allows != 1 {
		t.Fatalf("%d mint allow lines, want 1 (none for the refused mint)", allows)
	}
}

// adminCall sends one admin request with body and returns the exit code
// and the error line.
func (b *broker) adminCall(t *testing.T, sock string, body string, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code, errLine := CallBody(sock, args, []byte(body), &out)
	if out.Len() != 0 {
		t.Fatalf("%q: stdout %q, want empty", args, out.String())
	}
	if strings.ContainsAny(errLine, "\r\n") {
		t.Fatalf("%q: errLine %q is not one line", args, errLine)
	}
	return code, errLine
}

func TestBrokerSockRejectsAdminVerbs(t *testing.T) {
	b := newBroker(t)
	for _, c := range []struct {
		args []string
		body string
	}{
		{[]string{"secret-set", "github-app"}, "ghp_new\n"},
		{[]string{"secret-set", "github-app", "replace"}, "ghp_new\n"},
		{[]string{"secret-rm", "github-app"}, ""},
		{[]string{"policy-load"}, "{}\n"},
	} {
		code, errLine := b.adminCall(t, b.sock, c.body, c.args...)
		if code != ExitUsage || !strings.Contains(errLine, "mint <task-id>") {
			t.Errorf("broker.sock %q: exit %d, %q; want usage", c.args, code, errLine)
		}
	}
	if got := b.secrets.get("github-app"); got != "ghp_x" || !b.secrets.has("github-app") {
		t.Fatalf("github-app changed to %q", got)
	}
	if evs := b.events(t); len(evs) != 0 {
		t.Fatalf("audit events %+v, want none", evs)
	}
}

func TestAdminSockRejectsSessionVerbs(t *testing.T) {
	b := newBroker(t)
	for _, args := range [][]string{
		{"mint", "T1", "example/app"},
		{"renew", "T1"},
		{"revoke", "T1"},
		{"frob"},
	} {
		code, errLine := b.adminCall(t, b.adminSock, "", args...)
		if code != ExitUsage || !strings.Contains(errLine, "secret-set <name>") {
			t.Errorf("admin.sock %q: exit %d, %q; want admin usage", args, code, errLine)
		}
	}
	if n := b.svc.Tokens.Revoke("T1"); n != 0 {
		t.Fatalf("admin.sock minted %d tokens", n)
	}
	if evs := b.events(t); len(evs) != 0 {
		t.Fatalf("audit events %+v, want none", evs)
	}
}

func TestAdminSecretVerbs(t *testing.T) {
	const value = "ghp_ROTATED_canary_77"
	b := newBroker(t)
	// Without replace, an existing name is refused.
	if code, errLine := b.adminCall(t, b.adminSock, value+"\n", "secret-set", "github-app"); code != ExitErr || !strings.Contains(errLine, "exists") {
		t.Fatalf("set existing: exit %d, %q", code, errLine)
	}
	if code, errLine := b.adminCall(t, b.adminSock, value+"\n", "secret-set", "github-app", "replace"); code != ExitOK {
		t.Fatalf("set replace: exit %d, %q", code, errLine)
	}
	if got := b.secrets.get("github-app"); got != value {
		t.Fatalf("github-app = %q, want the new value", got)
	}
	if code, errLine := b.adminCall(t, b.adminSock, "v1\n", "secret-set", "new-one"); code != ExitOK || b.secrets.get("new-one") != "v1" {
		t.Fatalf("set new: exit %d, %q", code, errLine)
	}
	if code, errLine := b.adminCall(t, b.adminSock, "", "secret-rm", "new-one"); code != ExitOK || b.secrets.has("new-one") {
		t.Fatalf("rm: exit %d, %q", code, errLine)
	}
	if code, errLine := b.adminCall(t, b.adminSock, "", "secret-rm", "new-one"); code != ExitErr || !strings.Contains(errLine, "not found") {
		t.Fatalf("rm missing: exit %d, %q", code, errLine)
	}
	// Usage errors: bad name, bad word, missing or bad value line.
	for _, c := range []struct {
		args []string
		body string
		code int
		msg  string
	}{
		{[]string{"secret-set", "Bad"}, "v\n", ExitUsage, "invalid secret name"},
		{[]string{"secret-set", "x", "force"}, "v\n", ExitUsage, "secret-set <name>"},
		{[]string{"secret-set"}, "v\n", ExitUsage, "secret-set <name>"},
		{[]string{"secret-rm"}, "", ExitUsage, "secret-set <name>"},
		{[]string{"secret-rm", "x", "y"}, "", ExitUsage, "secret-set <name>"},
		{[]string{"secret-set", "x"}, "", ExitUsage, "secret value"},
		{[]string{"secret-set", "x"}, "no newline", ExitUsage, "secret value"},
		{[]string{"secret-set", "x"}, "\n", ExitErr, "secret value is empty"},
		{[]string{"secret-set", "x"}, "a\rb\n", ExitErr, "control character"},
		{[]string{"secret-set", "x"}, " a\n", ExitErr, "space"},
		{[]string{"secret-set", "x"}, "a\xffb\n", ExitErr, "UTF-8"},
		{[]string{"secret-set", "x"}, strings.Repeat("a", MaxSecretValue+1) + "\n", ExitUsage, "secret value"},
	} {
		code, errLine := b.adminCall(t, b.adminSock, c.body, c.args...)
		if code != c.code || !strings.Contains(errLine, c.msg) {
			t.Errorf("%q: exit %d, %q; want %d containing %q", c.args, code, errLine, c.code, c.msg)
		}
		if strings.Contains(errLine, "a\rb") {
			t.Errorf("%q: errLine quotes the value", c.args)
		}
	}
	if b.secrets.has("x") {
		t.Fatal("a refused secret-set stored x")
	}
	// The longest value is accepted.
	long := strings.Repeat("a", MaxSecretValue)
	if code, errLine := b.adminCall(t, b.adminSock, long+"\n", "secret-set", "long"); code != ExitOK || b.secrets.get("long") != long {
		t.Fatalf("set %d bytes: exit %d, %q", MaxSecretValue, code, errLine)
	}
	// A store failure is one error line.
	b.secrets.fail = errors.New("store busy")
	if code, errLine := b.adminCall(t, b.adminSock, "v\n", "secret-set", "y"); code != ExitErr || errLine != "store busy" {
		t.Fatalf("set with failing store: exit %d, %q", code, errLine)
	}
	b.secrets.fail = nil

	evs := b.events(t)
	var got []string
	for _, e := range evs {
		if e.Event != "secret" || e.Decision != "allow" {
			t.Fatalf("audit event %+v", e)
		}
		got = append(got, e.Secret+" "+e.Reason)
	}
	want := []string{"github-app replace", "new-one add", "new-one rm", "long add"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("audit %q, want %q", got, want)
	}
	if strings.Contains(string(readFile(t, b.auditPath)), value) {
		t.Fatal("audit log carries the secret value")
	}
}

func TestAdminSecretAuditFailure(t *testing.T) {
	b := newBroker(t)
	b.log.Close()
	code, errLine := b.adminCall(t, b.adminSock, "v\n", "secret-set", "x")
	if code != ExitErr || !strings.Contains(errLine, "write audit log") {
		t.Fatalf("exit %d, %q", code, errLine)
	}
}

func TestCallBodyFraming(t *testing.T) {
	b := newBroker(t)
	// The body never reaches a session verb's handler as a second request.
	code, errLine := b.adminCall(t, b.sock, "revoke T1\n", "frob")
	if code != ExitUsage {
		t.Fatalf("exit %d, %q", code, errLine)
	}
	if evs := b.events(t); len(evs) != 0 {
		t.Fatalf("audit events %+v, want none", evs)
	}
}

func TestAdminPolicyLoad(t *testing.T) {
	b := newBroker(t)
	var got [][]byte
	var fail error
	var mu sync.Mutex
	b.svc.LoadPolicy = func(body []byte) error {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, bytes.Clone(body))
		return fail
	}
	body := `{"version": 1, "projects": {}}` + "\n"
	if code, errLine := b.adminCall(t, b.adminSock, body, "policy-load"); code != ExitOK || errLine != "" {
		t.Fatalf("policy-load: exit %d, %q", code, errLine)
	}
	if len(got) != 1 || string(got[0]) != body {
		t.Fatalf("LoadPolicy got %q, want %q", got, body)
	}
	// The longest body is passed whole; one byte more is refused before
	// LoadPolicy.
	long := bytes.Repeat([]byte("a"), MaxPolicy)
	if code, errLine := b.adminCall(t, b.adminSock, string(long), "policy-load"); code != ExitOK || !bytes.Equal(got[1], long) {
		t.Fatalf("policy-load of %d bytes: exit %d, %q", MaxPolicy, code, errLine)
	}
	if code, errLine := b.adminCall(t, b.adminSock, string(long)+"a", "policy-load"); code != ExitUsage || !strings.Contains(errLine, "policy") || len(got) != 2 {
		t.Fatalf("policy-load of %d bytes: exit %d, %q, calls %d", MaxPolicy+1, code, errLine, len(got))
	}
	if code, errLine := b.adminCall(t, b.adminSock, body, "policy-load", "x"); code != ExitUsage || !strings.Contains(errLine, "policy-load") || len(got) != 2 {
		t.Fatalf("policy-load x: exit %d, %q", code, errLine)
	}
	mu.Lock()
	fail = fmt.Errorf("%w: secret %q not in store", ErrInvalidPolicy, "nope")
	mu.Unlock()
	if code, errLine := b.adminCall(t, b.adminSock, "{}\n", "policy-load"); code != ExitErr || errLine != `invalid policy: secret "nope" not in store` {
		t.Fatalf("refused policy: exit %d, %q", code, errLine)
	}
	mu.Lock()
	fail = errors.New("write policy: disk full")
	mu.Unlock()
	if code, errLine := b.adminCall(t, b.adminSock, "{}\n", "policy-load"); code != ExitErr || errLine != "write policy: disk full" {
		t.Fatalf("failed write: exit %d, %q", code, errLine)
	}
	var lines []string
	for _, e := range b.events(t) {
		if e.Event != "policy" {
			t.Fatalf("audit event %+v", e)
		}
		lines = append(lines, e.Decision+" "+e.Reason)
	}
	sum := func(s string) string { return fmt.Sprintf("sha256=%x", sha256.Sum256([]byte(s))) }
	want := []string{
		"allow " + sum(body),
		"allow " + sum(string(long)),
		"deny invalid " + sum("{}\n"),
		"deny failed " + sum("{}\n"),
	}
	if strings.Join(lines, "|") != strings.Join(want, "|") {
		t.Fatalf("audit\n%q\nwant\n%q", lines, want)
	}
}

func TestAdminPolicyLoadAuditFailure(t *testing.T) {
	b := newBroker(t)
	called := false
	b.svc.LoadPolicy = func([]byte) error { called = true; return nil }
	b.log.Close()
	code, errLine := b.adminCall(t, b.adminSock, "{}\n", "policy-load")
	if code != ExitErr || !strings.Contains(errLine, "write audit log") || !called {
		t.Fatalf("exit %d, %q, called %v", code, errLine, called)
	}
}

func TestMintNarrowedByEnv(t *testing.T) {
	b := newBroker(t)
	code, lines, errLine := b.call(t, "mint", "T1", "example/app", "GH_TOKEN")
	if code != ExitOK || errLine != "" {
		t.Fatalf("exit %d, errLine %q, want 0 and empty", code, errLine)
	}
	if len(lines) != 1 || !tokenLine["GH_TOKEN"].MatchString(lines[0]) {
		t.Fatalf("stdout lines %q, want one GH_TOKEN line", lines)
	}
	// Renew extends what the mint issued; it never adds the other grant.
	if live, err := b.svc.Renew("T1"); err != nil || live != 1 {
		t.Fatalf("renew: live %d, err %v, want 1 and nil", live, err)
	}
	code, lines, _ = b.call(t, "mint", "T2", "example/app", "GH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN")
	if code != ExitOK || len(lines) != 2 {
		t.Fatalf("mint with both envs: exit %d, %d lines, want 0 and 2", code, len(lines))
	}
	for i, env := range []string{"CLAUDE_CODE_OAUTH_TOKEN", "GH_TOKEN"} {
		if !tokenLine[env].MatchString(lines[i]) {
			t.Errorf("line %d = %q, want %s (policy order)", i, lines[i], tokenLine[env])
		}
	}
	want := []audit.Event{
		{Event: "mint", Task: "T1", Project: "example/app", Secret: "github-app", Decision: "allow"},
		{Event: "renew", Task: "T1", Project: "example/app", Decision: "allow", Reason: "live=1"},
		{Event: "mint", Task: "T2", Project: "example/app", Secret: "github-app", Decision: "allow"},
		{Event: "mint", Task: "T2", Project: "example/app", Secret: "claude-oauth", Decision: "allow"},
	}
	got := b.events(t)
	if len(got) != len(want) {
		t.Fatalf("audit has %d events %+v, want %d", len(got), got, len(want))
	}
	for i := range want {
		got[i].Time = want[i].Time
		if got[i] != want[i] {
			t.Errorf("event %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestMintEnvNotGranted(t *testing.T) {
	b := newBroker(t)
	code, lines, errLine := b.call(t, "mint", "T1", "example/app", "GH_TOKEN", "NPM_TOKEN")
	if code != ExitDenied || len(lines) != 0 {
		t.Fatalf("exit %d, lines %q, want 4 and none", code, lines)
	}
	if errLine != `policy denies the project "example/app": no grant for NPM_TOKEN` {
		t.Fatalf("errLine %q", errLine)
	}
	if _, ok := b.svc.Tokens.Project("T1"); ok {
		t.Fatal("a denied mint left tokens")
	}
	want := audit.Event{Event: "mint", Task: "T1", Project: "example/app", Decision: "deny", Reason: "env"}
	got := b.events(t)
	if len(got) != 1 {
		t.Fatalf("audit %+v, want one deny", got)
	}
	got[0].Time = want.Time
	if got[0] != want {
		t.Fatalf("event %+v, want %+v", got[0], want)
	}
}

func TestMintEnvUsage(t *testing.T) {
	b := newBroker(t)
	for _, args := range [][]string{
		{"mint", "T1", "example/app", "gh_token"},
		{"mint", "T1", "example/app", "GH-TOKEN"},
		{"mint", "T1", "example/app", "GH_TOKEN", "GH_TOKEN"},
		{"mint", "T1", "example/app", "A", "B", "C", "D"},
		{"mint", "T1", "example/app", strings.Repeat("A", 65)},
	} {
		if code, lines, _ := b.call(t, args...); code != ExitUsage || len(lines) != 0 {
			t.Errorf("%q: exit %d, lines %q, want 2 and none", args, code, lines)
		}
	}
	if got := b.events(t); len(got) != 0 {
		t.Fatalf("usage errors wrote audit events %+v", got)
	}
}

func TestMintLongestRequestFits(t *testing.T) {
	b := newBroker(t)
	task := strings.Repeat("t", 64)
	project := strings.Repeat("o", 100) + "/" + strings.Repeat("r", 100)
	env := strings.Repeat("A", 64)
	args := []string{"mint", task, project, env, "B" + env[1:], "C" + env[1:]}
	if n := len(strings.Join(args, " ")) + 1; n >= maxRequest {
		t.Fatalf("longest mint request is %d bytes, maxRequest %d", n, maxRequest)
	}
	// The policy does not list the project: a deny proves the line was read whole.
	if code, _, errLine := b.call(t, args...); code != ExitDenied {
		t.Fatalf("exit %d, errLine %q, want 4", code, errLine)
	}
}
