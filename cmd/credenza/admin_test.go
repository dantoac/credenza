// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dantoac/credenza/internal/store"
)

func TestMain(m *testing.M) {
	store.DefaultIterations = store.MinIterations
	// Test audit logs cannot carry chattr +a; tests of the warning set
	// their own fileFlags.
	fileFlags = func(string) (uint32, error) { return fsAppendFL, nil }
	os.Exit(m.Run())
}

const (
	pass    = "correct horse battery"
	newPass = "a brand new passphrase"
	canary  = "ghp_CANARY_VALUE_42"
)

type fakeIO struct {
	env
	out, errb *bytes.Buffer
	prompts   []string
}

// fakeEnv returns an env whose readSecret pops answers in order.
func fakeEnv(answers ...string) *fakeIO {
	f := &fakeIO{out: new(bytes.Buffer), errb: new(bytes.Buffer)}
	f.env = env{
		stdin:  strings.NewReader(""),
		stdout: f.out,
		stderr: f.errb,
		getenv: func(string) string { return "" },
		now:    time.Now,
		readSecret: func(ctx context.Context, prompt string) (string, error) {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			f.prompts = append(f.prompts, prompt)
			if len(answers) == 0 {
				return "", errors.New("no more input")
			}
			a := answers[0]
			answers = answers[1:]
			return a, nil
		},
	}
	return f
}

func (f *fakeIO) run(t *testing.T, args ...string) int {
	t.Helper()
	return run(context.Background(), args, f.env)
}

// credenza runs one command with answers and fails the test on a code other than want.
func credenza(t *testing.T, want int, answers []string, args ...string) *fakeIO {
	t.Helper()
	f := fakeEnv(answers...)
	if got := f.run(t, args...); got != want {
		t.Fatalf("%v: exit %d, want %d; stderr %q", args, got, want, f.errb)
	}
	return f
}

func initStore(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	credenza(t, 0, []string{pass, pass}, "init", "-dir", dir)
	return dir
}

func storeBytes(t *testing.T, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "store.enc"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func assertOneLine(t *testing.T, s string) {
	t.Helper()
	if strings.Count(s, "\n") != 1 || !strings.HasSuffix(s, "\n") || len(s) < 2 {
		t.Fatalf("stderr %q is not one line", s)
	}
}

func TestInit(t *testing.T) {
	cases := []struct {
		name    string
		answers []string
		want    int
		errText string
	}{
		{"ok", []string{pass, pass}, 0, "credenza: store created at "},
		{"short", []string{"short", "short"}, 1, "at least 12"},
		{"mismatch", []string{pass, "different one here"}, 1, "do not match"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "store.enc")
			f := credenza(t, tc.want, tc.answers, "init", "-dir", dir)
			if !strings.Contains(f.errb.String(), tc.errText) {
				t.Fatalf("stderr %q, want %q", f.errb, tc.errText)
			}
			assertOneLine(t, f.errb.String())
			if tc.want != 0 {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("store.enc exists after a failed init: %v", err)
				}
				return
			}
			fi, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o600 {
				t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
			}
			d, err := store.Load(path, pass)
			if err != nil {
				t.Fatal(err)
			}
			if len(d.Secrets) != 0 || d.CA != nil {
				t.Fatalf("new store not empty: %d secrets, CA %v", len(d.Secrets), d.CA != nil)
			}
		})
	}
	t.Run("exists", func(t *testing.T) {
		dir := initStore(t)
		before := storeBytes(t, dir)
		f := credenza(t, 1, []string{pass, pass}, "init", "-dir", dir)
		if !strings.Contains(f.errb.String(), "already exists") {
			t.Fatalf("stderr %q", f.errb)
		}
		if len(f.prompts) != 0 {
			t.Fatalf("prompted %v before refusing", f.prompts)
		}
		if !bytes.Equal(before, storeBytes(t, dir)) {
			t.Fatal("store.enc changed")
		}
	})
}

func TestSecretAddListRm(t *testing.T) {
	dir := initStore(t)
	steps := []struct {
		answers []string
		args    []string
		want    int
		out     string
		errText string
	}{
		{[]string{pass, canary}, []string{"secret", "add", "-dir", dir, "github-app"}, 0, "", "credenza: secret github-app saved; used at next serve start"},
		{[]string{pass}, []string{"secret", "list", "-dir", dir}, 0, "github-app\n", ""},
		{[]string{pass, canary}, []string{"secret", "add", "-dir", dir, "github-app"}, 1, "", "exists"},
		{[]string{pass, canary}, []string{"secret", "add", "-dir", dir, "-replace", "github-app"}, 0, "", "saved"},
		{[]string{pass, "sk-other"}, []string{"secret", "add", "-dir", dir, "claude-oauth"}, 0, "", "saved"},
		{[]string{pass}, []string{"secret", "list", "-dir", dir}, 0, "claude-oauth\ngithub-app\n", ""},
		{[]string{pass}, []string{"secret", "rm", "-dir", dir, "claude-oauth"}, 0, "", "credenza: secret claude-oauth removed; used at next serve start"},
		{[]string{pass}, []string{"secret", "rm", "-dir", dir, "github-app"}, 0, "", "removed"},
		{[]string{pass}, []string{"secret", "list", "-dir", dir}, 0, "", ""},
		{[]string{pass}, []string{"secret", "rm", "-dir", dir, "github-app"}, 1, "", "not found"},
	}
	for i, s := range steps {
		f := credenza(t, s.want, s.answers, s.args...)
		if f.out.String() != s.out {
			t.Fatalf("step %d %v: stdout %q, want %q", i, s.args, f.out, s.out)
		}
		if !strings.Contains(f.errb.String(), s.errText) {
			t.Fatalf("step %d %v: stderr %q, want %q", i, s.args, f.errb, s.errText)
		}
		if strings.Contains(f.out.String()+f.errb.String(), canary) {
			t.Fatalf("step %d %v: secret value in output", i, s.args)
		}
	}
}

func TestSecretAddReplaceKeepsValue(t *testing.T) {
	dir := initStore(t)
	credenza(t, 0, []string{pass, "first-value"}, "secret", "add", "-dir", dir, "github-app")
	credenza(t, 0, []string{pass, "second-value"}, "secret", "add", "-dir", dir, "-replace", "github-app")
	d, err := store.Load(filepath.Join(dir, "store.enc"), pass)
	if err != nil {
		t.Fatal(err)
	}
	if d.Secrets["github-app"] != "second-value" {
		t.Fatal("replace did not store the new value")
	}
}

func TestSecretBadName(t *testing.T) {
	dir := initStore(t)
	for _, args := range [][]string{
		{"secret", "add", "-dir", dir, "Bad Name"},
		{"secret", "rm", "-dir", dir, "Bad Name"},
	} {
		f := credenza(t, 2, []string{pass, canary}, args...)
		if len(f.prompts) != 0 {
			t.Fatalf("%v: prompted %v", args, f.prompts)
		}
		assertOneLine(t, f.errb.String())
		if strings.Contains(f.errb.String(), "Bad Name") {
			t.Fatalf("%v: invalid name quoted in stderr %q", args, f.errb)
		}
	}
}

func TestSecretAddRejectsValue(t *testing.T) {
	dir := initStore(t)
	before := storeBytes(t, dir)
	for _, v := range []string{"", "ghp_a\nb", "ghp_a\rb", "ghp_a\x00b", "ghp_a\tb", "ghp_a\x1bb", "ghp_a\x7fb", " ghp_a", "ghp_a ", "ghp_a\xffb"} {
		f := credenza(t, 1, []string{pass, v}, "secret", "add", "-dir", dir, "github-app")
		assertOneLine(t, f.errb.String())
		if v != "" && strings.Contains(f.errb.String(), "ghp_a") {
			t.Fatalf("value %q echoed in stderr %q", v, f.errb)
		}
		if !bytes.Equal(before, storeBytes(t, dir)) {
			t.Fatalf("value %q: store.enc changed", v)
		}
	}
}

func TestSecretMissingStore(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{
		{"secret", "list", "-dir", dir},
		{"secret", "add", "-dir", dir, "github-app"},
		{"ca-cert", "-dir", dir},
		{"passwd", "-dir", dir},
	} {
		f := credenza(t, 1, []string{pass, canary}, args...)
		if !strings.Contains(f.errb.String(), "credenza init") || len(f.prompts) != 0 {
			t.Fatalf("%v: stderr %q, prompts %v", args, f.errb, f.prompts)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("dir not empty: %v", entries)
	}
}

func parseCert(t *testing.T, out string) *x509.Certificate {
	t.Helper()
	b, rest := pem.Decode([]byte(out))
	if b == nil || b.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatalf("stdout is not exactly one CERTIFICATE block: %q", out)
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCAInitAndCert(t *testing.T) {
	dir := initStore(t)
	f := credenza(t, 0, []string{pass}, "ca", "init", "-dir", dir, "-domains", "github.com,anthropic.com")
	if !strings.Contains(f.errb.String(), "credenza: CA created; export it with credenza ca-cert and rebuild every image") {
		t.Fatalf("stderr %q", f.errb)
	}
	first := credenza(t, 0, []string{pass}, "ca-cert", "-dir", dir).out.String()
	c := parseCert(t, first)
	if !c.IsCA {
		t.Fatal("not a CA")
	}
	if c.Subject.CommonName != "credenza CA" {
		t.Fatalf("CN %q, want the default \"credenza CA\"", c.Subject.CommonName)
	}
	if want := []string{"github.com", "anthropic.com"}; !slices.Equal(c.PermittedDNSDomains, want) {
		t.Fatalf("PermittedDNSDomains %v, want %v", c.PermittedDNSDomains, want)
	}

	f = credenza(t, 1, []string{pass}, "ca", "init", "-dir", dir, "-domains", "github.com")
	if !strings.Contains(f.errb.String(), "exists") {
		t.Fatalf("stderr %q", f.errb)
	}
	credenza(t, 0, []string{pass}, "ca", "init", "-dir", dir, "-force", "-name", "Home Lab CA", "-domains", "github.com")
	second := credenza(t, 0, []string{pass}, "ca-cert", "-dir", dir).out.String()
	if second == first {
		t.Fatal("-force kept the old certificate")
	}
	if cn := parseCert(t, second).Subject.CommonName; cn != "Home Lab CA" {
		t.Fatalf("CN %q, want -name \"Home Lab CA\"", cn)
	}
	if got := parseCert(t, second).PermittedDNSDomains; !slices.Equal(got, []string{"github.com"}) {
		t.Fatalf("PermittedDNSDomains %v", got)
	}
}

func TestCAInitRequiresScope(t *testing.T) {
	dir := initStore(t)
	cases := []struct {
		args    []string
		want    int
		errText string
	}{
		{[]string{}, 2, "-domains or -unconstrained"},
		{[]string{"-domains", ""}, 2, ""},
		{[]string{"-domains", "github.com", "-unconstrained"}, 2, ""},
		{[]string{"-domains", "Bad Host"}, 2, "Bad Host"},
		{[]string{"-domains", "github.com,"}, 2, ""},
		{[]string{"-domains", "github.com,github.com"}, 2, "duplicate"},
		{[]string{"-domains", "github.com:443"}, 2, ""},
		{[]string{"-domains", "github.com", "extra"}, 2, ""},
		{[]string{"-name", "", "-unconstrained"}, 2, "CA name is empty"},
		{[]string{"-name", " CA", "-unconstrained"}, 2, "space"},
		{[]string{"-name", "a\tb", "-unconstrained"}, 2, "control character"},
		{[]string{"-name", strings.Repeat("x", 65), "-unconstrained"}, 2, "longer than 64"},
		{[]string{"-unconstrained"}, 0, "CA created"},
	}
	for _, tc := range cases {
		args := append([]string{"ca", "init", "-dir", dir}, tc.args...)
		f := credenza(t, tc.want, []string{pass}, args...)
		if !strings.Contains(f.errb.String(), tc.errText) {
			t.Fatalf("%v: stderr %q, want %q", tc.args, f.errb, tc.errText)
		}
		if tc.want == 2 {
			assertOneLine(t, f.errb.String())
			if len(f.prompts) != 0 {
				t.Fatalf("%v: prompted %v before validating", tc.args, f.prompts)
			}
		}
	}
	c := parseCert(t, credenza(t, 0, []string{pass}, "ca-cert", "-dir", dir).out.String())
	if len(c.PermittedDNSDomains) != 0 {
		t.Fatalf("unconstrained CA has PermittedDNSDomains %v", c.PermittedDNSDomains)
	}
}

func TestInterruptedPrompt(t *testing.T) {
	cases := []struct {
		name    string
		answers []string // given before the interrupted read
		// At the interrupted read, "ctx" cancels and returns ctx.Err(), "wrapped"
		// returns a wrapped context.Canceled, and "late" cancels but still
		// returns an answer (Ctrl-C during the key derivation).
		mode string
		args func(dir string) []string
	}{
		{"secret add at passphrase, ctx done", nil, "ctx", func(d string) []string { return []string{"secret", "add", "-dir", d, "claude-oauth"} }},
		{"secret add at passphrase", nil, "wrapped", func(d string) []string { return []string{"secret", "add", "-dir", d, "claude-oauth"} }},
		{"secret add at value", []string{pass}, "wrapped", func(d string) []string { return []string{"secret", "add", "-dir", d, "claude-oauth"} }},
		{"secret rm", nil, "wrapped", func(d string) []string { return []string{"secret", "rm", "-dir", d, "github-app"} }},
		{"passwd at repeat", []string{pass, newPass}, "wrapped", func(d string) []string { return []string{"passwd", "-dir", d} }},
		{"ca init", nil, "ctx", func(d string) []string { return []string{"ca", "init", "-dir", d, "-unconstrained"} }},
		{"ca init after passphrase", nil, "late", func(d string) []string { return []string{"ca", "init", "-dir", d, "-unconstrained"} }},
		{"secret rm after passphrase", nil, "late", func(d string) []string { return []string{"secret", "rm", "-dir", d, "github-app"} }},
		{"passwd after repeat", []string{pass, newPass}, "late", func(d string) []string { return []string{"passwd", "-dir", d} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := initStore(t)
			credenza(t, 0, []string{pass, canary}, "secret", "add", "-dir", dir, "github-app")
			before := storeBytes(t, dir)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := fakeEnv()
			calls := 0
			f.readSecret = func(ctx context.Context, prompt string) (string, error) {
				calls++
				if calls <= len(tc.answers) {
					return tc.answers[calls-1], nil
				}
				switch tc.mode {
				case "ctx":
					cancel()
					return "", ctx.Err()
				case "late":
					cancel()
					if calls == 1 {
						return pass, nil
					}
					return newPass, nil
				}
				return "", fmt.Errorf("tty: %w", context.Canceled)
			}
			if got := run(ctx, tc.args(dir), f.env); got != 1 {
				t.Fatalf("exit %d, want 1; stderr %q", got, f.errb)
			}
			if f.errb.String() != "credenza: interrupted\n" {
				t.Fatalf("stderr %q", f.errb)
			}
			if calls != len(tc.answers)+1 {
				t.Fatalf("readSecret called %d times, want %d", calls, len(tc.answers)+1)
			}
			if !bytes.Equal(before, storeBytes(t, dir)) {
				t.Fatal("store.enc changed")
			}
		})
	}
	for _, late := range []bool{false, true} {
		t.Run(fmt.Sprintf("init at repeat, late %v", late), func(t *testing.T) {
			dir := t.TempDir()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := fakeEnv()
			calls := 0
			f.readSecret = func(ctx context.Context, prompt string) (string, error) {
				calls++
				if calls == 1 {
					return pass, nil
				}
				if late {
					cancel()
					return pass, nil
				}
				return "", context.Canceled
			}
			if got := run(ctx, []string{"init", "-dir", dir}, f.env); got != 1 || f.errb.String() != "credenza: interrupted\n" {
				t.Fatalf("exit %d, stderr %q", got, f.errb)
			}
			if _, err := os.Stat(filepath.Join(dir, "store.enc")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("store.enc created: %v", err)
			}
		})
	}
}

func TestStoreEditsTakeLock(t *testing.T) {
	dir := initStore(t)
	path := filepath.Join(dir, "store.enc")
	before := storeBytes(t, dir)
	edits := [][]string{
		{"secret", "add", "-dir", dir, "github-app"},
		{"secret", "rm", "-dir", dir, "github-app"},
		{"ca", "init", "-dir", dir, "-unconstrained"},
		{"passwd", "-dir", dir},
		{"init", "-dir", dir},
	}
	t.Run("busy", func(t *testing.T) {
		unlock, err := store.Lock(path)
		if err != nil {
			t.Fatal(err)
		}
		defer unlock()
		for _, args := range edits[:4] {
			f := credenza(t, 1, []string{pass, canary}, args...)
			if !strings.Contains(f.errb.String(), "locked") || len(f.prompts) != 0 {
				t.Fatalf("%v: stderr %q, prompts %v", args, f.errb, f.prompts)
			}
		}
		if !bytes.Equal(before, storeBytes(t, dir)) {
			t.Fatal("store.enc changed")
		}
	})
	t.Run("held at every prompt", func(t *testing.T) {
		os.Remove(path) // init needs a missing store
		// In this order, secret add creates the name secret rm removes.
		for _, args := range append(edits[4:], edits[:4]...) {
			f := fakeEnv()
			answers := map[string][]string{
				"init":   {pass, pass},
				"secret": {pass, canary},
				"ca":     {pass},
				"passwd": {pass, newPass, newPass},
			}[args[0]]
			f.readSecret = func(ctx context.Context, prompt string) (string, error) {
				if unlock, err := store.Lock(path); err == nil {
					unlock()
					t.Errorf("%v: store not locked at prompt %q", args, prompt)
				}
				a := answers[0]
				answers = answers[1:]
				return a, nil
			}
			if got := f.run(t, args...); got != 0 {
				t.Fatalf("%v: exit %d, stderr %q", args, got, f.errb)
			}
			if args[0] == "passwd" {
				credenza(t, 0, []string{newPass, pass, pass}, "passwd", "-dir", dir)
			}
		}
	})
}

func TestCACertWithoutCA(t *testing.T) {
	dir := initStore(t)
	f := credenza(t, 1, []string{pass}, "ca-cert", "-dir", dir)
	if !strings.Contains(f.errb.String(), "no CA") || f.out.Len() != 0 {
		t.Fatalf("stdout %q, stderr %q", f.out, f.errb)
	}
}

func TestWrongPassphrase(t *testing.T) {
	dir := initStore(t)
	f := credenza(t, 1, []string{"not the passphrase"}, "secret", "list", "-dir", dir)
	if f.errb.String() != "credenza: wrong passphrase or corrupted store\n" {
		t.Fatalf("stderr %q", f.errb)
	}
}

func TestPasswd(t *testing.T) {
	dir := initStore(t)
	before := storeBytes(t, dir)
	for _, tc := range []struct {
		answers []string
		errText string
	}{
		{[]string{"not the passphrase", newPass, newPass}, "wrong passphrase"},
		{[]string{pass, "short", "short"}, "at least 12"},
		{[]string{pass, newPass, "something else here"}, "do not match"},
	} {
		f := credenza(t, 1, tc.answers, "passwd", "-dir", dir)
		if !strings.Contains(f.errb.String(), tc.errText) {
			t.Fatalf("%v: stderr %q", tc.answers, f.errb)
		}
		if !bytes.Equal(before, storeBytes(t, dir)) {
			t.Fatalf("%v: store.enc changed", tc.answers)
		}
	}

	credenza(t, 0, []string{pass, canary}, "secret", "add", "-dir", dir, "github-app")
	f := credenza(t, 0, []string{pass, newPass, newPass}, "passwd", "-dir", dir)
	if f.errb.String() != "credenza: passphrase changed\n" {
		t.Fatalf("stderr %q", f.errb)
	}
	f = credenza(t, 1, []string{pass}, "secret", "list", "-dir", dir)
	if !strings.Contains(f.errb.String(), "wrong passphrase") {
		t.Fatalf("stderr %q", f.errb)
	}
	f = credenza(t, 0, []string{newPass}, "secret", "list", "-dir", dir)
	if f.out.String() != "github-app\n" {
		t.Fatalf("stdout %q", f.out)
	}
}

func TestPolicyCheck(t *testing.T) {
	valid, err := os.ReadFile("../../internal/policy/testdata/valid.json")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		content []byte // nil: no file
		want    int
		out     string
	}{
		{"valid", valid, 0, "policy ok: 1 project(s)\n"},
		{"invalid", []byte(`{"version": 2, "projects": {}}`), 1, ""},
		{"not json", []byte("{\n\"version\": 1,\n"), 1, ""},
		{"missing", nil, 1, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.content != nil {
				p := filepath.Join(dir, "policy.json")
				if err := os.WriteFile(p, tc.content, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(p, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			f := credenza(t, tc.want, nil, "policy", "check", "-dir", dir)
			if f.out.String() != tc.out {
				t.Fatalf("stdout %q, want %q", f.out, tc.out)
			}
			if len(f.prompts) != 0 {
				t.Fatalf("prompted %v", f.prompts)
			}
			if tc.want != 0 {
				assertOneLine(t, f.errb.String())
				if !strings.HasPrefix(f.errb.String(), "credenza: policy: ") {
					t.Fatalf("stderr %q", f.errb)
				}
			}
		})
	}
}

func TestVersion(t *testing.T) {
	f := credenza(t, 0, nil, "version")
	if f.out.String() != version+"\n" || f.errb.Len() != 0 {
		t.Fatalf("stdout %q, stderr %q", f.out, f.errb)
	}
}

func TestHelp(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"-h"}, {"-help"}, {"--help"}, {"secret", "add", "-h"}, {"ca", "init", "-h"}} {
		f := fakeEnv()
		if got := f.run(t, args...); got != 0 {
			t.Fatalf("%v: exit %d, want 0", args, got)
		}
		assertOneLine(t, f.errb.String())
		if !strings.HasPrefix(f.errb.String(), "usage: credenza") {
			t.Fatalf("%v: stderr %q", args, f.errb)
		}
	}
}

func TestUsageDoesNotEchoOperands(t *testing.T) {
	for _, args := range [][]string{
		{"ghp_PASTED"},
		{"secret", "ghp_PASTED"},
		{"ca", "ghp_PASTED"},
		{"policy", "ghp_PASTED"},
		{"secret", "add", "-ghp_PASTED", "github-app"},
		{"secret", "list", "ghp_PASTED"},
	} {
		f := credenza(t, 2, nil, args...)
		if strings.Contains(f.errb.String(), "PASTED") {
			t.Fatalf("%v: operand echoed in stderr %q", args, f.errb)
		}
	}
}

func TestFlagAfterName(t *testing.T) {
	dir := initStore(t)
	f := credenza(t, 2, nil, "secret", "add", "-dir", dir, "github-app", "-replace")
	if !strings.Contains(f.errb.String(), "flags go before") {
		t.Fatalf("stderr %q", f.errb)
	}
}

func TestInitMissingDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "absent")
	f := credenza(t, 1, []string{pass, pass}, "init", "-dir", dir)
	if !strings.Contains(f.errb.String(), "is its filesystem mounted?") || len(f.prompts) != 0 {
		t.Fatalf("stderr %q, prompts %v", f.errb, f.prompts)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dir created: %v", err)
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"frob"},
		{"secret"},
		{"secret", "add"},
		{"secret", "add", "a", "b"},
		{"secret", "frob"},
		{"secret", "list", "extra"},
		{"secret", "add", "-nope", "github-app"},
		{"ca"},
		{"ca", "frob"},
		{"policy"},
		{"policy", "check", "extra"},
		{"init", "extra"},
		{"passwd", "extra"},
		{"ca-cert", "extra"},
		{"version", "extra"},
	} {
		f := fakeEnv(pass, pass)
		if got := f.run(t, args...); got != 2 {
			t.Fatalf("%v: exit %d, want 2; stderr %q", args, got, f.errb)
		}
		assertOneLine(t, f.errb.String())
		if !strings.HasPrefix(f.errb.String(), "credenza: ") || !strings.Contains(f.errb.String(), "usage: credenza") {
			t.Fatalf("%v: stderr %q has no usage", args, f.errb)
		}
		if len(f.prompts) != 0 || f.out.Len() != 0 {
			t.Fatalf("%v: prompts %v, stdout %q", args, f.prompts, f.out)
		}
	}
}

func TestSecretAddOfflineWhenDown(t *testing.T) {
	dir := setupDir(t)
	// A stale socket file from a serve that died is not a running serve.
	run := filepath.Join(dir, "run")
	if err := os.Mkdir(run, 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", filepath.Join(run, "admin.sock"))
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	f := credenza(t, 0, []string{pass, "ghp_offline"}, "secret", "add", "-dir", dir, "-replace", "github-app")
	if want := []string{"passphrase: ", "secret value: "}; !slices.Equal(f.prompts, want) {
		t.Fatalf("prompts %q, want %q", f.prompts, want)
	}
	if got := f.errb.String(); got != "credenza: secret github-app saved; used at next serve start\n" {
		t.Fatalf("stderr %q", got)
	}
	f = credenza(t, 0, []string{pass}, "secret", "rm", "-dir", dir, "github-app")
	if want := []string{"passphrase: "}; !slices.Equal(f.prompts, want) {
		t.Fatalf("rm prompts %q, want %q", f.prompts, want)
	}
	if got := f.errb.String(); got != "credenza: secret github-app removed; used at next serve start\n" {
		t.Fatalf("rm stderr %q", got)
	}
	d, err := store.Load(filepath.Join(dir, "store.enc"), pass)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := d.Secrets["github-app"]; ok {
		t.Fatal("github-app still in the store")
	}
}

func TestSecretAddUsesSocketWhenServing(t *testing.T) {
	dir := setupDir(t)
	startServe(t, dir)
	before := storeBytes(t, dir)
	// No -replace: an existing name is refused, after the value prompt
	// only, and the store is unchanged.
	f := credenza(t, 1, []string{canary}, "secret", "add", "-dir", dir, "github-app")
	if want := []string{"secret value: "}; !slices.Equal(f.prompts, want) {
		t.Fatalf("prompts %q, want %q", f.prompts, want)
	}
	if !strings.Contains(f.errb.String(), "exists") {
		t.Fatalf("stderr %q", f.errb)
	}
	assertOneLine(t, f.errb.String())
	if !bytes.Equal(before, storeBytes(t, dir)) {
		t.Fatal("refused add changed store.enc")
	}
	f = credenza(t, 0, []string{canary}, "secret", "add", "-dir", dir, "-replace", "github-app")
	if want := []string{"secret value: "}; !slices.Equal(f.prompts, want) {
		t.Fatalf("prompts %q, want %q", f.prompts, want)
	}
	if got := f.errb.String(); got != "credenza: secret github-app saved; live\n" {
		t.Fatalf("stderr %q", got)
	}
	f = credenza(t, 0, []string{canary}, "secret", "add", "-dir", dir, "extra")
	if got := f.errb.String(); got != "credenza: secret extra saved; live\n" {
		t.Fatalf("stderr %q", got)
	}
	f = credenza(t, 0, nil, "secret", "rm", "-dir", dir, "extra")
	if len(f.prompts) != 0 {
		t.Fatalf("rm prompted %q", f.prompts)
	}
	if got := f.errb.String(); got != "credenza: secret extra removed; live\n" {
		t.Fatalf("rm stderr %q", got)
	}
	f = credenza(t, 1, nil, "secret", "rm", "-dir", dir, "extra")
	if !strings.Contains(f.errb.String(), "not found") {
		t.Fatalf("rm missing: stderr %q", f.errb)
	}
	// A bad value is refused before it is sent.
	f = credenza(t, 1, []string{"a\rb"}, "secret", "add", "-dir", dir, "-replace", "github-app")
	if !strings.Contains(f.errb.String(), "control character") {
		t.Fatalf("bad value: stderr %q", f.errb)
	}
	d, err := store.Load(filepath.Join(dir, "store.enc"), pass)
	if err != nil {
		t.Fatal(err)
	}
	if d.Secrets["github-app"] != canary {
		t.Fatal("github-app does not hold the new value")
	}
	if _, ok := d.Secrets["extra"]; ok {
		t.Fatal("extra still in the store")
	}
}
