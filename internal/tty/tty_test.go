// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: Apache-2.0

package tty

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeStty puts an stty on PATH that appends its arguments to the returned
// log file and exits with code, so the read path runs on a pipe. It exits 3
// unless its standard input is a pipe, and writes a canary to stderr.
func fakeStty(t *testing.T, code int) string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "stty.log")
	script := "#!/bin/sh\n[ -p /dev/stdin ] || exit 3\necho \"$*\" >> \"$STTY_LOG\"\necho 'typed secret' >&2\nexit " + strconv.Itoa(code) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "stty"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("STTY_LOG", log)
	return log
}

func sttyCalls(t *testing.T, log string) string {
	t.Helper()
	b, err := os.ReadFile(log)
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func pipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	return r, w
}

func TestReadNotTerminal(t *testing.T) {
	r, w := pipe(t)
	w.WriteString("typed secret\n")
	_, err := New(r, io.Discard).Read(context.Background(), "passphrase: ")
	if err == nil || !strings.Contains(err.Error(), "not a terminal") {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "typed secret") {
		t.Fatal("input in error")
	}
}

func TestReadCancelled(t *testing.T) {
	r, w := pipe(t)
	w.WriteString("typed secret\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := New(r, io.Discard).Read(ctx, "passphrase: ")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestReadSttyFailureHidesOutput(t *testing.T) {
	log := fakeStty(t, 1)
	r, w := pipe(t)
	w.WriteString("typed secret\n")
	var out bytes.Buffer
	_, err := New(r, &out).Read(context.Background(), "passphrase: ")
	if err == nil || err.Error() != "tty: standard input is not a terminal" {
		t.Fatalf("got %v", err)
	}
	// The prompt is printed only once echo is off.
	if out.String() != "" {
		t.Fatalf("out %q", out.String())
	}
	if got := sttyCalls(t, log); got != "-echo\n" {
		t.Fatalf("stty calls %q", got)
	}
}

func TestReadSttyMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	r, _ := pipe(t)
	_, err := New(r, io.Discard).Read(context.Background(), "passphrase: ")
	if err == nil || err.Error() != "tty: stty not found" {
		t.Fatalf("got %v", err)
	}
}

func TestReadLine(t *testing.T) {
	cases := []struct {
		name, input, want string
	}{
		{"newline", "s3cret pass\n", "s3cret pass"},
		{"crlf", "s3cret pass\r\n", "s3cret pass"},
		{"eof without newline", "s3cret pass", "s3cret pass"},
		{"empty line", "\n", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			log := fakeStty(t, 0)
			r, w := pipe(t)
			w.WriteString(c.input)
			w.Close()
			var out bytes.Buffer
			got, err := New(r, &out).Read(context.Background(), "passphrase: ")
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
			if out.String() != "passphrase: \n" {
				t.Fatalf("out %q", out.String())
			}
			if calls := sttyCalls(t, log); calls != "-echo\necho\n" {
				t.Fatalf("stty calls %q", calls)
			}
		})
	}
}

func TestReadKeepsBufferedInput(t *testing.T) {
	fakeStty(t, 0)
	r, w := pipe(t)
	w.WriteString("first passphrase\nsecond passphrase\n")
	h := New(r, io.Discard)
	for _, want := range []string{"first passphrase", "second passphrase"} {
		got, err := h.Read(context.Background(), "passphrase: ")
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}

func TestReadNoInput(t *testing.T) {
	log := fakeStty(t, 0)
	r, w := pipe(t)
	w.Close()
	_, err := New(r, io.Discard).Read(context.Background(), "passphrase: ")
	if err == nil || !strings.Contains(err.Error(), "no input") {
		t.Fatalf("got %v", err)
	}
	if calls := sttyCalls(t, log); calls != "-echo\necho\n" {
		t.Fatalf("stty calls %q", calls)
	}
}

func TestReadCancelledWhileWaiting(t *testing.T) {
	log := fakeStty(t, 0)
	r, w := pipe(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			if b, _ := os.ReadFile(log); strings.Contains(string(b), "-echo") {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
	}()
	var out bytes.Buffer
	h := New(r, &out)
	_, err := h.Read(ctx, "passphrase: ")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if out.String() != "passphrase: \n" {
		t.Fatalf("out %q", out.String())
	}
	if calls := sttyCalls(t, log); calls != "-echo\necho\n" {
		t.Fatalf("stty calls %q", calls)
	}

	// A line typed after the cancel may have been echoed: a later Read
	// refuses instead of returning it or racing the abandoned read.
	w.WriteString("late line\n")
	lateCtx, lateCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer lateCancel()
	_, err = h.Read(lateCtx, "secret value: ")
	if err == nil || err.Error() != "tty: an earlier read was cancelled" {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(out.String(), "secret value") {
		t.Fatalf("out %q", out.String())
	}
}
