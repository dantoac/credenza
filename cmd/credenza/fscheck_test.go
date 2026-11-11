// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"errors"
	"log"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestWarnLowSpace(t *testing.T) {
	const low = "credenza: warning: 19% free on the filesystem of /srv/credenza/audit.log, below 20%; rotate the audit log (runbook R15)\n"
	cases := []struct {
		name         string
		avail, total uint64
		err          error
		want         string // empty means no line
	}{
		{"plenty", 50, 100, nil, ""},
		{"exactly 20%", 20, 100, nil, ""},
		{"below 20%", 19, 100, nil, low},
		{"full", 0, 1000, nil, "credenza: warning: 0% free on the filesystem of /srv/credenza/audit.log, below 20%; rotate the audit log (runbook R15)\n"},
		{"no blocks", 0, 0, nil, ""},
		{"unsupported", 0, 0, errUnsupported, ""},
		{"error", 0, 0, syscall.EIO, "credenza: warning: cannot check free space for /srv/credenza/audit.log: " + syscall.EIO.Error() + "\n"},
	}
	defer func(f func(string) (uint64, uint64, error)) { diskSpace = f }(diskSpace)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var gotPath string
			diskSpace = func(path string) (uint64, uint64, error) {
				gotPath = path
				return c.avail, c.total, c.err
			}
			var buf bytes.Buffer
			var w spaceWarner
			w.check(log.New(&buf, "", 0), "/srv/credenza/audit.log", time.Now())
			if buf.String() != c.want {
				t.Errorf("got %q, want %q", buf.String(), c.want)
			}
			if gotPath != "/srv/credenza/audit.log" {
				t.Errorf("statfs on %q", gotPath)
			}
		})
	}

	// Repeats: at the drop below 20%, then at most once an hour.
	avail := uint64(19)
	diskSpace = func(string) (uint64, uint64, error) { return avail, 100, nil }
	var buf bytes.Buffer
	var w spaceWarner
	l := log.New(&buf, "", 0)
	t0 := time.Now()
	steps := []struct {
		after time.Duration
		avail uint64
		lines int
	}{
		{0, 19, 1},
		{time.Minute, 19, 1},
		{59 * time.Minute, 19, 1},
		{time.Hour, 19, 2},
		{time.Hour + time.Minute, 50, 2},   // space back: no line, state reset
		{time.Hour + 2*time.Minute, 19, 3}, // a new drop warns at once
	}
	for _, st := range steps {
		avail = st.avail
		w.check(l, "/srv/credenza/audit.log", t0.Add(st.after))
		if n := strings.Count(buf.String(), "\n"); n != st.lines {
			t.Fatalf("after %v with %d%% free: %d lines, want %d", st.after, st.avail, n, st.lines)
		}
	}
}

func TestWarnNotAppendOnly(t *testing.T) {
	const notAppend = "credenza: warning: audit log /srv/credenza/audit.log is not append-only; run sudo chattr +a on it (runbook R9)\n"
	cases := []struct {
		name  string
		flags uint32
		err   error
		want  string
	}{
		{"append-only", fsAppendFL, nil, ""},
		{"append-only and noatime", fsAppendFL | 0x80, nil, ""},
		{"no flags", 0, nil, notAppend},
		{"immutable only", 0x10, nil, notAppend},
		{"unsupported", 0, errUnsupported, ""},
		{"error", 0, syscall.ENOTTY, "credenza: warning: cannot read the attributes of audit log /srv/credenza/audit.log: " + syscall.ENOTTY.Error() + "\n"},
	}
	defer func(f func(string) (uint32, error)) { fileFlags = f }(fileFlags)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fileFlags = func(string) (uint32, error) { return c.flags, c.err }
			var buf bytes.Buffer
			warnNotAppendOnly(log.New(&buf, "", 0), "/srv/credenza/audit.log")
			if buf.String() != c.want {
				t.Errorf("got %q, want %q", buf.String(), c.want)
			}
		})
	}
	if fsAppendFL != 0x20 {
		t.Errorf("fsAppendFL = %#x, want 0x20 (FS_APPEND_FL)", fsAppendFL)
	}
}

// TestServeWarnsNotAppendOnly: serve still starts, with one warning line
// before the serving line.
func TestServeWarnsNotAppendOnly(t *testing.T) {
	defer func(f func(string) (uint32, error)) { fileFlags = f }(fileFlags)
	fileFlags = func(string) (uint32, error) { return 0, nil }
	dir := setupDir(t)
	s := launch(t, dir, newServeIO(pass, time.Now))
	lines := strings.Split(strings.TrimSuffix(s.io.errb.String(), "\n"), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "is not append-only") || !strings.HasPrefix(lines[1], "credenza: serving proxy on ") {
		t.Fatalf("stderr %q", s.io.errb)
	}
	if code := s.stop(); code != 0 {
		t.Fatalf("stop: exit %d", code)
	}
}

// TestServeWrapsListener: serve closes a connection from outside -clients
// at accept, without an answer.
func TestServeWrapsListener(t *testing.T) {
	dir := setupDir(t)
	sio := newServeIO(pass, time.Now)
	s := launchArgs(t, []string{"serve", "-dir", dir, "-listen", "127.0.0.1:0", "-clients", "10.0.0.0/8"}, sio)
	c, err := net.DialTimeout("tcp", s.proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c.Read(make([]byte, 64))
	var ne interface{ Timeout() bool }
	if n != 0 || err == nil || errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("read %d bytes, %v; want the connection closed with no answer", n, err)
	}
	if !strings.Contains(sio.errb.String(), "(client 1, not-connect 0, conn-limit 0, rate-limited 0)") {
		t.Fatalf("stderr %q", sio.errb)
	}
}
