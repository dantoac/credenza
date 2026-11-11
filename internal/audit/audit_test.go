// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: GPL-3.0-or-later

package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"
)

// fakeFile records what Log does with its file. Write is deliberately not
// guarded, so the race detector reports a Log that writes concurrently;
// Sync may run outside the Log's lock and has its own.
type fakeFile struct {
	buf      bytes.Buffer
	writes   int
	tearNext bool // the next Write stores half of p and fails

	mu      sync.Mutex
	syncs   int
	syncErr error
}

func (f *fakeFile) Write(p []byte) (int, error) {
	f.writes++
	if f.tearNext {
		f.tearNext = false
		n, _ := f.buf.Write(p[:len(p)/2])
		return n, syscall.ENOSPC
	}
	return f.buf.Write(p)
}

func (f *fakeFile) Sync() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.syncs++
	return f.syncErr
}

func (f *fakeFile) Close() error { return nil }

var fixedTime = time.Date(2026, 10, 31, 12, 0, 0, 123456789, time.FixedZone("CLT", -3*3600))

func clock() time.Time { return fixedTime }

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return lines
}

func TestWriteAppendsJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	local := time.Date(2026, 10, 31, 9, 0, 0, 0, time.FixedZone("CLT", -3*3600))
	for _, e := range []Event{
		{Event: "mint", Task: "t1", Project: "example/app", Secret: "github-app", Decision: "allow"},
		{Time: local, Event: "proxy", Host: "api.github.com", Method: "GET", Path: "/repos/example/app", Client: "10.0.0.5", Decision: "deny", Reason: "path"},
	} {
		if err := l.Write(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Write(Event{Event: "revoke", Task: "t1", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	lines := readLines(t, path)
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3", len(lines))
	}
	wantEvents := []string{"mint", "proxy", "revoke"}
	for i, line := range lines {
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if e.Event != wantEvents[i] {
			t.Fatalf("line %d: event %q, want %q", i, e.Event, wantEvents[i])
		}
		if e.Time.IsZero() || e.Time.Location() != time.UTC {
			t.Fatalf("line %d: time %v not set in UTC", i, e.Time)
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			t.Fatal(err)
		}
		if ts, _ := raw["time"].(string); !strings.HasSuffix(ts, "Z") {
			t.Fatalf("line %d: time %q not in UTC", i, ts)
		}
	}
	var second Event
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatal(err)
	}
	if !second.Time.Equal(local) {
		t.Fatalf("given time changed: got %v, want %v", second.Time, local)
	}
}

func TestOpenMode0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode %o, want 600", got)
	}
}

func TestOpenRefusesSymlink(t *testing.T) {
	tests := []struct {
		name   string
		target bool // whether the symlink target exists
	}{
		{"existing target", true},
		{"dangling", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "elsewhere")
			if tt.target {
				if err := os.WriteFile(target, []byte("keep\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			link := filepath.Join(dir, "audit.log")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			l, err := Open(link)
			if err == nil {
				l.Close()
				t.Fatal("Open followed a symlink")
			}
			if !strings.Contains(err.Error(), "symlink") {
				t.Fatalf("error %q does not mention the symlink", err)
			}
			got, err := os.ReadFile(target)
			switch {
			case tt.target && (err != nil || string(got) != "keep\n"):
				t.Fatalf("target changed: %q, %v", got, err)
			case !tt.target && err == nil:
				t.Fatal("Open created the symlink target")
			}
		})
	}
}

func TestOpenRefusesNonRegular(t *testing.T) {
	tests := []struct {
		name string
		path func(t *testing.T) string
	}{
		{"directory", func(t *testing.T) string { return t.TempDir() }},
		{"device", func(*testing.T) string { return os.DevNull }},
		{"fifo without reader", func(t *testing.T) string {
			p := filepath.Join(t.TempDir(), "audit.log")
			if err := syscall.Mkfifo(p, 0o600); err != nil {
				t.Fatal(err)
			}
			return p
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.path(t)
			done := make(chan error, 1)
			go func() {
				l, err := Open(path)
				if err == nil {
					l.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "not a regular file") {
					t.Fatalf("got %v, want a not a regular file error", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Open blocked")
			}
		})
	}
}

func TestOpenRefusesLoosePermissions(t *testing.T) {
	tests := []struct {
		mode os.FileMode
		ok   bool
	}{
		{0o600, true},
		{0o640, false},
		{0o604, false},
		{0o666, false},
	}
	for _, tt := range tests {
		t.Run(tt.mode.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.log")
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tt.mode); err != nil {
				t.Fatal(err)
			}
			l, err := Open(path)
			if tt.ok && err != nil {
				t.Fatalf("mode %v refused: %v", tt.mode, err)
			}
			if !tt.ok && (err == nil || !strings.Contains(err.Error(), "group or other")) {
				t.Fatalf("mode %v: got %v, want a permissions error", tt.mode, err)
			}
			if err == nil {
				l.Close()
			}
		})
	}
}

func TestOpenRepairsTornTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte(`{"time":"2026-10-31T00:00:00Z","event":"mint","decision":"allow"}`+"\n"+`{"time":"2026-10-31T00:00:01Z","even`), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Write(Event{Event: "revoke", Task: "t1", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	lines := readLines(t, path)
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3: %q", len(lines), lines)
	}
	var e Event
	if err := json.Unmarshal([]byte(lines[2]), &e); err != nil || e.Event != "revoke" {
		t.Fatalf("new line %q not intact: %v", lines[2], err)
	}
}

func TestConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 50*20)
	for g := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 20 {
				e := Event{Event: "proxy", Task: fmt.Sprintf("g%d-%d", g, i), Decision: "deny", Reason: "path"}
				if i%5 == 0 {
					e.Decision = "allow"
				}
				if err := l.Write(e); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	lines := readLines(t, path)
	if len(lines) != 1000 {
		t.Fatalf("got %d lines, want 1000", len(lines))
	}
	seen := make(map[string]bool, len(lines))
	for i, line := range lines {
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("line %d %q: %v", i, line, err)
		}
		seen[e.Task] = true
	}
	if len(seen) != 1000 {
		t.Fatalf("got %d distinct events, want 1000", len(seen))
	}
}

func TestEventHasNoValueField(t *testing.T) {
	want := []struct{ name, tag string }{
		{"Time", "time"},
		{"Event", "event"},
		{"Task", "task,omitempty"},
		{"Project", "project,omitempty"},
		{"Secret", "secret,omitempty"},
		{"Host", "host,omitempty"},
		{"Method", "method,omitempty"},
		{"Path", "path,omitempty"},
		{"Client", "client,omitempty"},
		{"Decision", "decision"},
		{"Reason", "reason,omitempty"},
	}
	typ := reflect.TypeFor[Event]()
	if typ.NumField() != len(want) {
		t.Fatalf("Event has %d fields, want %d", typ.NumField(), len(want))
	}
	for i, w := range want {
		f := typ.Field(i)
		if f.Name != w.name || f.Tag.Get("json") != w.tag {
			t.Fatalf("field %d: %s `json:%q`, want %s `json:%q`", i, f.Name, f.Tag.Get("json"), w.name, w.tag)
		}
		wantType := reflect.TypeFor[string]()
		if w.name == "Time" {
			wantType = reflect.TypeFor[time.Time]()
		}
		if f.Type != wantType {
			t.Fatalf("field %s has type %s, want %s", f.Name, f.Type, wantType)
		}
	}
}

// straddle returns a 10 KiB string whose 2-byte rune starts at byte n-1,
// so a plain byte cut at n splits it.
func straddle(n int) string {
	s := strings.Repeat("a", n-1) + "é"
	return s + strings.Repeat("b", 10<<10-len(s))
}

func TestAuditFieldLimits(t *testing.T) {
	f := &fakeFile{}
	l := newLog(f, clock)
	e := Event{Event: "proxy", Host: straddle(MaxHost), Method: straddle(MaxMethod), Path: straddle(MaxPath), Decision: "deny", Reason: "host"}
	if err := l.Write(e); err != nil {
		t.Fatal(err)
	}
	raw := f.buf.Bytes()
	if len(raw) >= 1<<10 {
		t.Fatalf("line is %d bytes, want under 1 KiB", len(raw))
	}
	var got Event
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		s    string
		max  int
	}{
		{"host", got.Host, MaxHost},
		{"method", got.Method, MaxMethod},
		{"path", got.Path, MaxPath},
	} {
		if len(c.s) > c.max {
			t.Errorf("%s is %d bytes, want <= %d", c.name, len(c.s), c.max)
		}
		if !utf8.ValidString(c.s) || strings.ContainsRune(c.s, utf8.RuneError) {
			t.Errorf("%s is not clean UTF-8: %q", c.name, c.s)
		}
		if c.s != strings.Repeat("a", c.max-1) {
			t.Errorf("%s cut wrong: %d bytes", c.name, len(c.s))
		}
	}
}

func TestSyncOnAllowOnly(t *testing.T) {
	f := &fakeFile{}
	l := newLog(f, clock)
	events := []Event{
		{Event: "proxy", Host: "api.github.com", Decision: "allow"},
		{Event: "mint", Task: "t1", Decision: "allow"},
		{Event: "revoke", Task: "t1", Decision: "allow"},
		{Event: "proxy", Host: "api.github.com", Decision: "deny", Reason: "path"},
		{Event: "mint", Task: "t2", Decision: "deny", Reason: "policy"},
	}
	for _, e := range events {
		if err := l.Write(e); err != nil {
			t.Fatal(err)
		}
	}
	if f.syncs != 3 {
		t.Fatalf("syncs = %d, want 3", f.syncs)
	}
	if f.writes != len(events) {
		t.Fatalf("writes = %d, want one per event (%d)", f.writes, len(events))
	}
	lines := strings.Split(strings.TrimSuffix(f.buf.String(), "\n"), "\n")
	if len(lines) != len(events) {
		t.Fatalf("got %d lines, want %d", len(lines), len(events))
	}
	for i, line := range lines {
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		if !e.Time.Equal(fixedTime) || e.Time.Location() != time.UTC {
			t.Fatalf("line %d: time %v, want %v in UTC", i, e.Time, fixedTime.UTC())
		}
	}
}

func TestSyncFailureReturnsError(t *testing.T) {
	syncErr := errors.New("disk gone")
	f := &fakeFile{syncErr: syncErr}
	l := newLog(f, clock)
	if err := l.Write(Event{Event: "proxy", Decision: "allow"}); !errors.Is(err, syncErr) {
		t.Fatalf("allow: got %v, want the sync error", err)
	}
	if err := l.Write(Event{Event: "proxy", Decision: "deny", Reason: "path"}); err != nil {
		t.Fatalf("deny: %v", err)
	}
}

func TestConcurrentWritesSerialized(t *testing.T) {
	f := &fakeFile{}
	l := newLog(f, clock)
	var wg sync.WaitGroup
	for g := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 20 {
				d := "deny"
				if i%5 == 0 {
					d = "allow"
				}
				if err := l.Write(Event{Event: "proxy", Task: fmt.Sprintf("g%d-%d", g, i), Decision: d}); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if f.writes != 1000 {
		t.Fatalf("writes = %d, want 1000", f.writes)
	}
	if f.syncs != 200 {
		t.Fatalf("syncs = %d, want 200", f.syncs)
	}
}

func TestAuditLineWorstCase(t *testing.T) {
	// json.Marshal escapes <, >, &, control bytes and U+2028 to 6 bytes
	// each, so a line is bounded by six times the capped fields plus the
	// fixed fields.
	const bound = 6*(MaxHost+MaxMethod+MaxPath) + 256
	f := &fakeFile{}
	l := newLog(f, clock)
	e := Event{
		Event:    "proxy",
		Host:     strings.Repeat("<", 10<<10),
		Method:   strings.Repeat("\x01", 10<<10),
		Path:     strings.Repeat("\u2028", 10<<10),
		Decision: "deny",
		Reason:   "port",
	}
	if err := l.Write(e); err != nil {
		t.Fatal(err)
	}
	if n := f.buf.Len(); n > bound {
		t.Fatalf("line is %d bytes, want <= %d", n, bound)
	}
}

func TestWriteAfterTornWriteStartsNewLine(t *testing.T) {
	f := &fakeFile{tearNext: true}
	l := newLog(f, clock)
	if err := l.Write(Event{Event: "proxy", Decision: "deny", Reason: "path"}); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("torn write: got %v, want ENOSPC", err)
	}
	if err := l.Write(Event{Event: "mint", Task: "t1", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(f.buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want the torn one and the new one: %q", len(lines), lines)
	}
	var e Event
	if err := json.Unmarshal([]byte(lines[1]), &e); err != nil || e.Event != "mint" {
		t.Fatalf("line after a torn write %q not intact: %v", lines[1], err)
	}
}

func TestWriteAfterClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"allow", "deny"} {
		if err := l.Write(Event{Event: "proxy", Decision: d}); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("%s after Close: got %v, want os.ErrClosed", d, err)
		}
	}
}
