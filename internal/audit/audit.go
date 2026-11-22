// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: Apache-2.0

// Package audit writes the broker's append-only JSON-lines audit log.
//
// An Event has no field able to hold a secret or a token value. Allow
// events are synced to disk before Write returns; deny events are not, so
// a flood of denies costs no fsync.
//
// Host, Method and Path are cut to MaxHost, MaxMethod and MaxPath bytes.
// encoding/json escapes <, >, &, control bytes and U+2028/U+2029 to six
// bytes each, so those three fields take at most 6*(253+16+512) = 4686
// bytes of a line.
package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Event has no field that can carry a secret or a token value.
type Event struct {
	Time     time.Time `json:"time"`  // UTC, RFC 3339 with nanoseconds (encoding/json default)
	Event    string    `json:"event"` // "mint" | "renew" | "revoke" | "proxy" | "secret" | "policy"
	Task     string    `json:"task,omitempty"`
	Project  string    `json:"project,omitempty"`
	Secret   string    `json:"secret,omitempty"` // secret name
	Host     string    `json:"host,omitempty"`
	Method   string    `json:"method,omitempty"`
	Path     string    `json:"path,omitempty"`   // URL path only, never the query
	Client   string    `json:"client,omitempty"` // remote IP
	Decision string    `json:"decision"`         // "allow" | "deny"
	Reason   string    `json:"reason,omitempty"` // short code, see Task 8 and Task 9; renew: "live=<n>" on allow, "gone", "max-session" or "project" on deny; secret: "add", "replace" or "rm"; policy: "sha256=<hex>" on allow, "invalid sha256=<hex>" or "failed sha256=<hex>" on deny
}

// Byte limits for the fields a client controls.
const (
	MaxHost   = 253
	MaxMethod = 16
	MaxPath   = 512
)

// file is what Log writes to; *os.File satisfies it, tests pass a fake.
type file interface {
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

// Log appends events to one file. It is safe for concurrent use.
type Log struct {
	mu   sync.Mutex
	f    file
	now  func() time.Time
	torn bool // the file ends inside a line; the next write starts a new one
}

// Open opens or creates the audit log at path for appending, mode 0600.
// It refuses a symlink, anything that is not a regular file, and a file
// with any group or other permission bit. When the file does not end in a
// newline (a write cut by power loss), the first Write starts a new line.
func Open(path string) (*Log, error) {
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := checkFile(path, fi); err != nil {
			return nil, err
		}
	}
	// O_NOFOLLOW and O_NONBLOCK close the gap between Lstat and OpenFile:
	// a symlink swapped in fails instead of being followed, and a FIFO
	// fails instead of blocking until a reader appears.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	// FreeBSD reports O_NOFOLLOW on a symlink as EMLINK, the others as ELOOP.
	if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK) {
		return nil, fmt.Errorf("audit log %s is a symlink", path)
	}
	if err != nil {
		return nil, err
	}
	fi, err = f.Stat()
	if err == nil {
		err = checkFile(path, fi)
	}
	var torn bool
	if err == nil {
		torn, err = endsInsideLine(path, fi.Size())
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	l := newLog(f, time.Now)
	l.torn = torn
	return l, nil
}

func checkFile(path string, fi fs.FileInfo) error {
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("audit log %s is a symlink", path)
	case !fi.Mode().IsRegular():
		return fmt.Errorf("audit log %s is not a regular file", path)
	case fi.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("audit log %s has mode %04o, want no group or other access", path, fi.Mode().Perm())
	}
	return nil
}

// endsInsideLine reports whether the size-byte file at path has a last
// byte other than a newline.
func endsInsideLine(path string, size int64) (bool, error) {
	if size == 0 {
		return false, nil
	}
	r, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false, err
	}
	defer r.Close()
	last := make([]byte, 1)
	if _, err := r.ReadAt(last, size-1); err != nil {
		return false, fmt.Errorf("read end of audit log %s: %w", path, err)
	}
	return last[0] != '\n', nil
}

func newLog(f file, now func() time.Time) *Log {
	return &Log{f: f, now: now}
}

// Write appends e as one JSON line in a single write. It sets Time to now
// when zero, stores it in UTC, and cuts Host, Method and Path to MaxHost,
// MaxMethod and MaxPath bytes of valid UTF-8. When e.Decision is "allow"
// it then syncs the file and returns the sync error.
func (l *Log) Write(e Event) error {
	if e.Time.IsZero() {
		e.Time = l.now()
	}
	e.Time = e.Time.UTC()
	e.Host = cut(e.Host, MaxHost)
	e.Method = cut(e.Method, MaxMethod)
	e.Path = cut(e.Path, MaxPath)
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("encode audit event: %w", err)
	}
	b = append(b, '\n')
	if err := l.writeLine(b); err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}
	if e.Decision != "allow" {
		return nil
	}
	// Sync runs outside the lock so writes do not queue behind an fsync;
	// it still covers the line written above.
	if err := l.f.Sync(); err != nil {
		return fmt.Errorf("sync audit log: %w", err)
	}
	return nil
}

// writeLine writes line in one Write call, after a newline when an earlier
// write left the file inside a line.
func (l *Log) writeLine(line []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.torn {
		line = append([]byte{'\n'}, line...)
	}
	n, err := l.f.Write(line)
	if err == nil && n != len(line) {
		err = io.ErrShortWrite
	}
	// A failed write that stored nothing leaves the file as it was.
	l.torn = err != nil && (n > 0 || l.torn)
	return err
}

// Close closes the underlying file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

// cut returns at most n bytes of s with invalid UTF-8, including a rune
// split by the cut, removed.
func cut(s string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	return strings.ToValidUTF8(s, "")
}
