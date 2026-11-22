// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFSIocGetflags(t *testing.T) {
	want := uintptr(0x80086601)
	if ^uintptr(0)>>32 == 0 {
		want = 0x80046601
	}
	if fsIocGetflags != want {
		t.Fatalf("fsIocGetflags = %#x, want %#x", fsIocGetflags, want)
	}
}

func TestStatfsAndFlagsOnLinux(t *testing.T) {
	dir := t.TempDir()
	avail, total, err := statfsSpace(dir)
	if err != nil || total == 0 || avail > total {
		t.Fatalf("statfsSpace = %d, %d, %v", avail, total, err)
	}
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// A new file has no append-only flag; some filesystems (tmpfs on old
	// kernels) do not support the ioctl at all.
	if flags, err := inodeFlags(path); err == nil && flags&fsAppendFL != 0 {
		t.Fatalf("new file has FS_APPEND_FL (flags %#x)", flags)
	}
	if _, err := inodeFlags(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("inodeFlags of a missing file succeeded")
	}
}
