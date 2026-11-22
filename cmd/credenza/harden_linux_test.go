// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"syscall"
	"testing"
)

func TestHardenNotDumpable(t *testing.T) {
	if os.Getenv(hardenChild) != "1" {
		inChild(t, "TestHardenNotDumpable")
		return
	}
	if v, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0); errno != 0 || v != 1 {
		t.Skipf("process not dumpable before harden (%d, %v); nothing to observe", v, errno)
	}
	if err := harden(); err != nil {
		t.Fatal(err)
	}
	v, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	if v != 0 {
		t.Fatalf("PR_GET_DUMPABLE %d, want 0", v)
	}
}
