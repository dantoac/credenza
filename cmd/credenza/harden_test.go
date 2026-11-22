// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
)

// hardenChild is set in the environment of the child process that runs
// harden(): its limits cannot be raised again, so the test process
// itself never calls it.
const hardenChild = "BROKER_TEST_HARDEN_CHILD"

var hardenCalls atomic.Int32

func init() {
	hardenProcess = func() error {
		hardenCalls.Add(1)
		return nil
	}
}

// inChild re-executes the test binary to run only the test name with
// hardenChild set, and fails unless that test passed there.
func inChild(t *testing.T, name string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+name+"$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), hardenChild+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	switch {
	case strings.Contains(string(out), "--- PASS: "+name):
	case strings.Contains(string(out), "--- SKIP: "+name):
		t.Skipf("child skipped:\n%s", out)
	default:
		t.Fatalf("child did not run %s:\n%s", name, out)
	}
}

func TestHardenCoreLimit(t *testing.T) {
	if os.Getenv(hardenChild) != "1" {
		inChild(t, "TestHardenCoreLimit")
		return
	}
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &rl); err != nil {
		t.Fatal(err)
	}
	if rl.Max == 0 {
		t.Skip("core hard limit already 0; nothing to observe")
	}
	// Raise the soft limit so harden() has to lower both.
	rl.Cur = rl.Max
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &rl); err != nil {
		t.Fatal(err)
	}
	if err := harden(); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &rl); err != nil {
		t.Fatal(err)
	}
	if rl.Cur != 0 || rl.Max != 0 {
		t.Fatalf("RLIMIT_CORE %+v, want 0 and 0", rl)
	}
}

func TestRunHardens(t *testing.T) {
	missing := "/nonexistent-broker-dir"
	cases := []struct {
		args   []string
		harden bool
	}{
		{[]string{"init", "-dir", missing}, true},
		{[]string{"secret", "list", "-dir", missing}, true},
		{[]string{"ca", "init", "-dir", missing, "-unconstrained"}, true},
		{[]string{"ca-cert", "-dir", missing}, true},
		{[]string{"passwd", "-dir", missing}, true},
		{[]string{"serve", "-dir", missing, "-clients", "10.0.0.0/8"}, true},
		{[]string{"policy", "check", "-dir", missing}, false},
		{[]string{"version"}, false},
		{[]string{"ssh-command", "-dir", missing}, false},
	}
	for _, c := range cases {
		before := hardenCalls.Load()
		run(context.Background(), c.args, fakeEnv().env)
		if got := hardenCalls.Load() > before; got != c.harden {
			t.Errorf("%v: harden called %v, want %v", c.args, got, c.harden)
		}
	}
}

func TestServeHardenFailure(t *testing.T) {
	dir := setupDir(t)
	old := hardenProcess
	hardenProcess = func() error { return syscall.EPERM }
	defer func() { hardenProcess = old }()
	sio := newServeIO(pass, nil)
	if got := run(context.Background(), serveArgs(dir), sio.env); got != 1 {
		t.Fatalf("exit %d, want 1", got)
	}
	if got := sio.errb.String(); got != "credenza: harden: "+syscall.EPERM.Error()+"\n" {
		t.Fatalf("stderr %q", got)
	}
	if n := sio.prompts.Load(); n != 0 {
		t.Fatalf("prompted %d times before hardening", n)
	}
}
