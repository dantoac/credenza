// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"syscall"
)

// hardenProcess is harden, replaced in tests: the limits harden sets
// cannot be raised again, so harden_test.go checks them in a child.
var hardenProcess = harden

// harden keeps secrets out of core files: RLIMIT_CORE 0 on every OS, and
// on Linux the process is also made not dumpable, which stops other
// processes of the same user from attaching with ptrace.
func harden() error {
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("set RLIMIT_CORE: %w", err)
	}
	return hardenOS()
}

// hardened runs hardenProcess before a passphrase or a secret is read.
// When ok is false the caller returns code.
func (c *cli) hardened() (code int, ok bool) {
	if err := hardenProcess(); err != nil {
		return c.fail(fmt.Errorf("harden: %w", err)), false
	}
	return exitOK, true
}
