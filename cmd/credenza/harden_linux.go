// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"syscall"
)

func hardenOS() error {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0); errno != 0 {
		return fmt.Errorf("prctl PR_SET_DUMPABLE: %w", errno)
	}
	return nil
}
