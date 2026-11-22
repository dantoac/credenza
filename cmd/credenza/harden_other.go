// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package main

// hardenOS has nothing to add outside Linux: PR_SET_DUMPABLE is a Linux
// prctl.
func hardenOS() error { return nil }
