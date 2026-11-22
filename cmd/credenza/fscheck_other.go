// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package main

// The free-space and append-only checks are Linux-only: credenza
// targets Linux servers, and chattr +a is a Linux attribute.

func statfsSpace(string) (avail, total uint64, err error) { return 0, 0, errUnsupported }

func inodeFlags(string) (uint32, error) { return 0, errUnsupported }
