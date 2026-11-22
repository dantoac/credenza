// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"syscall"
	"unsafe"
)

// fsIocGetflags is FS_IOC_GETFLAGS, _IOR('f', 1, long) in linux/fs.h: the
// size field holds sizeof(long), so 0x80046601 on linux/arm and
// 0x80086601 on linux/arm64 and linux/amd64.
const fsIocGetflags = 0x80006601 | unsafe.Sizeof(uintptr(0))<<16

func statfsSpace(path string) (avail, total uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	return st.Bavail, st.Blocks, nil
}

func inodeFlags(path string) (uint32, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)
	// The kernel writes an int, whatever the long in the macro says
	// (ioctl_iflags(2)).
	var attr int32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), fsIocGetflags, uintptr(unsafe.Pointer(&attr))); errno != 0 {
		return 0, errno
	}
	return uint32(attr), nil
}
