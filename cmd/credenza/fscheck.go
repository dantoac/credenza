// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"errors"
	"log"
	"time"
)

// minFreePercent is the free space below which serve warns: a full stick
// makes every allow audit write fail, and the proxy then answers 503.
const minFreePercent = 20

// lowSpaceRepeat spaces the free-space warnings while space stays low, so
// they do not push the other lines out of the tmux scrollback.
const lowSpaceRepeat = time.Hour

// fsAppendFL is FS_APPEND_FL from linux/fs.h: writes may only append.
const fsAppendFL = 0x20

var errUnsupported = errors.New("not supported on this OS")

// diskSpace returns the blocks available to unprivileged users and the
// total blocks of the filesystem holding path, or errUnsupported.
// Replaced in tests.
var diskSpace = statfsSpace

// fileFlags returns the inode flags of path (FS_IOC_GETFLAGS), or
// errUnsupported. Replaced in tests.
var fileFlags = inodeFlags

// spaceWarner remembers when it last warned about free space.
type spaceWarner struct {
	warned time.Time // zero while space is not low
}

// check writes one line when less than minFreePercent of the filesystem
// holding path is free: when space drops below it, then at most once per
// lowSpaceRepeat while it stays low. It says nothing where the check is
// unsupported.
func (w *spaceWarner) check(l *log.Logger, path string, now time.Time) {
	avail, total, err := diskSpace(path)
	switch {
	case errors.Is(err, errUnsupported):
	case err != nil:
		l.Printf("credenza: warning: cannot check free space for %s: %v", path, err)
	case total > 0 && avail*100 < total*minFreePercent:
		if !w.warned.IsZero() && now.Sub(w.warned) < lowSpaceRepeat {
			return
		}
		w.warned = now
		l.Printf("credenza: warning: %d%% free on the filesystem of %s, below %d%%; rotate the audit log (runbook R15)",
			avail*100/total, path, minFreePercent)
	default:
		w.warned = time.Time{}
	}
}

// warnNotAppendOnly writes one line when the audit log at path lacks the
// append-only attribute that runbook R9 sets. It says nothing where the
// check is unsupported.
func warnNotAppendOnly(l *log.Logger, path string) {
	flags, err := fileFlags(path)
	switch {
	case errors.Is(err, errUnsupported):
	case err != nil:
		l.Printf("credenza: warning: cannot read the attributes of audit log %s: %v", path, err)
	case flags&fsAppendFL == 0:
		l.Printf("credenza: warning: audit log %s is not append-only; run sudo chattr +a on it (runbook R9)", path)
	}
}
