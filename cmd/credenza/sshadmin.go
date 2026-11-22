// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/dantoac/credenza/internal/control"
)

const sshAdminUsage = "usage: policy-load < policy.json"

// sshAdmin is the forced command of the policy key, held by whatever loads
// the policy (a person or a config tool).
// It accepts only "policy-load" from SSH_ORIGINAL_COMMAND, reads the
// policy from stdin, passes it to the admin socket and never runs a
// shell or another program. It never dials broker.sock, and the session
// key's ssh-command never dials admin.sock.
func (c *cli) sshAdmin(args []string) int {
	cmd := newCommand("ssh-admin", "credenza ssh-admin [-dir <dir>]")
	if code, ok := c.parse(cmd, args, 0); !ok {
		return code
	}
	words := dropProgramName(strings.Fields(c.e.getenv("SSH_ORIGINAL_COMMAND")))
	if len(words) != 1 || words[0] != "policy-load" {
		fmt.Fprintln(c.e.stderr, sshAdminUsage)
		return exitUsage
	}
	// One byte more than control.MaxPolicy shows a body that is too long.
	body, err := io.ReadAll(io.LimitReader(c.e.stdin, control.MaxPolicy+1))
	if err != nil {
		return c.fail(fmt.Errorf("read policy: %w", err))
	}
	if len(body) > control.MaxPolicy {
		fmt.Fprintln(c.e.stderr, sshAdminUsage)
		return exitUsage
	}
	if body == nil {
		// A nil body would not end the writes.
		body = []byte{}
	}
	code, errLine := control.CallBody(filepath.Join(*cmd.dir, "run", "admin.sock"), words, body, c.e.stdout)
	if code != control.ExitOK {
		fmt.Fprintf(c.e.stderr, "credenza: %s\n", errLine)
	}
	return code
}
