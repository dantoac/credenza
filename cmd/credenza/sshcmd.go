// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/dantoac/credenza/internal/control"
	"github.com/dantoac/credenza/internal/policy"
	"github.com/dantoac/credenza/internal/token"
)

const sshUsage = "usage: mint <task-id> <project> [<env>...] | renew <task-id> | revoke <task-id>"

// sshCommand is the forced command of the session key in the credenza user's
// authorized_keys.
// It accepts only mint (optionally narrowed to env names), renew and revoke
// from SSH_ORIGINAL_COMMAND, passes them
// to the control socket and never runs a shell or another program.
func (c *cli) sshCommand(args []string) int {
	cmd := newCommand("ssh-command", "credenza ssh-command [-dir <dir>]")
	if code, ok := c.parse(cmd, args, 0); !ok {
		return code
	}
	words := dropProgramName(strings.Fields(c.e.getenv("SSH_ORIGINAL_COMMAND")))
	if !validRequest(words) {
		fmt.Fprintln(c.e.stderr, sshUsage)
		return exitUsage
	}
	code, errLine := control.Call(filepath.Join(*cmd.dir, "run", "broker.sock"), words, c.e.stdout)
	if code != control.ExitOK {
		fmt.Fprintf(c.e.stderr, "credenza: %s\n", errLine)
	}
	return code
}

// dropProgramName drops one leading program name, so that
// "ssh credenza@<host> credenza mint ..." works as well as "... mint ...".
// "broker", the command name before the rename to credenza, is still
// accepted for clients that send it.
func dropProgramName(words []string) []string {
	if len(words) > 0 && (words[0] == "credenza" || words[0] == "broker") {
		return words[1:]
	}
	return words
}

func validRequest(words []string) bool {
	switch {
	case len(words) >= 3 && len(words) <= 3+control.MaxMintEnvs && words[0] == "mint":
		for _, e := range words[3:] {
			if !policy.ValidEnv(e) {
				return false
			}
		}
		return token.ValidTaskID(words[1]) && policy.ValidProject(words[2])
	case len(words) == 2 && (words[0] == "renew" || words[0] == "revoke"):
		return token.ValidTaskID(words[1])
	}
	return false
}
