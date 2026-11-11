// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: GPL-3.0-or-later

// Command broker keeps real secrets in an encrypted store and swaps
// per-task temporary tokens for them inside a TLS-intercepting proxy.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dantoac/credenza/internal/tty"
)

var version = "dev" // set with -ldflags "-X main.version=..."

// env is everything run needs from the process, so tests can replace it.
type env struct {
	stdin          io.Reader // ssh-admin reads the policy from it
	stdout, stderr io.Writer
	readSecret     func(ctx context.Context, prompt string) (string, error) // tty.New(os.Stdin, os.Stderr).Read in main
	getenv         func(string) string
	now            func() time.Time
	ready          func(proxyAddr, socketPath string) // nil in main; tests use it (Task 11)
}

const (
	exitOK    = 0
	exitErr   = 1
	exitUsage = 2
)

const defaultDir = "/srv/credenza"

const usageLine = "credenza init | secret add|rm|list | ca init | ca-cert | passwd | policy check | serve | ssh-command | ssh-admin | version [-dir <dir>]"

func main() {
	// Installed before any prompt, so Ctrl-C at a prompt restores echo
	// and returns context.Canceled instead of killing the process.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// After the first signal, restore the default action, so a second
	// Ctrl-C kills a process busy in the key derivation.
	context.AfterFunc(ctx, stop)
	e := env{
		stdin:  os.Stdin,
		stdout: os.Stdout,
		stderr: os.Stderr,
		// One Hidden per process: a new one per prompt would lose input
		// buffered by the previous one.
		readSecret: tty.New(os.Stdin, os.Stderr).Read,
		getenv:     os.Getenv,
		now:        time.Now,
	}
	code := run(ctx, os.Args[1:], e)
	stop()
	os.Exit(code)
}

// run dispatches one subcommand and returns the process exit code.
func run(ctx context.Context, args []string, e env) int {
	if len(args) == 0 {
		return usage(e, "missing command", usageLine)
	}
	c := &cli{ctx: ctx, e: e}
	switch args[0] {
	case "init", "secret", "ca", "ca-cert", "passwd":
		// They read a passphrase or a secret. serve hardens itself after
		// parsing its flags.
		if code, ok := c.hardened(); !ok {
			return code
		}
	}
	switch cmd, rest := args[0], args[1:]; cmd {
	case "init":
		return c.init(rest)
	case "secret":
		return c.secret(rest)
	case "ca":
		return c.ca(rest)
	case "ca-cert":
		return c.caCert(rest)
	case "passwd":
		return c.passwd(rest)
	case "policy":
		return c.policy(rest)
	case "serve":
		return c.serve(rest)
	case "ssh-command":
		return c.sshCommand(rest)
	case "ssh-admin":
		return c.sshAdmin(rest)
	case "version":
		return c.version(rest)
	case "help", "-h", "-help", "--help":
		fmt.Fprintf(e.stderr, "usage: %s\n", usageLine)
		return exitOK
	default:
		// Not quoted: it may be a value pasted in the wrong place.
		return usage(e, "unknown command", usageLine)
	}
}

// usage prints one line with the reason and the command syntax, and
// returns exitUsage.
func usage(e env, reason, syntax string) int {
	fmt.Fprintf(e.stderr, "credenza: %s; usage: %s\n", reason, syntax)
	return exitUsage
}
