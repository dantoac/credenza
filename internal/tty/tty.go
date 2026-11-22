// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: Apache-2.0

// Package tty reads passphrases and secret values from a terminal without
// echoing them, using stty on the input file.
package tty

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

type result struct {
	line string
	err  error
}

// Hidden reads lines from a terminal with echo turned off. It is not safe
// for concurrent use.
type Hidden struct {
	in  *os.File
	r   *bufio.Reader
	out io.Writer
	// cancelled is set when a Read returns before its line arrived. The
	// abandoned read still owns r, and a line typed after the cancel may
	// have been echoed, so every later Read fails.
	cancelled bool
}

// New returns a Hidden that reads from in and prints prompts to out.
func New(in *os.File, out io.Writer) *Hidden {
	return &Hidden{in: in, r: bufio.NewReader(in), out: out}
}

// Read runs `stty -echo`, prints prompt to out, reads one line, runs `stty echo`,
// prints "\n" and returns the line without "\r\n". Errors if in is not a terminal.
// When ctx is done before a line arrives, Read runs `stty echo`, prints "\n" and
// returns ctx.Err(); the blocked line read stays in its goroutine (the caller exits).
func (h *Hidden) Read(ctx context.Context, prompt string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if h.cancelled {
		return "", errors.New("tty: an earlier read was cancelled")
	}
	if err := h.stty("-echo"); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return "", errors.New("tty: stty not found")
		}
		return "", errors.New("tty: standard input is not a terminal")
	}
	defer func() {
		h.stty("echo")
		fmt.Fprint(h.out, "\n")
	}()
	fmt.Fprint(h.out, prompt)

	ch := make(chan result, 1)
	go func() {
		line, err := h.r.ReadString('\n')
		ch <- result{line, err}
	}()
	select {
	case res := <-ch:
		return finish(res)
	case <-ctx.Done():
		h.cancelled = true
		return "", ctx.Err()
	}
}

// finish strips the line ending. Errors never include the input.
func finish(res result) (string, error) {
	if res.err != nil {
		if !errors.Is(res.err, io.EOF) {
			return "", fmt.Errorf("tty: reading input: %w", res.err)
		}
		if res.line == "" {
			return "", errors.New("tty: no input")
		}
	}
	line := strings.TrimSuffix(res.line, "\n")
	return strings.TrimSuffix(line, "\r"), nil
}

// stty runs stty on h.in: stty acts on its standard input. Its output is
// discarded.
func (h *Hidden) stty(arg string) error {
	cmd := exec.Command("stty", arg)
	cmd.Stdin = h.in
	return cmd.Run()
}
