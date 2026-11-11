// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/dantoac/credenza/internal/ca"
	"github.com/dantoac/credenza/internal/control"
	"github.com/dantoac/credenza/internal/policy"
	"github.com/dantoac/credenza/internal/store"
)

const minPassphrase = 12

var errInterrupted = errors.New("interrupted")

// cli runs the store management commands for one process.
type cli struct {
	ctx context.Context
	e   env
}

// command is one subcommand's flag set; every subcommand takes -dir.
type command struct {
	fs     *flag.FlagSet
	dir    *string
	syntax string
}

func newCommand(name, syntax string) *command {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	// The flag package prints its error and the usage on separate lines;
	// usage() prints both on one.
	fs.SetOutput(io.Discard)
	return &command{fs: fs, dir: fs.String("dir", defaultDir, "state directory"), syntax: syntax}
}

// parse parses args and checks that exactly nargs positional arguments
// remain. When ok is false the caller returns code.
func (c *cli) parse(cmd *command, args []string, nargs int) (code int, ok bool) {
	if err := cmd.fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintf(c.e.stderr, "usage: %s\n", cmd.syntax)
			return exitOK, false
		}
		// The flag package's error quotes the flag, which may be a value
		// pasted in the wrong place.
		return usage(c.e, "unknown flag or bad flag value", cmd.syntax), false
	}
	if n := cmd.fs.NArg(); n != nargs {
		for _, a := range cmd.fs.Args() {
			if strings.HasPrefix(a, "-") {
				return usage(c.e, "flags go before the arguments", cmd.syntax), false
			}
		}
		return usage(c.e, fmt.Sprintf("want %d argument(s), got %d", nargs, n), cmd.syntax), false
	}
	return exitOK, true
}

// fail prints err as one line and returns exitErr.
func (c *cli) fail(err error) int {
	msg := strings.NewReplacer("\r", " ", "\n", " ").Replace(err.Error())
	fmt.Fprintf(c.e.stderr, "credenza: %s\n", msg)
	return exitErr
}

func (c *cli) done(format string, a ...any) int {
	fmt.Fprintf(c.e.stderr, "credenza: "+format+"\n", a...)
	return exitOK
}

// prompt reads one hidden line. Any sign of cancellation becomes
// errInterrupted, so the caller stops before touching the disk.
func (c *cli) prompt(text string) (string, error) {
	s, err := c.e.readSecret(c.ctx, text)
	if err != nil {
		if c.ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return "", errInterrupted
		}
		return "", err
	}
	return s, nil
}

// newPassphrase reads a new passphrase twice.
func (c *cli) newPassphrase(first, again string) (string, error) {
	p, err := c.prompt(first)
	if err != nil {
		return "", err
	}
	if len(p) < minPassphrase {
		return "", fmt.Errorf("passphrase must be at least %d bytes", minPassphrase)
	}
	q, err := c.prompt(again)
	if err != nil {
		return "", err
	}
	if p != q {
		return "", errors.New("passphrases do not match")
	}
	return p, nil
}

// storePath returns <dir>/store.enc after checking that it exists, so a
// missing store fails before any prompt.
func storePath(dir string) (string, error) {
	p := filepath.Join(dir, "store.enc")
	if _, err := os.Stat(p); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("no store at %s; run credenza init", p)
		}
		return "", err
	}
	return p, nil
}

// unlock reads the passphrase with text as the prompt and loads the store.
func (c *cli) unlock(path, text string) (*store.Data, string, error) {
	pass, err := c.prompt(text)
	if err != nil {
		return nil, "", err
	}
	d, err := store.Load(path, pass)
	if err != nil {
		return nil, "", err
	}
	return d, pass, nil
}

// edit unlocks the store in dir and runs fn on it, then saves the store
// under the passphrase fn returns. The lock covers the whole
// read-modify-write; nothing is written when fn fails.
func (c *cli) edit(dir, text string, fn func(d *store.Data, pass string) (string, error)) error {
	path, err := storePath(dir)
	if err != nil {
		return err
	}
	unlock, err := store.Lock(path)
	if err != nil {
		return err
	}
	defer unlock()
	d, pass, err := c.unlock(path, text)
	if err != nil {
		return err
	}
	if pass, err = fn(d, pass); err != nil {
		return err
	}
	return c.save(path, d, pass)
}

func (c *cli) init(args []string) int {
	cmd := newCommand("init", "credenza init [-dir <dir>]")
	if code, ok := c.parse(cmd, args, 0); !ok {
		return code
	}
	// The state dir is usually a separate filesystem's mount point: never
	// create it, so an unmounted one does not get a store on the root
	// filesystem.
	if fi, err := os.Stat(*cmd.dir); err != nil || !fi.IsDir() {
		return c.fail(fmt.Errorf("state directory %s not found (is its filesystem mounted?)", *cmd.dir))
	}
	path := filepath.Join(*cmd.dir, "store.enc")
	if err := c.create(path); err != nil {
		return c.fail(err)
	}
	return c.done("store created at %s", path)
}

func (c *cli) create(path string) error {
	if err := refuseExisting(path); err != nil {
		return err
	}
	unlock, err := store.Lock(path)
	if err != nil {
		return err
	}
	defer unlock()
	// Again under the lock: another init may have finished meanwhile.
	if err := refuseExisting(path); err != nil {
		return err
	}
	pass, err := c.newPassphrase("new passphrase: ", "repeat passphrase: ")
	if err != nil {
		return err
	}
	return c.save(path, &store.Data{Version: 1, Secrets: map[string]string{}}, pass)
}

// save writes the store unless the context was cancelled meanwhile: a
// Ctrl-C during the key derivation, after the last prompt, still aborts.
func (c *cli) save(path string, d *store.Data, pass string) error {
	if c.ctx.Err() != nil {
		return errInterrupted
	}
	return store.Save(path, d, pass)
}

func refuseExisting(path string) error {
	_, err := os.Lstat(path)
	if err == nil {
		return fmt.Errorf("store already exists at %s", path)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (c *cli) secret(args []string) int {
	const syntax = "credenza secret add|rm|list [-dir <dir>] ..."
	if len(args) == 0 {
		return usage(c.e, "missing secret command", syntax)
	}
	switch args[0] {
	case "add":
		return c.secretAdd(args[1:])
	case "rm":
		return c.secretRm(args[1:])
	case "list":
		return c.secretList(args[1:])
	default:
		return usage(c.e, "unknown secret command", syntax)
	}
}

// secretName returns the one positional argument when it is a valid
// secret name. An invalid name is not quoted: it may be a value pasted
// in the wrong place.
func (c *cli) secretName(cmd *command) (string, int, bool) {
	name := cmd.fs.Arg(0)
	if !store.ValidSecretName(name) {
		return "", usage(c.e, "invalid secret name (want lowercase letters, digits, '.', '_' or '-', at most 64)", cmd.syntax), false
	}
	return name, exitOK, true
}

func (c *cli) secretAdd(args []string) int {
	cmd := newCommand("secret add", "credenza secret add [-dir <dir>] [-replace] <name>")
	replace := cmd.fs.Bool("replace", false, "overwrite an existing secret")
	if code, ok := c.parse(cmd, args, 1); !ok {
		return code
	}
	name, code, ok := c.secretName(cmd)
	if !ok {
		return code
	}
	if sock := adminSocket(*cmd.dir); control.Up(sock) {
		return c.secretAddLive(sock, name, *replace)
	}
	err := c.edit(*cmd.dir, "passphrase: ", func(d *store.Data, pass string) (string, error) {
		if _, ok := d.Secrets[name]; ok && !*replace {
			return "", fmt.Errorf("secret %s exists; use -replace to overwrite it", name)
		}
		v, err := c.prompt("secret value: ")
		if err != nil {
			return "", err
		}
		if err := control.CheckSecretValue(v); err != nil {
			return "", err
		}
		d.Secrets[name] = v
		return pass, nil
	})
	if err != nil {
		return c.fail(err)
	}
	return c.done("secret %s saved; used at next serve start", name)
}

// adminSocket is the admin socket of a serve on dir.
func adminSocket(dir string) string {
	return filepath.Join(dir, "run", "admin.sock")
}

// secretAddLive sends the value to a running serve, which saves the store
// and uses the value at once. No passphrase is asked: the socket is 0600
// in a 0700 directory, so only the broker user reaches it.
func (c *cli) secretAddLive(sock, name string, replace bool) int {
	v, err := c.prompt("secret value: ")
	if err != nil {
		return c.fail(err)
	}
	if err := control.CheckSecretValue(v); err != nil {
		return c.fail(err)
	}
	if len(v) > control.MaxSecretValue {
		return c.fail(fmt.Errorf("secret value is longer than %d bytes", control.MaxSecretValue))
	}
	args := []string{"secret-set", name}
	if replace {
		args = append(args, "replace")
	}
	return c.callAdmin(sock, args, []byte(v+"\n"), "secret %s saved; live", name)
}

// callAdmin sends one admin request and reports done or the error line.
func (c *cli) callAdmin(sock string, args []string, body []byte, format string, a ...any) int {
	code, errLine := control.CallBody(sock, args, body, io.Discard)
	if code != control.ExitOK {
		fmt.Fprintf(c.e.stderr, "credenza: %s\n", errLine)
		return exitErr
	}
	return c.done(format, a...)
}

func (c *cli) secretRm(args []string) int {
	cmd := newCommand("secret rm", "credenza secret rm [-dir <dir>] <name>")
	if code, ok := c.parse(cmd, args, 1); !ok {
		return code
	}
	name, code, ok := c.secretName(cmd)
	if !ok {
		return code
	}
	if sock := adminSocket(*cmd.dir); control.Up(sock) {
		return c.callAdmin(sock, []string{"secret-rm", name}, []byte{}, "secret %s removed; live", name)
	}
	err := c.edit(*cmd.dir, "passphrase: ", func(d *store.Data, pass string) (string, error) {
		if _, ok := d.Secrets[name]; !ok {
			return "", fmt.Errorf("secret %s not found", name)
		}
		delete(d.Secrets, name)
		return pass, nil
	})
	if err != nil {
		return c.fail(err)
	}
	return c.done("secret %s removed; used at next serve start", name)
}

func (c *cli) secretList(args []string) int {
	cmd := newCommand("secret list", "credenza secret list [-dir <dir>]")
	if code, ok := c.parse(cmd, args, 0); !ok {
		return code
	}
	path, err := storePath(*cmd.dir)
	if err != nil {
		return c.fail(err)
	}
	d, _, err := c.unlock(path, "passphrase: ")
	if err != nil {
		return c.fail(err)
	}
	names := make([]string, 0, len(d.Secrets))
	for name := range d.Secrets {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		fmt.Fprintln(c.e.stdout, name)
	}
	return exitOK
}

func (c *cli) ca(args []string) int {
	const syntax = "credenza ca init [-dir <dir>] [-force] [-name <cn>] (-domains d1,d2 | -unconstrained)"
	if len(args) == 0 {
		return usage(c.e, "missing ca command", syntax)
	}
	if args[0] != "init" {
		return usage(c.e, "unknown ca command", syntax)
	}
	return c.caInit(args[1:], syntax)
}

func (c *cli) caInit(args []string, syntax string) int {
	cmd := newCommand("ca init", syntax)
	force := cmd.fs.Bool("force", false, "replace an existing CA")
	domainList := cmd.fs.String("domains", "", "comma-separated DNS name constraints")
	unconstrained := cmd.fs.Bool("unconstrained", false, "create a CA without name constraints")
	name := cmd.fs.String("name", ca.DefaultName, "CA certificate common name")
	if code, ok := c.parse(cmd, args, 0); !ok {
		return code
	}
	domainsSet := false
	cmd.fs.Visit(func(f *flag.Flag) { domainsSet = domainsSet || f.Name == "domains" })
	if domainsSet == *unconstrained {
		return usage(c.e, "ca init needs exactly one of -domains or -unconstrained", syntax)
	}
	if err := ca.ValidName(*name); err != nil {
		return usage(c.e, err.Error(), syntax)
	}
	var domains []string // nil only with -unconstrained
	if domainsSet {
		var err error
		if domains, err = parseDomains(*domainList); err != nil {
			return usage(c.e, err.Error(), syntax)
		}
	}
	err := c.edit(*cmd.dir, "passphrase: ", func(d *store.Data, pass string) (string, error) {
		if d.CA != nil && !*force {
			return "", errors.New("CA already exists; use -force to replace it")
		}
		certPEM, keyPEM, err := ca.New(*name, domains, c.e.now())
		if err != nil {
			return "", err
		}
		d.CA = &store.CA{CertPEM: string(certPEM), KeyPEM: string(keyPEM)}
		return pass, nil
	})
	if err != nil {
		return c.fail(err)
	}
	return c.done("CA created; export it with credenza ca-cert and rebuild every image")
}

// parseDomains splits a -domains value. ca.New checks neither DNS syntax
// nor duplicates, so both are checked here.
func parseDomains(list string) ([]string, error) {
	domains := strings.Split(list, ",")
	for i, d := range domains {
		if !policy.ValidHost(d) {
			return nil, fmt.Errorf("invalid CA domain %q (want a lowercase DNS name with a dot)", d)
		}
		if slices.Contains(domains[:i], d) {
			return nil, fmt.Errorf("duplicate CA domain %q", d)
		}
	}
	return domains, nil
}

func (c *cli) caCert(args []string) int {
	cmd := newCommand("ca-cert", "credenza ca-cert [-dir <dir>]")
	if code, ok := c.parse(cmd, args, 0); !ok {
		return code
	}
	path, err := storePath(*cmd.dir)
	if err != nil {
		return c.fail(err)
	}
	d, _, err := c.unlock(path, "passphrase: ")
	if err != nil {
		return c.fail(err)
	}
	if d.CA == nil {
		return c.fail(errors.New("no CA in store; run credenza ca init"))
	}
	// Load checks that the certificate is a CA and matches its key, and
	// keeps only the first PEM block.
	loaded, err := ca.Load([]byte(d.CA.CertPEM), []byte(d.CA.KeyPEM), c.e.now)
	if err != nil {
		return c.fail(err)
	}
	c.e.stdout.Write(loaded.CertPEM())
	return exitOK
}

func (c *cli) passwd(args []string) int {
	cmd := newCommand("passwd", "credenza passwd [-dir <dir>]")
	if code, ok := c.parse(cmd, args, 0); !ok {
		return code
	}
	err := c.edit(*cmd.dir, "old passphrase: ", func(*store.Data, string) (string, error) {
		return c.newPassphrase("new passphrase: ", "repeat new passphrase: ")
	})
	if err != nil {
		return c.fail(err)
	}
	return c.done("passphrase changed")
}

func (c *cli) policy(args []string) int {
	const syntax = "credenza policy check [-dir <dir>]"
	if len(args) == 0 {
		return usage(c.e, "missing policy command", syntax)
	}
	if args[0] != "check" {
		return usage(c.e, "unknown policy command", syntax)
	}
	cmd := newCommand("policy check", syntax)
	if code, ok := c.parse(cmd, args[1:], 0); !ok {
		return code
	}
	p, err := policy.Load(filepath.Join(*cmd.dir, "policy.json"))
	if err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.e.stdout, "policy ok: %d project(s)\n", len(p.Projects))
	return exitOK
}

func (c *cli) version(args []string) int {
	cmd := newCommand("version", "credenza version")
	if code, ok := c.parse(cmd, args, 0); !ok {
		return code
	}
	fmt.Fprintln(c.e.stdout, version)
	return exitOK
}
