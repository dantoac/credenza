// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dantoac/credenza/internal/audit"
	"github.com/dantoac/credenza/internal/ca"
	"github.com/dantoac/credenza/internal/control"
	"github.com/dantoac/credenza/internal/policy"
	"github.com/dantoac/credenza/internal/proxy"
	"github.com/dantoac/credenza/internal/store"
	"github.com/dantoac/credenza/internal/token"
)

const (
	passphraseAttempts = 3
	// pruneEvery bounds how long a request in flight outlives its
	// token's lease when nobody renews it.
	pruneEvery = 5 * time.Second
	// spaceEvery is the free-space check's interval (runbook R11).
	spaceEvery        = time.Minute
	defaultMaxSession = control.DefaultMaxSession
	minMaxSession     = time.Minute
	maxMaxSession     = 720 * time.Hour
)

// upstreamForTest replaces the proxy's upstream transport in tests; nil
// in production.
var upstreamForTest http.RoundTripper

func (c *cli) serve(args []string) int {
	cmd := newCommand("serve", "credenza serve [-dir <dir>] [-listen <addr>] [-max-session <dur>] -clients <cidr,...>")
	listen := cmd.fs.String("listen", ":8888", "proxy listen address")
	clientList := cmd.fs.String("clients", "", "comma-separated client CIDRs")
	maxSessionText := cmd.fs.String("max-session", defaultMaxSession.String(), "absolute lease limit per task, 1m to 720h")
	if code, ok := c.parse(cmd, args, 0); !ok {
		return code
	}
	maxSession, err := time.ParseDuration(*maxSessionText)
	if err != nil || maxSession < minMaxSession || maxSession > maxMaxSession {
		return usage(c.e, "invalid -max-session (want a duration from 1m to 720h, such as 24h)", cmd.syntax)
	}
	clients, err := parseClients(*clientList)
	if err != nil {
		return usage(c.e, err.Error(), cmd.syntax)
	}
	// Here, not after the slow unlock.
	if _, _, err := net.SplitHostPort(*listen); err != nil {
		return usage(c.e, "invalid -listen address (want host:port or :port)", cmd.syntax)
	}
	// Before the passphrase exists in memory.
	if code, ok := c.hardened(); !ok {
		return code
	}
	dir := *cmd.dir
	// The state dir is usually a separate filesystem's mount point (a USB
	// stick on the reference deployment). Nothing is created before this
	// check, so an unmounted one leaves the root filesystem untouched.
	storeFile := filepath.Join(dir, "store.enc")
	if _, err := os.Stat(storeFile); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return c.fail(fmt.Errorf("store not found at %s (is its filesystem mounted?)", storeFile))
		}
		return c.fail(err)
	}
	d, pass, err := c.unlockServe(storeFile)
	if err != nil {
		return c.fail(err)
	}
	if d.CA == nil {
		return c.fail(errors.New("no CA in store; run credenza ca init"))
	}
	authority, err := ca.Load([]byte(d.CA.CertPEM), []byte(d.CA.KeyPEM), c.e.now)
	if err != nil {
		return c.fail(err)
	}
	policyFile := filepath.Join(dir, "policy.json")
	if err := checkPolicy(policyFile, d, authority); err != nil {
		return c.fail(err)
	}
	auditPath := filepath.Join(dir, "audit.log")
	auditLog, err := audit.Open(auditPath)
	if err != nil {
		return c.fail(err)
	}
	// One logger for every line from here on, so writes to stderr from
	// the listeners' goroutines are serialized.
	errLog := log.New(c.e.stderr, "", 0)
	warnNotAppendOnly(errLog, auditPath)
	socket := filepath.Join(dir, "run", "broker.sock")
	adminSocket := filepath.Join(dir, "run", "admin.sock")
	ctlLn, adminLn, proxyLn, err := c.listen(storeFile, socket, adminSocket, *listen)
	if err != nil {
		auditLog.Close()
		return c.fail(err)
	}
	tokens := token.NewRegistry(c.e.now)
	secrets := newLiveSecrets(storeFile, pass, d.Secrets)
	svc := &control.Service{
		Policy: func() (*policy.Policy, error) { return policy.Load(policyFile) },
		HasSecret: func(name string) bool {
			_, ok := secrets.Get(name)
			return ok
		},
		CheckHost:    authority.CheckHost,
		Tokens:       tokens,
		Audit:        auditLog,
		MaxSession:   maxSession,
		SetSecret:    secrets.Set,
		RemoveSecret: secrets.Remove,
		LoadPolicy: func(body []byte) error {
			return loadPolicy(policyFile, body, func(name string) bool {
				_, ok := secrets.Get(name)
				return ok
			}, authority.CheckHost)
		},
	}
	addr := proxyLn.Addr().String()
	handler := proxy.New(proxy.Config{
		CA:       authority,
		Tokens:   tokens,
		Secret:   secrets.Get,
		Audit:    auditLog,
		Clients:  clients,
		Upstream: upstreamForTest,
		ErrorLog: errLog,
		Now:      c.e.now,
	})
	srv := proxy.NewServer(addr, handler, errLog)

	failed := make(chan error, 3)
	var wg sync.WaitGroup
	wg.Go(func() {
		if err := control.Serve(ctlLn, svc); err != nil {
			failed <- fmt.Errorf("control socket: %w", err)
		}
	})
	wg.Go(func() {
		if err := control.ServeAdmin(adminLn, svc); err != nil {
			failed <- fmt.Errorf("admin socket: %w", err)
		}
	})
	wg.Go(func() {
		if err := srv.Serve(handler.Listener(proxyLn)); !errors.Is(err, http.ErrServerClosed) {
			failed <- fmt.Errorf("proxy: %w", err)
		}
	})
	errLog.Printf("credenza: serving proxy on %s, control on %s, admin on %s", addr, socket, adminSocket)
	if c.e.ready != nil {
		c.e.ready(addr, socket)
	}

	prune := time.NewTicker(pruneEvery)
	defer prune.Stop()
	spaceTick := time.NewTicker(spaceEvery)
	defer spaceTick.Stop()
	var space spaceWarner
	var serveErr error
wait:
	for {
		select {
		case <-c.ctx.Done():
			break wait
		case serveErr = <-failed:
			break wait
		case <-prune.C:
			tokens.Prune()
		case <-spaceTick.C:
			space.check(errLog, auditPath, c.e.now())
		}
	}
	// Closing the Unix listener removes the socket file. Hijacked tunnels
	// are not tracked by Close; their audit writes fail closed once the
	// log is closed, and process exit ends them.
	ctlLn.Close()
	adminLn.Close()
	srv.Close()
	wg.Wait()
	// control.Serve and ServeAdmin have returned, so no mint or secret
	// verb is writing to the log.
	if err := auditLog.Close(); err != nil && serveErr == nil {
		serveErr = fmt.Errorf("close audit log: %w", err)
	}
	if serveErr != nil {
		return c.fail(serveErr)
	}
	return exitOK
}

// parseClients parses the -clients list. It must name at least one prefix:
// an empty list would deny every client.
func parseClients(list string) ([]netip.Prefix, error) {
	if list == "" {
		return nil, errors.New("-clients is required")
	}
	var clients []netip.Prefix
	for s := range strings.SplitSeq(list, ",") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("invalid -clients entry %q (want a CIDR such as 192.168.1.0/24)", s)
		}
		clients = append(clients, p)
	}
	return clients, nil
}

// unlockServe reads the passphrase up to passphraseAttempts times and
// returns the store and the passphrase that opened it. An interrupt at
// the prompt or during the key derivation stops at once.
func (c *cli) unlockServe(path string) (*store.Data, []byte, error) {
	for attempt := 1; ; attempt++ {
		if c.ctx.Err() != nil {
			return nil, nil, errInterrupted
		}
		pass, err := c.prompt("passphrase: ")
		if err != nil {
			return nil, nil, err
		}
		d, err := store.Load(path, pass)
		if c.ctx.Err() != nil {
			return nil, nil, errInterrupted
		}
		if err == nil {
			return d, []byte(pass), nil
		}
		if !errors.Is(err, store.ErrWrongPassphrase) || attempt == passphraseAttempts {
			return nil, nil, err
		}
	}
}

// checkPolicy loads the policy and checks that every grant's secret is in
// the store and that the CA can serve every host: a CA whose name
// constraints miss a policy host would make every client reject its
// leaves.
func checkPolicy(path string, d *store.Data, authority *ca.CA) error {
	p, err := policy.Load(path)
	if err != nil {
		return err
	}
	if err := enforceable(p, func(name string) bool {
		_, ok := d.Secrets[name]
		return ok
	}, authority.CheckHost); err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	return nil
}

// enforceable checks that every grant's secret exists and that the CA
// can serve every host of p.
func enforceable(p *policy.Policy, hasSecret func(string) bool, checkHost func(string) error) error {
	for _, grants := range p.Projects {
		for _, g := range grants {
			if !hasSecret(g.Secret) {
				return fmt.Errorf("secret %q not in store", g.Secret)
			}
		}
	}
	for _, host := range p.Hosts() {
		if err := checkHost(host); err != nil {
			return fmt.Errorf("host %q not permitted by the CA: %v", host, err)
		}
	}
	return nil
}

// loadPolicy is policy-load: it parses body with the rules of
// policy.Parse, checks it like serve's start does against the live
// secrets, and replaces the file at path with body (writeAtomic). A
// refused body wraps control.ErrInvalidPolicy and leaves the file as it
// was.
func loadPolicy(path string, body []byte, hasSecret func(string) bool, checkHost func(string) error) error {
	p, err := policy.Parse(body)
	if err == nil {
		err = enforceable(p, hasSecret, checkHost)
	}
	if err != nil {
		// policy.Parse errors start with "policy: ".
		return fmt.Errorf("%w: %s", control.ErrInvalidPolicy, strings.TrimPrefix(err.Error(), "policy: "))
	}
	if err := writeAtomic(path, body, 0o644); err != nil {
		return fmt.Errorf("write policy: %w", err)
	}
	return nil
}

// writeAtomic replaces path with b: a temp file in the same directory,
// written, chmod'ed to mode, synced and renamed over path, then the
// directory synced. A reader sees the old file or the new one, never a
// part; an error before the rename removes the temp file and leaves path
// unchanged. After the rename the new file is in force, so a failed
// directory sync is not an error: the file may only be lost by a crash
// before the directory reaches the disk. The file is owned by the
// running user, which policy.Load requires.
func writeAtomic(path string, b []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err = f.Write(b); err != nil {
		return err
	}
	// Chmod after writing so the umask does not change mode.
	if err = f.Chmod(mode); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	// The rename is done and the new file is in force: report success
	// whatever the directory sync does.
	if d, derr := os.Open(dir); derr == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// listen opens the control and admin sockets and the proxy listener.
// The store lock covers the sockets' stale checks, so two serves cannot
// both decide a socket is stale; a running serve is refused by that
// check.
func (c *cli) listen(storeFile, socket, adminSocket, addr string) (ctlLn, adminLn, proxyLn net.Listener, err error) {
	// A Ctrl-C after the last prompt still stops before listening.
	if c.ctx.Err() != nil {
		return nil, nil, nil, errInterrupted
	}
	unlock, err := store.Lock(storeFile)
	if err != nil {
		return nil, nil, nil, err
	}
	defer unlock()
	ctlLn, err = control.Listen(socket)
	if err != nil {
		return nil, nil, nil, err
	}
	adminLn, err = control.Listen(adminSocket)
	if err != nil {
		ctlLn.Close()
		return nil, nil, nil, err
	}
	proxyLn, err = net.Listen("tcp", addr)
	if err != nil {
		ctlLn.Close()
		adminLn.Close()
		return nil, nil, nil, err
	}
	return ctlLn, adminLn, proxyLn, nil
}
