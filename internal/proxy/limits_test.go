// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: GPL-3.0-or-later

package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dantoac/credenza/internal/policy"
)

// TestProxyListenerClosesNonClients: a connection from an address outside
// Clients is closed at accept, before any byte is read, and counted.
func TestProxyListenerClosesNonClients(t *testing.T) {
	h := newHarness(t, func(cfg *Config) {
		cfg.Clients = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	})
	conn, err := net.Dial("tcp", h.broker.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	b, err := io.ReadAll(conn)
	var ne net.Error
	if len(b) != 0 || errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("read %q, %v; want the connection closed with no answer", b, err)
	}
	if events := h.auditEvents(); len(events) != 0 {
		t.Errorf("audit events %+v, want none", events)
	}
	if lines := h.unauditedLines(); len(lines) != 1 || !strings.Contains(lines[0], "(client 1, not-connect 0, conn-limit 0, rate-limited 0)") {
		t.Errorf("ErrorLog lines %q", lines)
	}
}

// fakeConn is a net.Conn with a chosen remote address that records Close.
type fakeConn struct {
	net.Conn
	remote net.Addr
	mu     sync.Mutex
	closed int
}

func newFakeConn(addr string) *fakeConn {
	c, _ := net.Pipe()
	return &fakeConn{Conn: c, remote: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(addr))}
}

func (c *fakeConn) RemoteAddr() net.Addr { return c.remote }

func (c *fakeConn) Close() error {
	c.mu.Lock()
	c.closed++
	c.mu.Unlock()
	return c.Conn.Close()
}

func (c *fakeConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed > 0
}

// fakeListener hands out the conns sent on its channel.
type fakeListener struct{ conns chan net.Conn }

func (l *fakeListener) Accept() (net.Conn, error) {
	c, ok := <-l.conns
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}

func (l *fakeListener) Close() error   { return nil }
func (l *fakeListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestProxyListenerConnLimits(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	errLog := &lockedBuffer{}
	p := New(Config{
		Clients:       []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		ErrorLog:      log.New(errLog, "", 0),
		Now:           clock.Now,
		MaxConns:      3,
		MaxConnsPerIP: 2,
	})
	inner := &fakeListener{conns: make(chan net.Conn, 16)}
	ln := p.Listener(inner)
	push := func(addr string) *fakeConn {
		c := newFakeConn(addr)
		inner.conns <- c
		return c
	}
	accept := func(want *fakeConn) net.Conn {
		t.Helper()
		got, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		if got.RemoteAddr() != want.remote {
			t.Fatalf("Accept returned %v, want %v", got.RemoteAddr(), want.remote)
		}
		return got
	}
	a1 := push("192.168.1.10:1001")
	acceptedA1 := accept(a1)
	accept(push("192.168.1.10:1002"))
	a3 := push("192.168.1.10:1003") // third from one address
	b1 := push("192.168.1.20:1001")
	accept(b1)
	if !a3.isClosed() {
		t.Error("third connection from one address was not closed")
	}
	// The total is full: Accept closes these and blocks until a slot frees.
	got := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		got <- c
	}()
	refused := map[string]*fakeConn{
		"c1": push("192.168.1.30:1001"),      // over the total
		"x1": push("10.9.9.9:1001"),          // not a client
		"x2": push("[::ffff:10.9.9.9]:1002"), // not a client, mapped
	}
	deadline := time.Now().Add(2 * time.Second)
	for name, c := range refused {
		for !c.isClosed() {
			if time.Now().After(deadline) {
				t.Fatalf("%s was not closed at accept", name)
			}
			time.Sleep(time.Millisecond)
		}
	}
	acceptedA1.Close()
	acceptedA1.Close() // a second Close must not free a second slot
	a4 := push("192.168.1.10:1004")
	if c := <-got; c == nil || c.RemoteAddr() != a4.remote {
		t.Fatalf("Accept after a slot freed returned %v, want a4", c)
	}
	if !a1.isClosed() {
		t.Error("Close of the accepted conn did not reach the inner conn")
	}
	d1 := push("192.168.1.40:1001") // total is full again: a1 freed one slot, a4 took it
	clock.Advance(61 * time.Second)
	push("10.9.9.9:1003")
	close(inner.conns)
	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after the inner listener closed: %v", err)
	}
	if !d1.isClosed() {
		t.Error("connection over the total after a reuse was not closed")
	}
	var lines []string
	for line := range strings.SplitSeq(errLog.String(), "\n") {
		if strings.Contains(line, "unaudited denials") {
			lines = append(lines, line)
		}
	}
	want := []string{
		"1 unaudited denials (client 0, not-connect 0, conn-limit 1, rate-limited 0)",
		"4 unaudited denials (client 2, not-connect 0, conn-limit 2, rate-limited 0)",
	}
	if len(lines) != len(want) {
		t.Fatalf("ErrorLog lines %q", lines)
	}
	for i := range want {
		if !strings.Contains(lines[i], want[i]) {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestProxyListenerDefaults(t *testing.T) {
	p := New(Config{ErrorLog: log.New(io.Discard, "", 0)})
	if p.cfg.MaxConns != 256 || p.cfg.MaxConnsPerIP != 32 || p.cfg.DenyBurst != 200 || p.limiter.rate != 1 {
		t.Errorf("defaults MaxConns %d MaxConnsPerIP %d DenyBurst %d rate %v, want 256 32 200 1",
			p.cfg.MaxConns, p.cfg.MaxConnsPerIP, p.cfg.DenyBurst, p.limiter.rate)
	}
}

func TestDenyLimiter(t *testing.T) {
	t0 := time.Now()
	l := newDenyLimiter(20, 3)
	allow := func(key string, at time.Time) bool {
		ok, _ := l.allow(key, at)
		return ok
	}
	for i := range 3 {
		if !allow("a", t0) {
			t.Fatalf("deny %d of the burst refused", i)
		}
	}
	if ok, first := l.allow("a", t0); ok || !first {
		t.Fatalf("first deny beyond the burst: ok %v first %v, want false true", ok, first)
	}
	if ok, first := l.allow("a", t0); ok || first {
		t.Fatalf("second deny beyond the burst: ok %v first %v, want false false", ok, first)
	}
	if !allow("b", t0) {
		t.Fatal("another client shares the bucket")
	}
	if !allow("a", t0.Add(50*time.Millisecond)) {
		t.Fatal("50ms at 20/s must refill one")
	}
	// Not refilled to the burst: the episode goes on, no new first.
	if ok, first := l.allow("a", t0.Add(50*time.Millisecond)); ok || first {
		t.Fatalf("refusal in the same episode: ok %v first %v", ok, first)
	}
	// A long pause refills to the burst, not beyond, and ends the episode.
	later := t0.Add(time.Hour)
	for i := range 3 {
		if !allow("a", later) {
			t.Fatalf("deny %d after the pause refused", i)
		}
	}
	if ok, first := l.allow("a", later); ok || !first {
		t.Fatalf("refusal after the pause: ok %v first %v, want false true", ok, first)
	}
	// A clock stepped back does not refill.
	if allow("a", t0) {
		t.Fatal("clock stepped back refilled the bucket")
	}
}

func TestDenyLimiterForgetsFullBuckets(t *testing.T) {
	t0 := time.Now()
	l := newDenyLimiter(20, 3)
	for i := range maxDenyBuckets + 10 {
		l.allow(fmt.Sprintf("10.0.%d.%d", i/256, i%256), t0)
	}
	l.allow("x", t0.Add(time.Hour))
	if n := len(l.buckets); n > maxDenyBuckets {
		t.Fatalf("limiter keeps %d buckets, want at most %d", n, maxDenyBuckets)
	}
}

// TestProxyAuditedDeniesRateLimited: audited denies beyond the client's
// burst are answered as usual but counted, not audited.
func TestProxyAuditedDeniesRateLimited(t *testing.T) {
	h := newHarness(t, func(cfg *Config) { cfg.DenyBurst = 3 })
	noToken := func() {
		t.Helper()
		resp, _ := h.do(newRequest(t, "GET", "https://api.github.com/repos/example/app/pulls", ""))
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401", resp.StatusCode)
		}
	}
	for range 5 {
		noToken()
	}
	// The burst, then one rate-limited line that marks the episode.
	events := h.auditEvents()
	if len(events) != 4 {
		t.Fatalf("audit has %d events, want 4 (the burst and one rate-limited)", len(events))
	}
	if e := events[3]; e.Reason != "rate-limited" || e.Decision != "deny" || e.Client == "" || e.Host != "api.github.com" {
		t.Fatalf("episode event %+v", e)
	}
	h.clock.Advance(time.Second)
	noToken()
	if n := len(h.auditEvents()); n != 5 {
		t.Fatalf("audit has %d events after a refill, want 5", n)
	}
	h.clock.Advance(61 * time.Second)
	_, _, resp := h.rawConnect("api.github.com:80", "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403", resp.StatusCode)
	}
	if n := len(h.auditEvents()); n != 6 {
		t.Fatalf("audit has %d events, want 6 (the port deny after a full refill)", n)
	}
	conn, err := net.Dial("tcp", h.broker.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET http://api.github.com/ HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
	if resp, err := http.ReadResponse(bufio.NewReader(conn), nil); err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("not-connect: %v", err)
	}
	// The episode's first deny is audited, so only the 5th is counted.
	lines := h.unauditedLines()
	want := []string{
		"1 unaudited denials (client 0, not-connect 0, conn-limit 0, rate-limited 1)",
		"1 unaudited denials (client 0, not-connect 1, conn-limit 0, rate-limited 0)",
	}
	if len(lines) != len(want) {
		t.Fatalf("ErrorLog lines %q", lines)
	}
	for i := range want {
		if !strings.Contains(lines[i], want[i]) {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

// TestProxyClosesTunnelAfterDenies: the 20th denied request on one
// tunnel is answered with Connection: close and the tunnel ends.
func TestProxyClosesTunnelAfterDenies(t *testing.T) {
	h := newHarness(t)
	tc, err := h.tunnel("api.github.com", "api.github.com")
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	br := bufio.NewReader(tc)
	for i := 1; i <= maxTunnelDenies; i++ {
		io.WriteString(tc, "GET /repos/example/app/pulls HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("request %d: status %d", i, resp.StatusCode)
		}
		if resp.Close != (i == maxTunnelDenies) {
			t.Fatalf("request %d: Connection close %v", i, resp.Close)
		}
	}
	tc.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := br.ReadByte(); err != io.EOF {
		t.Fatalf("read after the last deny: %v, want EOF", err)
	}
	if maxTunnelDenies != 20 {
		t.Errorf("maxTunnelDenies = %d, want 20", maxTunnelDenies)
	}
}

// streamUntilCut mints a token for task with ttl, starts a streamed
// response and returns once the first event arrived; the returned channel
// yields the error that ended the client's body read.
func streamUntilCut(t *testing.T, h *harness, task string, ttl time.Duration) (<-chan error, <-chan struct{}) {
	t.Helper()
	var grants []policy.Grant
	for _, g := range h.grants {
		g.TTL = ttl
		grants = append(grants, g)
	}
	// The registry's clock was frozen at harness setup: bring it to now so
	// the TTL counts from here.
	h.clock.Advance(time.Since(h.clock.Now()))
	issued, err := h.tokens.Mint(task, "example/app", grants)
	if err != nil {
		t.Fatal(err)
	}
	var tok string
	for _, is := range issued {
		if is.Env == "CLAUDE_CODE_OAUTH_TOKEN" {
			tok = is.Token
		}
	}
	upstreamDone := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	h.setRespond(func(w http.ResponseWriter, r *http.Request) {
		defer close(upstreamDone)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "event: ping\n\n")
		http.NewResponseController(w).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	resp, err := h.client.Do(newRequest(t, "POST", "https://api.anthropic.com/v1/messages", "Bearer "+tok))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	br := bufio.NewReader(resp.Body)
	if line, err := br.ReadString('\n'); err != nil || line != "event: ping\n" {
		t.Fatalf("first line %q, %v", line, err)
	}
	ended := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, br)
		ended <- err
	}()
	return ended, upstreamDone
}

func waitCut(t *testing.T, ended <-chan error, upstreamDone <-chan struct{}) {
	t.Helper()
	select {
	case <-ended:
	case <-time.After(3 * time.Second):
		t.Fatal("stream still open")
	}
	select {
	case <-upstreamDone:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream request not cancelled")
	}
}

// syncClock brings the registry's frozen clock to the real time.
func syncClock(h *harness) {
	h.clock.Advance(time.Since(h.clock.Now()))
}

// stillOpen fails when the stream ends within d.
func stillOpen(t *testing.T, ended <-chan error, d time.Duration, when string) {
	t.Helper()
	select {
	case err := <-ended:
		t.Fatalf("stream ended %s: %v", when, err)
	case <-time.After(d):
	}
}

// TestProxyCutsStreamAtExpiry: without a renew, an allowed request holds
// its decision until the token expires, and the expired token is dropped
// by the registry's Prune, which serve runs every pruneEvery. The cut
// comes from that Prune, not from a deadline fixed at request start.
func TestProxyCutsStreamAtExpiry(t *testing.T) {
	h := newHarness(t)
	const ttl = time.Second
	ended, upstreamDone := streamUntilCut(t, h, "T2", ttl)
	minted := h.clock.Now() // frozen since the mint
	stillOpen(t, ended, 300*time.Millisecond, "before the token expired")
	syncClock(h)
	if n := h.tokens.Prune(); n != 0 {
		t.Fatalf("Prune before expiry dropped %d tokens", n)
	}
	// Past the expiry and no Prune yet: the stream is still open.
	time.Sleep(time.Until(minted.Add(ttl + 100*time.Millisecond)))
	stillOpen(t, ended, 100*time.Millisecond, "at expiry before a Prune")
	syncClock(h)
	if n := h.tokens.Prune(); n != len(h.grants) {
		t.Fatalf("Prune after expiry dropped %d tokens, want %d", n, len(h.grants))
	}
	waitCut(t, ended, upstreamDone)
}

// TestRenewExtendsStream: a stream that crosses the token's first expiry
// survives when the lease was renewed before it, and is cut on revoke.
func TestRenewExtendsStream(t *testing.T) {
	h := newHarness(t)
	const ttl = time.Second
	ended, upstreamDone := streamUntilCut(t, h, "T2", ttl)
	minted := h.clock.Now() // frozen since the mint
	syncClock(h)
	if live, err := h.tokens.Renew("T2", h.grants, 24*time.Hour); err != nil || live != len(h.grants) {
		t.Fatalf("Renew = %d, %v", live, err)
	}
	stillOpen(t, ended, time.Until(minted.Add(ttl+300*time.Millisecond)), "after the first expiry despite the renew")
	syncClock(h)
	if n := h.tokens.Prune(); n != 0 {
		t.Fatalf("Prune after renew dropped %d tokens", n)
	}
	stillOpen(t, ended, 100*time.Millisecond, "after a Prune of a renewed token")
	h.tokens.Revoke("T2")
	waitCut(t, ended, upstreamDone)
}

// TestProxyCutsStreamOnRevoke: revoke ends the task's requests in flight.
func TestProxyCutsStreamOnRevoke(t *testing.T) {
	h := newHarness(t)
	ended, upstreamDone := streamUntilCut(t, h, "T2", time.Hour)
	select {
	case err := <-ended:
		t.Fatalf("stream ended before revoke: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	h.tokens.Revoke("T2")
	waitCut(t, ended, upstreamDone)
}
