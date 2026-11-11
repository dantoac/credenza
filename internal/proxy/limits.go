// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: GPL-3.0-or-later

package proxy

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	defaultMaxConns      = 256
	defaultMaxConnsPerIP = 32
	// Audited denies per client IP: a sustained rate and a burst. At
	// 1/s a looping client adds at most about 60 MB a day of deny lines
	// (up to about 700 bytes each), not gigabytes.
	denyRate         = 1 // per second
	defaultDenyBurst = 200
	// maxDenyBuckets bounds the limiter's memory; full buckets are dropped
	// first.
	maxDenyBuckets = 4096
	// maxTunnelDenies closes a tunnel after this many denied requests.
	maxTunnelDenies = 20
)

// Listener wraps the proxy's TCP listener. Accept closes a connection at
// once, before reading a byte, when its address is outside Clients
// (counted as a client deny) or when it would pass MaxConns in total or
// MaxConnsPerIP from one address (counted as conn-limit). A hijacked
// tunnel holds its slot until it closes.
func (h *Handler) Listener(ln net.Listener) net.Listener {
	return &limitListener{Listener: ln, h: h, perIP: map[netip.Addr]int{}}
}

type limitListener struct {
	net.Listener
	h *Handler

	mu    sync.Mutex
	total int
	perIP map[netip.Addr]int
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		addr, ok := clientAddr(c.RemoteAddr().String(), l.h.cfg.Clients)
		if !ok {
			l.h.count(reasonClient)
			c.Close()
			continue
		}
		if !l.acquire(addr) {
			l.h.count(reasonConnLimit)
			c.Close()
			continue
		}
		return &limitConn{Conn: c, release: func() { l.release(addr) }}, nil
	}
}

func (l *limitListener) acquire(addr netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.h.cfg.MaxConns || l.perIP[addr] >= l.h.cfg.MaxConnsPerIP {
		return false
	}
	l.total++
	l.perIP[addr]++
	return true
}

func (l *limitListener) release(addr netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	if l.perIP[addr]--; l.perIP[addr] <= 0 {
		delete(l.perIP, addr)
	}
}

// limitConn frees its listener slot on the first Close.
type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// CloseWrite keeps the half-close net/http uses before closing a
// connection it answered with Connection: close.
func (c *limitConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// denyLimiter is a token bucket per client for audited denies.
type denyLimiter struct {
	rate    float64 // tokens per second
	burst   float64
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens  float64
	last    time.Time
	limited bool // refused since the bucket was last full
}

func newDenyLimiter(rate, burst int) *denyLimiter {
	return &denyLimiter{rate: float64(rate), burst: float64(burst), buckets: map[string]*bucket{}}
}

// allow takes one token from client's bucket and reports whether there
// was one. first reports the first refusal since the bucket was last
// full, which starts an episode of refusals. A clock that steps back
// refills nothing.
func (l *denyLimiter) allow(client string, now time.Time) (ok, first bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, found := l.buckets[client]
	if !found {
		if len(l.buckets) >= maxDenyBuckets {
			l.dropFull(now)
			// Still full: many addresses denied within one refill
			// interval. Count rather than grow.
			if len(l.buckets) >= maxDenyBuckets {
				return false, false
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[client] = b
	}
	if d := now.Sub(b.last); d > 0 {
		b.tokens = min(l.burst, b.tokens+d.Seconds()*l.rate)
		b.last = now
	}
	if b.tokens >= l.burst {
		b.limited = false
	}
	if b.tokens < 1 {
		first = !b.limited
		b.limited = true
		return false, first
	}
	b.tokens--
	return true, false
}

// dropFull forgets the buckets that have refilled to the burst: a new
// bucket starts full, so forgetting them changes nothing. l.mu must be
// held.
func (l *denyLimiter) dropFull(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
}
