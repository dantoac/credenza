// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: Apache-2.0

// Package proxy is the broker's data plane: an HTTP proxy that accepts
// CONNECT from listed clients, intercepts the TLS tunnel with a leaf
// certificate from the credenza CA, and forwards each request upstream with
// the temporary token in its Authorization header replaced by the real
// secret, when the token's scope allows the host, method and path.
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dantoac/credenza/internal/audit"
	"github.com/dantoac/credenza/internal/ca"
	"github.com/dantoac/credenza/internal/policy"
	"github.com/dantoac/credenza/internal/token"
)

const (
	defaultHandshakeTimeout = 10 * time.Second
	maxHeaderBytes          = 32 << 10
	outerIdleTimeout        = 30 * time.Second
	unauditedReportEvery    = time.Minute
)

// Config is what the proxy needs from serve.
type Config struct {
	CA               *ca.CA
	Tokens           *token.Registry // the caller runs Tokens.Prune often: it ends the requests in flight of expired tokens
	Secret           func(name string) (string, bool)
	Audit            *audit.Log
	Clients          []netip.Prefix    // empty means every client is denied
	Upstream         http.RoundTripper // nil means NewUpstream()
	ErrorLog         *log.Logger       // operational log; never receives header values
	Now              func() time.Time  // nil means time.Now; drives the unaudited-deny rate limit
	HandshakeTimeout time.Duration     // 0 means 10s; tests lower it
	MaxConns         int               // 0 means 256: open connections, tunnels included
	MaxConnsPerIP    int               // 0 means 32: open connections from one client address
	DenyBurst        int               // 0 means 200: audited denies per client before the 1/s rate applies
}

// NewUpstream returns the transport the proxy forwards with: no proxy (the
// broker's own HTTPS_PROXY would loop), system roots, TLS 1.2 minimum.
func NewUpstream() *http.Transport {
	return &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		ExpectContinueTimeout: time.Second,
	}
}

// NewServer returns the outer proxy server. It has no WriteTimeout and no
// ReadTimeout: tunnels and streamed responses are long-lived. IdleTimeout
// bounds a keep-alive connection waiting for its next request; a hijacked
// tunnel is not affected.
func NewServer(addr string, h http.Handler, errLog *log.Logger) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       outerIdleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          errLog,
	}
}

// Deny reasons written to the audit log and to deny bodies.
const (
	reasonClient       = "client" // counted, not audited
	reasonNotConnect   = "not-connect"
	reasonConnLimit    = "conn-limit"   // counted at accept, never answered
	reasonRateLimited  = "rate-limited" // a deny over its client's rate: the first audited, the rest counted
	reasonPort         = "port"
	reasonHost         = "host"
	reasonTLS          = "tls"
	reasonHostMismatch = "host-mismatch"
	reasonUpgrade      = "upgrade"
	reasonNoToken      = "no-token"
	reasonToken        = "token"
	reasonPath         = "path"
	reasonScope        = "scope"
	reasonSecret       = "secret"
)

// Handler is the proxy: it serves CONNECT itself and denies every
// other method. Listener wraps its TCP listener.
type Handler struct {
	cfg Config
	rp  *httputil.ReverseProxy

	limiter   *denyLimiter
	mu        sync.Mutex
	unaudited unaudited
}

// unaudited counts the denies that write no audit event.
type unaudited struct {
	client, notConnect, connLimit, rateLimited int
	since                                      time.Time
	reported                                   bool
}

// New returns the proxy handler.
func New(cfg Config) *Handler {
	if cfg.Upstream == nil {
		cfg.Upstream = NewUpstream()
	}
	if cfg.ErrorLog == nil {
		cfg.ErrorLog = log.New(os.Stderr, "", log.LstdFlags)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = defaultHandshakeTimeout
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = defaultMaxConns
	}
	if cfg.MaxConnsPerIP <= 0 {
		cfg.MaxConnsPerIP = defaultMaxConnsPerIP
	}
	if cfg.DenyBurst <= 0 {
		cfg.DenyBurst = defaultDenyBurst
	}
	h := &Handler{cfg: cfg, limiter: newDenyLimiter(denyRate, cfg.DenyBurst)}
	h.rp = &httputil.ReverseProxy{
		Rewrite:        rewrite,
		FlushInterval:  -1,
		Transport:      cfg.Upstream,
		ErrorLog:       cfg.ErrorLog,
		ErrorHandler:   h.upstreamError,
		ModifyResponse: h.scrubResponse,
	}
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Every answer here is a deny: close the connection so a peer cannot
	// keep it open. Hijack ignores response headers.
	w.Header().Set("Connection", "close")
	client, ok := clientAddr(r.RemoteAddr, h.cfg.Clients)
	if !ok {
		h.countDeny(w, reasonClient)
		return
	}
	if r.Method != http.MethodConnect {
		h.countDeny(w, reasonNotConnect)
		return
	}
	ev := audit.Event{Event: "proxy", Method: r.Method, Client: client.String()}
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		host, port = r.Host, ""
	}
	host = strings.ToLower(host)
	ev.Host = host
	if port != "443" || !policy.ValidHost(host) {
		h.deny(w, ev, reasonPort)
		return
	}
	if !h.cfg.Tokens.HostAllowed(host) {
		h.deny(w, ev, reasonHost)
		return
	}
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		h.cfg.ErrorLog.Printf("credenza: proxy: hijack: %v", err)
		return
	}
	defer conn.Close()
	tc, err := h.handshake(r.Context(), conn, brw.Reader, host)
	if err != nil {
		h.audit(ev, reasonTLS)
		return
	}
	h.serveTunnel(tc, host, client)
}

// handshake answers the CONNECT and runs the TLS server handshake with a
// leaf for host, all under one deadline of HandshakeTimeout.
func (h *Handler) handshake(ctx context.Context, conn net.Conn, buffered *bufio.Reader, host string) (*tls.Conn, error) {
	if err := conn.SetDeadline(time.Now().Add(h.cfg.HandshakeTimeout)); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return nil, err
	}
	tc := tls.Server(&prereadConn{Conn: conn, r: buffered}, &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName != "" && !strings.EqualFold(hello.ServerName, host) {
				return nil, errors.New("SNI does not match the CONNECT host")
			}
			cert, err := h.cfg.CA.Leaf(host)
			if err != nil {
				h.cfg.ErrorLog.Printf("credenza: proxy: leaf for %s: %v", host, err)
			}
			return cert, err
		},
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return tc, nil
}

// serveTunnel serves the requests of one decrypted tunnel until it closes.
func (h *Handler) serveTunnel(tc *tls.Conn, host string, client netip.Addr) {
	ln := newOneConnListener(tc)
	srv := &http.Server{
		Handler:           &tunnel{h: h, host: host, client: client.String()},
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       5 * time.Minute,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          h.cfg.ErrorLog,
		ConnState: func(_ net.Conn, s http.ConnState) {
			if s == http.StateClosed || s == http.StateHijacked {
				ln.Close()
			}
		},
	}
	srv.Serve(ln)
}

// tunnel handles the requests inside one CONNECT tunnel to host. The
// server calls it for one request at a time.
type tunnel struct {
	h      *Handler
	host   string
	client string
	denies int
}

func (t *tunnel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := t.h
	ev := audit.Event{Event: "proxy", Host: t.host, Method: r.Method, Path: r.URL.Path, Client: t.client}
	if !strings.EqualFold(stripPort(r.Host), t.host) {
		t.deny(w, ev, reasonHostMismatch)
		return
	}
	if isUpgrade(r.Header) {
		t.deny(w, ev, reasonUpgrade)
		return
	}
	auths := r.Header.Values("Authorization")
	if len(auths) == 0 {
		w.Header().Set("WWW-Authenticate", `Basic realm="credenza"`)
		t.denyStatus(w, ev, reasonNoToken, http.StatusUnauthorized)
		return
	}
	if len(auths) > 1 {
		t.deny(w, ev, reasonToken)
		return
	}
	cred, ok := ParseAuthorization(auths[0])
	if !ok {
		t.deny(w, ev, reasonToken)
		return
	}
	scope, ok := h.cfg.Tokens.Lookup(cred.Token)
	if !ok {
		t.deny(w, ev, reasonToken)
		return
	}
	ev.Task, ev.Project, ev.Secret = scope.Task, scope.Project, scope.Secret
	cleanPath, ok := policy.CleanRequestPath(r.URL)
	if !ok {
		t.deny(w, ev, reasonPath)
		return
	}
	if !allows(scope.Rules, t.host, r.Method, cleanPath) {
		t.deny(w, ev, reasonScope)
		return
	}
	secret, ok := h.cfg.Secret(scope.Secret)
	if !ok || secret == "" {
		t.deny(w, ev, reasonSecret)
		return
	}
	ev.Decision = "allow"
	if err := h.cfg.Audit.Write(ev); err != nil {
		h.cfg.ErrorLog.Printf("credenza: proxy: audit log write failed, request not forwarded: %v", err)
		http.Error(w, "credenza: audit log unavailable", http.StatusServiceUnavailable)
		return
	}
	auth := cred.WithSecret(secret)
	_, authCred, _ := strings.Cut(auth, " ")
	fw := &forward{host: t.host, task: scope.Task, secret: secret, auth: auth, cred: authCred}
	// The allow holds while the token stays in the registry: Done closes
	// on revoke, when a renew drops the token and when Prune drops it
	// expired, so a renewed lease keeps a long stream open and a lapsed
	// one ends it within serve's prune interval. The inner server has no
	// timeouts, so without this a streamed response would outlive both.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	go func() {
		select {
		case <-scope.Done:
			cancel()
		case <-ctx.Done():
		}
	}()
	h.rp.ServeHTTP(w, r.WithContext(context.WithValue(ctx, forwardKey{}, fw)))
}

// deny answers 403 for a denied request inside the tunnel.
func (t *tunnel) deny(w http.ResponseWriter, ev audit.Event, reason string) {
	t.denyStatus(w, ev, reason, http.StatusForbidden)
}

// denyStatus audits a deny and answers status. The maxTunnelDenies-th
// deny on one tunnel also closes it, so a client looping on a denied
// request must reconnect, and the per-address connection limit applies.
func (t *tunnel) denyStatus(w http.ResponseWriter, ev audit.Event, reason string, status int) {
	t.h.audit(ev, reason)
	if t.denies++; t.denies >= maxTunnelDenies {
		w.Header().Set("Connection", "close")
	}
	http.Error(w, "credenza: denied ("+reason+")", status)
}

func allows(rules []policy.Rule, host, method, cleanPath string) bool {
	for _, rule := range rules {
		if rule.Allows(host, method, cleanPath) {
			return true
		}
	}
	return false
}

// forward is what the ReverseProxy hooks need about an allowed request.
type forward struct {
	host, task string
	secret     string // the real secret
	auth       string // the rewritten Authorization value
	cred       string // auth without its scheme: Basic holds the secret only in base64
}

type forwardKey struct{}

func forwardOf(ctx context.Context) *forward {
	fw, _ := ctx.Value(forwardKey{}).(*forward)
	return fw
}

// rewrite sends the request to the tunnel host with the real credential.
// The path is left as received, so the path checked is the path forwarded.
func rewrite(pr *httputil.ProxyRequest) {
	fw := forwardOf(pr.In.Context())
	pr.Out.URL.Scheme = "https"
	pr.Out.URL.Host = fw.host
	pr.Out.Host = fw.host
	pr.Out.Header.Set("Authorization", fw.auth)
}

// scrubResponse drops every response header and trailer whose value
// carries the real secret or the rewritten credential. Bodies are
// streamed, not scanned.
func (h *Handler) scrubResponse(resp *http.Response) error {
	fw := forwardOf(resp.Request.Context())
	if fw == nil {
		return nil
	}
	h.scrubHeader(resp.Header, fw)
	// The transport fills resp.Trailer when the body is closed, and
	// ReverseProxy copies it right after closing the body.
	resp.Body = &trailerScrubber{ReadCloser: resp.Body, close: func() { h.scrubHeader(resp.Trailer, fw) }}
	return nil
}

func (h *Handler) scrubHeader(hdr http.Header, fw *forward) {
	for name, vals := range hdr {
		for _, v := range vals {
			// cred is a substring of the rewritten Authorization value,
			// so this also catches an echo of the whole value.
			if strings.Contains(v, fw.secret) || strings.Contains(v, fw.cred) {
				delete(hdr, name)
				h.cfg.ErrorLog.Printf("credenza: proxy: dropped response header %s carrying a credential (task %s)", name, fw.task)
				break
			}
		}
	}
}

// trailerScrubber runs close after the body it wraps is closed.
type trailerScrubber struct {
	io.ReadCloser
	close func()
}

func (b *trailerScrubber) Close() error {
	err := b.ReadCloser.Close()
	b.close()
	return err
}

func (h *Handler) upstreamError(w http.ResponseWriter, r *http.Request, err error) {
	task := ""
	if fw := forwardOf(r.Context()); fw != nil {
		task = fw.task
	}
	h.cfg.ErrorLog.Printf("credenza: proxy: upstream error (task %s): %v", task, err)
	http.Error(w, "credenza: upstream error", http.StatusBadGateway)
}

// deny writes a deny event with reason and answers 403.
func (h *Handler) deny(w http.ResponseWriter, ev audit.Event, reason string) {
	h.audit(ev, reason)
	http.Error(w, "credenza: denied ("+reason+")", http.StatusForbidden)
}

// audit writes a deny event, or counts it when the client is over its
// rate of audited denies: a listed client looping on a denied request
// must not fill the audit log. The first deny over the rate is written
// with reason rate-limited instead of its own, so the log shows where an
// episode of counted denies starts. Allows are never limited. A failed
// deny write still denies.
func (h *Handler) audit(ev audit.Event, reason string) {
	if ok, first := h.limiter.allow(ev.Client, h.cfg.Now()); !ok {
		if !first {
			h.count(reasonRateLimited)
			return
		}
		reason = reasonRateLimited
	}
	ev.Decision, ev.Reason = "deny", reason
	if err := h.cfg.Audit.Write(ev); err != nil {
		h.cfg.ErrorLog.Printf("credenza: proxy: audit log write failed for a %s deny: %v", reason, err)
	}
}

// countDeny answers 403 without an audit event: anyone on the LAN can send
// these at line rate.
func (h *Handler) countDeny(w http.ResponseWriter, reason string) {
	h.count(reason)
	http.Error(w, "credenza: denied ("+reason+")", http.StatusForbidden)
}

// count records a deny that writes no audit event. It reports the counts
// to ErrorLog at most once a minute, the first one at once.
func (h *Handler) count(reason string) {
	now := h.cfg.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	u := &h.unaudited
	switch reason {
	case reasonClient:
		u.client++
	case reasonNotConnect:
		u.notConnect++
	case reasonConnLimit:
		u.connLimit++
	default:
		u.rateLimited++
	}
	if u.since.IsZero() {
		u.since = now
	}
	if !u.reported || now.Sub(u.since) >= unauditedReportEvery {
		h.cfg.ErrorLog.Printf("credenza: proxy: %d unaudited denials (client %d, not-connect %d, conn-limit %d, rate-limited %d) since %s",
			u.client+u.notConnect+u.connLimit+u.rateLimited, u.client, u.notConnect, u.connLimit, u.rateLimited,
			u.since.UTC().Format(time.RFC3339))
		*u = unaudited{since: now, reported: true}
	}
}

// clientAllowed reports whether remoteAddr is inside one of clients.
func clientAllowed(remoteAddr string, clients []netip.Prefix) bool {
	_, ok := clientAddr(remoteAddr, clients)
	return ok
}

// clientAddr returns the IP of remoteAddr, without IPv4 mapping or zone,
// and whether one of clients contains it.
func clientAddr(remoteAddr string, clients []netip.Prefix) (netip.Addr, bool) {
	ap, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	addr := ap.Addr().Unmap().WithZone("")
	for _, p := range clients {
		if p.Contains(addr) {
			return addr, true
		}
	}
	return netip.Addr{}, false
}

// isUpgrade reports whether h asks for a protocol upgrade: an Upgrade
// header, or "upgrade" among the Connection tokens.
func isUpgrade(h http.Header) bool {
	if len(h.Values("Upgrade")) > 0 {
		return true
	}
	for _, v := range h.Values("Connection") {
		for tok := range strings.SplitSeq(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				return true
			}
		}
	}
	return false
}

func stripPort(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return hostport
}

// prereadConn reads what the hijacked bufio.Reader already holds (it may
// hold the ClientHello) before reading from the conn.
type prereadConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *prereadConn) Read(p []byte) (int, error) {
	if c.r != nil {
		if c.r.Buffered() > 0 {
			return c.r.Read(p)
		}
		c.r = nil
	}
	return c.Conn.Read(p)
}

// oneConnListener hands out one conn, then blocks in Accept until Close.
type oneConnListener struct {
	mu   sync.Mutex
	conn net.Conn
	addr net.Addr
	done chan struct{}
	once sync.Once
}

func newOneConnListener(c net.Conn) *oneConnListener {
	return &oneConnListener{conn: c, addr: c.LocalAddr(), done: make(chan struct{})}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	c := l.conn
	l.conn = nil
	l.mu.Unlock()
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConnListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *oneConnListener) Addr() net.Addr { return l.addr }
