// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dantoac/credenza/internal/audit"
	"github.com/dantoac/credenza/internal/ca"
	"github.com/dantoac/credenza/internal/policy"
	"github.com/dantoac/credenza/internal/token"
)

const (
	ghSecret = "ghp_REALSECRET0000"
	clSecret = "sk-ant-oat01-REALSECRET1111"
)

// lockedBuffer is a bytes.Buffer safe for concurrent writes and reads.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestMain fails the run when anything reached the standard log package,
// which is where a nil ErrorLog on a server or ReverseProxy would write.
func TestMain(m *testing.M) {
	trap := &lockedBuffer{}
	log.SetOutput(trap)
	code := m.Run()
	if s := trap.String(); s != "" {
		fmt.Fprintf(os.Stderr, "the standard log package was written to:\n%s", s)
		code = 1
	}
	os.Exit(code)
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type upstreamRequest struct {
	Method, Host, Path, RawQuery string
	Authorization, AnthropicBeta string
	BodySum                      [sha256.Size]byte
}

type harness struct {
	t         *testing.T
	clock     *fakeClock
	tokens    *token.Registry
	grants    []policy.Grant
	audit     *audit.Log
	auditPath string
	errLog    *lockedBuffer
	caPool    *x509.CertPool
	broker    *httptest.Server
	client    *http.Client
	ghTok     string
	clTok     string

	mu      sync.Mutex
	last    upstreamRequest
	hits    int
	respond http.HandlerFunc
}

func newCA(t *testing.T) (*ca.CA, *x509.CertPool) {
	t.Helper()
	certPEM, keyPEM, err := ca.New(ca.DefaultName, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c, err := ca.Load(certPEM, keyPEM, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("cannot add CA to pool")
	}
	return c, pool
}

func newHarness(t *testing.T, opts ...func(*Config)) *harness {
	t.Helper()
	h := &harness{t: t, clock: &fakeClock{t: time.Now()}, errLog: &lockedBuffer{}}
	errLog := log.New(h.errLog, "", 0)

	testCA, testPool := newCA(t)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(h.serveUpstream))
	upstream.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return testCA.Leaf(hello.ServerName)
	}}
	upstream.Config.ErrorLog = errLog
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	upstreamAddr := upstream.Listener.Addr().String()
	upstreamTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, upstreamAddr)
		},
		TLSClientConfig: &tls.Config{RootCAs: testPool},
	}
	t.Cleanup(upstreamTransport.CloseIdleConnections)

	b, err := os.ReadFile("../policy/testdata/valid.json")
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	h.grants, _ = pol.Grants("example/app")
	h.tokens = token.NewRegistry(h.clock.Now)
	h.ghTok, h.clTok = h.mint("T1")

	h.auditPath = filepath.Join(t.TempDir(), "audit.log")
	h.audit, err = audit.Open(h.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.audit.Close() })

	authority, caPool := newCA(t)
	h.caPool = caPool
	secrets := map[string]string{"github-app": ghSecret, "claude-oauth": clSecret}
	cfg := Config{
		CA:     authority,
		Tokens: h.tokens,
		Secret: func(name string) (string, bool) {
			v, ok := secrets[name]
			return v, ok
		},
		Audit:    h.audit,
		Clients:  []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")},
		Upstream: upstreamTransport,
		ErrorLog: errLog,
		Now:      h.clock.Now,
	}
	for _, o := range opts {
		o(&cfg)
	}
	handler := New(cfg)
	h.broker = httptest.NewUnstartedServer(handler)
	h.broker.Listener = handler.Listener(h.broker.Listener)
	ref := NewServer("", handler, errLog)
	h.broker.Config.ReadHeaderTimeout = ref.ReadHeaderTimeout
	h.broker.Config.MaxHeaderBytes = ref.MaxHeaderBytes
	h.broker.Config.ErrorLog = ref.ErrorLog
	h.broker.Config.IdleTimeout = ref.IdleTimeout
	h.broker.Start()
	t.Cleanup(h.broker.Close)

	brokerURL, err := url.Parse(h.broker.URL)
	if err != nil {
		t.Fatal(err)
	}
	clientTransport := &http.Transport{
		Proxy:           http.ProxyURL(brokerURL),
		TLSClientConfig: &tls.Config{RootCAs: caPool},
	}
	h.client = &http.Client{Transport: clientTransport}
	t.Cleanup(clientTransport.CloseIdleConnections)
	return h
}

// mint returns the GH_TOKEN and CLAUDE_CODE_OAUTH_TOKEN tokens of a new
// mint for task.
func (h *harness) mint(task string) (gh, cl string) {
	h.t.Helper()
	issued, err := h.tokens.Mint(task, "example/app", h.grants)
	if err != nil {
		h.t.Fatal(err)
	}
	for _, is := range issued {
		switch is.Env {
		case "GH_TOKEN":
			gh = is.Token
		case "CLAUDE_CODE_OAUTH_TOKEN":
			cl = is.Token
		}
	}
	return gh, cl
}

func (h *harness) serveUpstream(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	h.hits++
	h.last = upstreamRequest{
		Method: r.Method, Host: r.Host, Path: r.URL.Path, RawQuery: r.URL.RawQuery,
		Authorization: r.Header.Get("Authorization"), AnthropicBeta: r.Header.Get("anthropic-beta"),
		BodySum: sha256.Sum256(body),
	}
	respond := h.respond
	h.mu.Unlock()
	if respond != nil {
		respond(w, r)
		return
	}
	io.WriteString(w, "ok")
}

func (h *harness) setRespond(f http.HandlerFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.respond = f
}

func (h *harness) upstream() (upstreamRequest, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.last, h.hits
}

func (h *harness) hitCount() int {
	_, n := h.upstream()
	return n
}

// do sends req through the broker and returns the response with its body.
func (h *harness) do(req *http.Request) (*http.Response, string) {
	h.t.Helper()
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp, string(body)
}

func newRequest(t *testing.T, method, rawURL, auth string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	return req
}

func (h *harness) auditEvents() []audit.Event {
	h.t.Helper()
	b, err := os.ReadFile(h.auditPath)
	if err != nil {
		h.t.Fatal(err)
	}
	var events []audit.Event
	for line := range strings.SplitSeq(strings.TrimSuffix(string(b), "\n"), "\n") {
		if line == "" {
			continue
		}
		var e audit.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			h.t.Fatalf("audit line %q: %v", line, err)
		}
		events = append(events, e)
	}
	return events
}

// waitAudit waits up to 2s for at least n audit events and returns them.
func (h *harness) waitAudit(n int) []audit.Event {
	h.t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		events := h.auditEvents()
		if len(events) >= n {
			return events
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("audit log has %d events, want at least %d", len(events), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (h *harness) lastAudit() audit.Event {
	h.t.Helper()
	events := h.auditEvents()
	if len(events) == 0 {
		h.t.Fatal("audit log is empty")
	}
	return events[len(events)-1]
}

// rawConnect writes a CONNECT for target with extra header lines and
// returns the conn, its reader and the broker's response.
func (h *harness) rawConnect(target, extra string) (net.Conn, *bufio.Reader, *http.Response) {
	h.t.Helper()
	conn, err := net.Dial("tcp", h.broker.Listener.Addr().String())
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { conn.Close() })
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", target, target, extra)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		h.t.Fatal(err)
	}
	return conn, br, resp
}

// tunnel opens a CONNECT tunnel to host:443 and runs a TLS handshake with sni.
func (h *harness) tunnel(host, sni string) (*tls.Conn, error) {
	h.t.Helper()
	return h.tunnelConfig(host, &tls.Config{ServerName: sni, RootCAs: h.caPool})
}

func (h *harness) tunnelConfig(host string, cfg *tls.Config) (*tls.Conn, error) {
	h.t.Helper()
	conn, br, resp := h.rawConnect(host+":443", "")
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("CONNECT %s: status %d", host, resp.StatusCode)
	}
	if br.Buffered() != 0 {
		h.t.Fatal("bytes after the CONNECT response")
	}
	tc := tls.Client(conn, cfg)
	return tc, tc.Handshake()
}

// rawRequest writes raw into a TLS tunnel to host and reads the response.
func (h *harness) rawRequest(host, raw string) *http.Response {
	h.t.Helper()
	tc, err := h.tunnel(host, host)
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := io.WriteString(tc, raw); err != nil {
		h.t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		h.t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

func (h *harness) unauditedLines() []string {
	var out []string
	for line := range strings.SplitSeq(h.errLog.String(), "\n") {
		if strings.Contains(line, "unaudited denials") {
			out = append(out, line)
		}
	}
	return out
}

func basic(user, pass string) string {
	return "Basic " + b64(user+":"+pass)
}

func TestProxySubstitutesToken(t *testing.T) {
	cases := []struct {
		name, method, url  string
		auth               func(h *harness) string
		beta               string
		wantAuth           string
		secret, host, path string
	}{
		{"gh", "GET", "https://api.github.com/repos/example/app/pulls",
			func(h *harness) string { return "token " + h.ghTok }, "",
			"token " + ghSecret, "github-app", "api.github.com", "/repos/example/app/pulls"},
		{"graphql", "POST", "https://api.github.com/graphql",
			func(h *harness) string { return "token " + h.ghTok }, "",
			"token " + ghSecret, "github-app", "api.github.com", "/graphql"},
		{"claude", "POST", "https://api.anthropic.com/v1/messages?beta=true",
			func(h *harness) string { return "Bearer " + h.clTok }, "oauth-2025-04-20",
			"Bearer " + clSecret, "claude-oauth", "api.anthropic.com", "/v1/messages"},
		{"git", "GET", "https://github.com/example/app.git/info/refs?service=git-upload-pack",
			func(h *harness) string { return basic("x-access-token", h.ghTok) }, "",
			basic("x-access-token", ghSecret), "github-app", "github.com", "/example/app.git/info/refs"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			req := newRequest(t, c.method, c.url, c.auth(h))
			if c.beta != "" {
				req.Header.Set("anthropic-beta", c.beta)
			}
			resp, body := h.do(req)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d, body %q", resp.StatusCode, body)
			}
			if strings.Contains(body, "REALSECRET") {
				t.Errorf("response body carries a secret: %q", body)
			}
			got, hits := h.upstream()
			if hits != 1 {
				t.Errorf("upstream hits %d, want 1", hits)
			}
			u, _ := url.Parse(c.url)
			if got.Authorization != c.wantAuth || got.Method != c.method || got.Host != c.host ||
				got.Path != c.path || got.RawQuery != u.RawQuery || got.AnthropicBeta != c.beta {
				t.Errorf("upstream got %+v", got)
			}
			e := h.lastAudit()
			if e.Event != "proxy" || e.Task != "T1" || e.Secret != c.secret || e.Host != c.host ||
				e.Method != c.method || e.Path != c.path || e.Decision != "allow" || e.Reason != "" {
				t.Errorf("audit %+v", e)
			}
		})
	}
}

func TestProxyDenies(t *testing.T) {
	gh := func(h *harness) string { return "token " + h.ghTok }
	cases := []struct {
		name, method, url string
		opaque            string // sent as URL.Opaque, so the client does not clean it
		auth              func(h *harness) string
		header            http.Header
		reason            string
	}{
		{"merge PR", "PUT", "https://api.github.com/repos/example/app/pulls/1/merge", "", gh, nil, "scope"},
		{"delete repo", "DELETE", "https://api.github.com/repos/example/app", "", gh, nil, "scope"},
		{"merge async", "PUT", "https://api.github.com/repos/example/app/pulls/1/merge-async", "", gh, nil, "scope"},
		{"REST POST", "POST", "https://api.github.com/repos/example/app/merges", "", gh, nil, "scope"},
		{"sibling repo", "GET", "https://api.github.com/repos/example/app-evil/pulls", "", gh, nil, "scope"},
		{"dot dot", "GET", "https://api.github.com/", "/repos/example/app/../app-evil/pulls", gh, nil, "path"},
		{"encoded slash", "GET", "https://api.github.com/repos/example%2Fapp/pulls", "", gh, nil, "path"},
		{"git settings", "GET", "https://github.com/example/app/settings", "",
			func(h *harness) string { return basic("x-access-token", h.ghTok) }, nil, "scope"},
		{"claude bridge", "POST", "https://api.anthropic.com/v1/environments/bridge", "",
			func(h *harness) string { return "Bearer " + h.clTok }, nil, "scope"},
		{"claude token on github", "GET", "https://api.github.com/repos/example/app/pulls", "",
			func(h *harness) string { return "Bearer " + h.clTok }, nil, "scope"},
		{"unknown token", "GET", "https://api.github.com/repos/example/app/pulls", "",
			func(h *harness) string { return "token fbt_nope" }, nil, "token"},
		{"revoked token", "GET", "https://api.github.com/repos/example/app/pulls", "",
			func(h *harness) string {
				tok, _ := h.mint("T9")
				h.tokens.Revoke("T9")
				return "token " + tok
			}, nil, "token"},
		{"expired token", "GET", "https://api.github.com/repos/example/app/pulls", "",
			func(h *harness) string {
				old := h.ghTok
				h.clock.Advance(9 * time.Hour)
				h.mint("T2")
				return "token " + old
			}, nil, "token"},
		{"two Authorization headers", "GET", "https://api.github.com/repos/example/app/pulls", "", nil,
			nil, "token"},
		{"unparsable", "GET", "https://api.github.com/repos/example/app/pulls", "",
			func(h *harness) string { return "Digest " + h.ghTok }, nil, "token"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			req := newRequest(t, c.method, c.url, "")
			if c.opaque != "" {
				req.URL.Opaque = c.opaque
			}
			if c.auth != nil {
				req.Header.Set("Authorization", c.auth(h))
			} else {
				req.Header["Authorization"] = []string{"token " + h.ghTok, "token " + h.ghTok}
			}
			resp, body := h.do(req)
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status %d, want 403", resp.StatusCode)
			}
			if want := "credenza: denied (" + c.reason + ")\n"; body != want {
				t.Errorf("body %q, want %q", body, want)
			}
			if n := h.hitCount(); n != 0 {
				t.Errorf("upstream hit %d times", n)
			}
			if e := h.lastAudit(); e.Decision != "deny" || e.Reason != c.reason || e.Event != "proxy" {
				t.Errorf("audit %+v, want deny %s", e, c.reason)
			}
		})
	}
}

func TestProxyNoAuthorizationGets401(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do(newRequest(t, "GET", "https://api.github.com/repos/example/app/pulls", ""))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != `Basic realm="credenza"` {
		t.Errorf("WWW-Authenticate %q", got)
	}
	if n := h.hitCount(); n != 0 {
		t.Errorf("upstream hit %d times", n)
	}
	if e := h.lastAudit(); e.Decision != "deny" || e.Reason != "no-token" {
		t.Errorf("audit %+v", e)
	}
}

func TestProxyConnectRules(t *testing.T) {
	cases := []struct {
		name    string
		clients []netip.Prefix // nil keeps the harness default
		raw     string
		reason  string // audit reason; empty means no new audit line
		errLog  string // expected in ErrorLog when reason is empty
	}{
		{"port 80", nil, "CONNECT api.github.com:80 HTTP/1.1\r\nHost: api.github.com:80\r\n\r\n", "port", ""},
		{"no token for host", nil, "CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n", "host", ""},
		{"IP literal", nil, "CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n", "port", ""},
		{"absolute URI", nil,
			"POST https://api.anthropic.com/v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: 0\r\n\r\n",
			"", "not-connect 1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, func(cfg *Config) {
				if c.clients != nil {
					cfg.Clients = c.clients
				}
			})
			conn, err := net.Dial("tcp", h.broker.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			io.WriteString(conn, c.raw)
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status %d, want 403", resp.StatusCode)
			}
			events := h.auditEvents()
			if c.reason == "" {
				if len(events) != 0 {
					t.Errorf("audit events %+v, want none", events)
				}
				if lines := h.unauditedLines(); len(lines) != 1 || !strings.Contains(lines[0], c.errLog) {
					t.Errorf("ErrorLog %q, want one line with %q", h.errLog.String(), c.errLog)
				}
				return
			}
			if len(events) != 1 || events[0].Reason != c.reason || events[0].Decision != "deny" {
				t.Errorf("audit events %+v, want one deny %s", events, c.reason)
			}
		})
	}
}

// TestProxyOuterDenyClosesConn: a deny before the tunnel closes the
// connection, so a peer cannot keep idle keep-alive connections open.
func TestProxyOuterDenyClosesConn(t *testing.T) {
	cases := []struct {
		name    string
		clients []netip.Prefix
		raw     string
	}{
		{"not-connect", nil, "GET http://api.anthropic.com/ HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n"},
		{"port", nil, "CONNECT api.github.com:80 HTTP/1.1\r\nHost: api.github.com:80\r\n\r\n"},
		{"host", nil, "CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, func(cfg *Config) {
				if c.clients != nil {
					cfg.Clients = c.clients
				}
			})
			conn, err := net.Dial("tcp", h.broker.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			io.WriteString(conn, c.raw)
			br := bufio.NewReader(conn)
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden || !resp.Close {
				t.Fatalf("status %d close %v, want 403 and Connection: close", resp.StatusCode, resp.Close)
			}
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := br.ReadByte(); err != io.EOF {
				t.Errorf("read after the deny: %v, want EOF", err)
			}
		})
	}
}

func TestNewServerTimeouts(t *testing.T) {
	srv := NewServer(":8888", http.NotFoundHandler(), log.New(io.Discard, "", 0))
	if srv.ReadHeaderTimeout != 10*time.Second || srv.MaxHeaderBytes != 32<<10 || srv.ErrorLog == nil ||
		srv.IdleTimeout <= 0 || srv.WriteTimeout != 0 || srv.ReadTimeout != 0 {
		t.Errorf("server %+v", srv)
	}
}

func TestClientAllowed(t *testing.T) {
	v4 := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	v6 := []netip.Prefix{netip.MustParsePrefix("::1/128")}
	cases := []struct {
		addr    string
		clients []netip.Prefix
		want    bool
	}{
		{"[::ffff:127.0.0.1]:5000", v4, true},
		{"127.0.0.1:5000", v4, true},
		{"[::1]:5000", v6, true},
		{"10.1.2.3:1", v4, false},
		{"garbage", v4, false},
		{"127.0.0.1:5000", nil, false},
		{"[fe80::1%en0]:5000", []netip.Prefix{netip.MustParsePrefix("fe80::/10")}, true},
	}
	for _, c := range cases {
		if got := clientAllowed(c.addr, c.clients); got != c.want {
			t.Errorf("clientAllowed(%q, %v) = %v, want %v", c.addr, c.clients, got, c.want)
		}
	}
}

func TestProxyUnauditedDeniesRateLimited(t *testing.T) {
	h := newHarness(t)
	brokerURL, _ := url.Parse(h.broker.URL)
	// A plain-HTTP URL makes the client send absolute-URI requests.
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(brokerURL)}}
	defer client.CloseIdleConnections()
	send := func() {
		t.Helper()
		resp, err := client.Post("http://api.anthropic.com/v1/messages", "text/plain", strings.NewReader("x"))
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d, want 403", resp.StatusCode)
		}
	}
	for range 100 {
		send()
	}
	if events := h.auditEvents(); len(events) != 0 {
		t.Fatalf("audit log gained %d events", len(events))
	}
	if lines := h.unauditedLines(); len(lines) != 1 || !strings.Contains(lines[0], "1 unaudited denials (client 0, not-connect 1, conn-limit 0, rate-limited 0)") {
		t.Fatalf("ErrorLog lines %q", lines)
	}
	h.clock.Advance(61 * time.Second)
	send()
	lines := h.unauditedLines()
	if len(lines) != 2 || !strings.Contains(lines[1], "100 unaudited denials (client 0, not-connect 100, conn-limit 0, rate-limited 0) since ") {
		t.Fatalf("ErrorLog lines %q", lines)
	}
	if !strings.HasPrefix(lines[1], "credenza: proxy: ") || strings.Contains(lines[1], "anthropic") {
		t.Errorf("ErrorLog line %q", lines[1])
	}
}

func TestProxySNIMismatch(t *testing.T) {
	h := newHarness(t)
	// The client skips verification, so only the broker can fail this handshake.
	_, err := h.tunnelConfig("api.github.com", &tls.Config{ServerName: "github.com", InsecureSkipVerify: true})
	if err == nil {
		t.Fatal("handshake with SNI github.com in a tunnel to api.github.com succeeded")
	}
	events := h.waitAudit(1)
	if e := events[0]; e.Reason != "tls" || e.Decision != "deny" || e.Host != "api.github.com" {
		t.Errorf("audit %+v", e)
	}
	tc, err := h.tunnel("api.github.com", "API.GitHub.com")
	if err != nil {
		t.Fatalf("handshake with SNI API.GitHub.com: %v", err)
	}
	tc.Close()
}

// connectThenTLS is a client conn that sends the CONNECT request and the
// ClientHello in one write, so both reach the broker before its 200; its
// first Read consumes the CONNECT response.
type connectThenTLS struct {
	net.Conn
	connect []byte // sent with the first Write
	br      *bufio.Reader
	resp    *http.Response
	err     error
}

func (c *connectThenTLS) Write(p []byte) (int, error) {
	if c.connect == nil {
		return c.Conn.Write(p)
	}
	b := append(c.connect, p...)
	c.connect = nil
	n, err := c.Conn.Write(b)
	return max(0, n-(len(b)-len(p))), err
}

func (c *connectThenTLS) Read(p []byte) (int, error) {
	if c.resp == nil && c.err == nil {
		c.resp, c.err = http.ReadResponse(c.br, &http.Request{Method: http.MethodConnect})
		if c.err == nil && c.resp.StatusCode != http.StatusOK {
			c.err = fmt.Errorf("CONNECT status %d", c.resp.StatusCode)
		}
	}
	if c.err != nil {
		return 0, c.err
	}
	return c.br.Read(p)
}

func TestProxyClientHelloWithConnect(t *testing.T) {
	h := newHarness(t)
	conn, err := net.Dial("tcp", h.broker.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tc := tls.Client(&connectThenTLS{
		Conn:    conn,
		connect: []byte("CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n"),
		br:      bufio.NewReader(conn),
	},
		&tls.Config{ServerName: "api.github.com", RootCAs: h.caPool})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("handshake with the ClientHello sent behind the CONNECT: %v", err)
	}
}

func TestProxyHandshakeTimeout(t *testing.T) {
	h := newHarness(t, func(cfg *Config) { cfg.HandshakeTimeout = 200 * time.Millisecond })
	conn, br, resp := h.rawConnect("api.github.com:443", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := br.ReadByte()
	if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read error %v, want the broker to close the conn", err)
	}
	events := h.waitAudit(1)
	if e := events[0]; e.Reason != "tls" || e.Decision != "deny" {
		t.Errorf("audit %+v", e)
	}
}

func TestProxyHostMismatch(t *testing.T) {
	h := newHarness(t)
	req := newRequest(t, "GET", "https://api.github.com/repos/example/app/pulls", "token "+h.ghTok)
	req.Host = "github.com"
	resp, body := h.do(req)
	if resp.StatusCode != http.StatusForbidden || body != "credenza: denied (host-mismatch)\n" {
		t.Fatalf("status %d body %q, want 403 host-mismatch", resp.StatusCode, body)
	}
	if n := h.hitCount(); n != 0 {
		t.Errorf("upstream hit %d times", n)
	}
	if e := h.lastAudit(); e.Reason != "host-mismatch" {
		t.Errorf("audit %+v", e)
	}

	req = newRequest(t, "GET", "https://api.github.com/repos/example/app/pulls", "token "+h.ghTok)
	req.Host = "API.GITHUB.COM"
	resp, _ = h.do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d with Host API.GITHUB.COM, want 200", resp.StatusCode)
	}
	if got, _ := h.upstream(); got.Host != "api.github.com" {
		t.Errorf("upstream Host %q", got.Host)
	}
}

func TestProxyDeniesUpgrade(t *testing.T) {
	cases := []struct{ name, headers string }{
		{"websocket", "Upgrade: websocket\r\nConnection: Upgrade\r\n"},
		{"connection token", "Connection: keep-alive, Upgrade\r\n"},
		{"h2c", "Upgrade: h2c\r\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			raw := "GET /repos/example/app/pulls HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: token " +
				h.ghTok + "\r\n" + c.headers + "\r\n"
			resp := h.rawRequest("api.github.com", raw)
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status %d, want 403", resp.StatusCode)
			}
			if n := h.hitCount(); n != 0 {
				t.Errorf("upstream hit %d times", n)
			}
			if e := h.lastAudit(); e.Reason != "upgrade" || e.Decision != "deny" {
				t.Errorf("audit %+v", e)
			}
		})
	}
}

func TestProxyScrubsEchoedCredential(t *testing.T) {
	cases := []struct {
		name, url string
		auth      func(h *harness) string
		rewritten string
	}{
		{"gh token", "https://api.github.com/repos/example/app/pulls",
			func(h *harness) string { return "token " + h.ghTok }, "token " + ghSecret},
		{"git basic", "https://github.com/example/app.git/info/refs?service=git-upload-pack",
			func(h *harness) string { return basic("x-access-token", h.ghTok) }, basic("x-access-token", ghSecret)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.setRespond(func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				_, cred, _ := strings.Cut(auth, " ")
				w.Header().Set("Trailer", "X-Echo-Trailer, X-Other-Trailer")
				w.Header().Set("X-Echo", auth)
				w.Header().Set("X-Echo-Cred", cred) // the credential without its scheme
				w.Header().Set("X-Other", "fine")
				io.WriteString(w, "ok")
				w.Header().Set("X-Echo-Trailer", auth)
				w.Header().Set("X-Other-Trailer", "fine")
			})
			resp, _ := h.do(newRequest(t, "GET", c.url, c.auth(h)))
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d", resp.StatusCode)
			}
			_, rewrittenCred, _ := strings.Cut(c.rewritten, " ")
			for kind, hdr := range map[string]http.Header{"header": resp.Header, "trailer": resp.Trailer} {
				for name, vals := range hdr {
					for _, v := range vals {
						if strings.Contains(v, ghSecret) || strings.Contains(v, rewrittenCred) {
							t.Errorf("response %s %s carries the credential", kind, name)
						}
					}
				}
			}
			if resp.Header.Get("X-Other") != "fine" || resp.Trailer.Get("X-Other-Trailer") != "fine" {
				t.Errorf("unrelated header or trailer dropped: %v %v", resp.Header, resp.Trailer)
			}
			for _, name := range []string{"X-Echo", "X-Echo-Cred", "X-Echo-Trailer"} {
				if !strings.Contains(h.errLog.String(), "dropped response header "+name+" ") {
					t.Errorf("ErrorLog %q has no drop line for %s", h.errLog.String(), name)
				}
			}
			if strings.Contains(h.errLog.String(), ghSecret) {
				t.Error("ErrorLog carries the secret")
			}
		})
	}
}

func TestProxyHeaderLimit(t *testing.T) {
	h := newHarness(t)
	big := strings.Repeat("a", 40<<10)
	req := newRequest(t, "GET", "https://api.github.com/repos/example/app/pulls", "token "+h.ghTok)
	req.Header.Set("X-Big", big)
	resp, _ := h.do(req)
	if resp.StatusCode < 400 {
		t.Errorf("inner request with a 40 KiB header: status %d", resp.StatusCode)
	}
	if n := h.hitCount(); n != 0 {
		t.Errorf("upstream hit %d times", n)
	}
	_, _, resp = h.rawConnect("api.github.com:443", "X-Big: "+big+"\r\n")
	if resp.StatusCode < 400 {
		t.Errorf("CONNECT with a 40 KiB header: status %d", resp.StatusCode)
	}
}

func TestProxyStreamsSSE(t *testing.T) {
	h := newHarness(t)
	release := make(chan struct{})
	h.setRespond(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "event: ping\n\n")
		http.NewResponseController(w).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	defer close(release)
	got := make(chan string, 1)
	go func() {
		req := newRequest(t, "POST", "https://api.anthropic.com/v1/messages", "Bearer "+h.clTok)
		resp, err := h.client.Do(req)
		if err != nil {
			got <- "error: " + err.Error()
			return
		}
		defer resp.Body.Close()
		line, err := bufio.NewReader(resp.Body).ReadString('\n')
		if err != nil {
			got <- "error: " + err.Error()
			return
		}
		got <- line
	}()
	select {
	case line := <-got:
		if line != "event: ping\n" {
			t.Fatalf("first line %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first SSE event did not arrive within 2s")
	}
}

func TestProxyChunkedPost(t *testing.T) {
	h := newHarness(t)
	payload := make([]byte, 1<<20)
	rand.Read(payload)
	pr, pw := io.Pipe()
	go func() {
		pw.Write(payload)
		pw.Close()
	}()
	req, err := http.NewRequest("POST", "https://github.com/example/app.git/git-receive-pack", pr)
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1
	req.Header.Set("Authorization", basic("x-access-token", h.ghTok))
	resp, _ := h.do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got, _ := h.upstream(); got.BodySum != sha256.Sum256(payload) {
		t.Error("upstream body differs from the sent body")
	}
}

func TestProxyAuditFailureFailsClosed(t *testing.T) {
	h := newHarness(t)
	h.audit.Close()
	resp, body := h.do(newRequest(t, "GET", "https://api.github.com/repos/example/app/pulls", "token "+h.ghTok))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", resp.StatusCode)
	}
	if strings.Contains(body, "REALSECRET") {
		t.Errorf("body %q", body)
	}
	if n := h.hitCount(); n != 0 {
		t.Errorf("upstream hit %d times", n)
	}
	if !strings.Contains(h.errLog.String(), "audit") {
		t.Errorf("ErrorLog %q has no audit failure line", h.errLog.String())
	}
}
