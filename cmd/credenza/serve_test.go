// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dantoac/credenza/internal/ca"
	"github.com/dantoac/credenza/internal/store"
)

const (
	ghReal = "ghp_SERVE_REAL_1111"
	clReal = "sk-ant-oat01-SERVE_REAL_2222"
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

// fixture is what a state dir is set up with, and what its setup printed.
type fixture struct {
	pass, gh, cl string
	outputs      []string // stdout and stderr of every setup command
}

// setupDir creates a state dir with a store holding github-app and
// claude-oauth, a CA for github.com and anthropic.com, and valid.json as
// the policy. os.MkdirTemp keeps <dir>/run/broker.sock under the 104-byte
// socket path limit of macOS, which t.TempDir() can exceed.
func setupDir(t *testing.T) string {
	t.Helper()
	return setupDirWith(t, &fixture{pass: pass, gh: ghReal, cl: clReal})
}

func setupDirWith(t *testing.T, fx *fixture) string {
	t.Helper()
	dir := tempStateDir(t)
	steps := []struct{ answers, args []string }{
		{[]string{fx.pass, fx.pass}, []string{"init", "-dir", dir}},
		{[]string{fx.pass, fx.gh}, []string{"secret", "add", "-dir", dir, "github-app"}},
		{[]string{fx.pass, fx.cl}, []string{"secret", "add", "-dir", dir, "claude-oauth"}},
		{[]string{fx.pass}, []string{"ca", "init", "-dir", dir, "-domains", "github.com,anthropic.com"}},
	}
	for _, s := range steps {
		f := credenza(t, 0, s.answers, s.args...)
		fx.outputs = append(fx.outputs, f.out.String(), f.errb.String())
	}
	writePolicy(t, dir, nil)
	return dir
}

func tempStateDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "fb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// writePolicy writes internal/policy/testdata/valid.json, changed by edit
// when it is not nil, to <dir>/policy.json with mode 0644.
func writePolicy(t *testing.T, dir string, edit func(string) string) {
	t.Helper()
	b, err := os.ReadFile("../../internal/policy/testdata/valid.json")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if edit != nil {
		s = edit(s)
	}
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
}

func missingSecretPolicy(s string) string {
	return strings.Replace(s, `"secret": "claude-oauth"`, `"secret": "missing-secret"`, 1)
}

// serveIO is an env for serve whose outputs can be read while it runs.
type serveIO struct {
	env
	out, errb *lockedBuffer
	prompts   atomic.Int32
}

// newServeIO returns an env whose readSecret answers passphrase every time.
func newServeIO(passphrase string, now func() time.Time) *serveIO {
	s := &serveIO{out: &lockedBuffer{}, errb: &lockedBuffer{}}
	s.env = env{
		stdout: s.out,
		stderr: s.errb,
		getenv: func(string) string { return "" },
		now:    now,
		readSecret: func(ctx context.Context, prompt string) (string, error) {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			s.prompts.Add(1)
			return passphrase, nil
		},
	}
	return s
}

func serveArgs(dir string) []string {
	return []string{"serve", "-dir", dir, "-listen", "127.0.0.1:0", "-clients", "127.0.0.0/8"}
}

// served is one serve run in a goroutine.
type served struct {
	proxyAddr, socket string
	io                *serveIO
	stop              func() int
}

// launch runs serve in a goroutine and waits until it is ready.
func launch(t *testing.T, dir string, sio *serveIO) *served {
	t.Helper()
	return launchArgs(t, serveArgs(dir), sio)
}

// launchArgs is launch with the whole serve command line.
func launchArgs(t *testing.T, args []string, sio *serveIO) *served {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	type addrs struct{ proxy, socket string }
	ready := make(chan addrs, 1)
	sio.ready = func(proxyAddr, socket string) { ready <- addrs{proxyAddr, socket} }
	done := make(chan int, 1)
	go func() { done <- run(ctx, args, sio.env) }()
	var once sync.Once
	var code int
	stop := func() int {
		once.Do(func() {
			cancel()
			select {
			case code = <-done:
			case <-time.After(10 * time.Second):
				t.Error("serve did not stop within 10s")
				code = -1
			}
		})
		return code
	}
	t.Cleanup(func() { stop() })
	select {
	case a := <-ready:
		return &served{proxyAddr: a.proxy, socket: a.socket, io: sio, stop: stop}
	case c := <-done:
		once.Do(func() { cancel(); code = c })
		t.Fatalf("serve exited %d before ready; stderr %q", c, sio.errb)
	case <-time.After(30 * time.Second):
		t.Fatal("serve not ready within 30s")
	}
	return nil
}

func startServe(t *testing.T, dir string) (proxyAddr, socket string, stop func() int) {
	t.Helper()
	s := launch(t, dir, newServeIO(pass, time.Now))
	return s.proxyAddr, s.socket, s.stop
}

// sshCommand runs ssh-command with SSH_ORIGINAL_COMMAND set to command.
func sshCommand(t *testing.T, dir, command string) (code int, stdout, stderr string) {
	t.Helper()
	f := fakeEnv()
	f.getenv = func(k string) string {
		if k == "SSH_ORIGINAL_COMMAND" {
			return command
		}
		return ""
	}
	code = f.run(t, "ssh-command", "-dir", dir)
	return code, f.out.String(), f.errb.String()
}

// mint runs "mint <task> example/app" through ssh-command and returns the
// tokens by env name.
func mint(t *testing.T, dir, task string) map[string]string {
	t.Helper()
	code, out, errOut := sshCommand(t, dir, "mint "+task+" example/app")
	if code != 0 {
		t.Fatalf("mint %s: exit %d, stderr %q", task, code, errOut)
	}
	return parseMint(t, out)
}

// parseMint returns the NAME=VALUE lines of mint's stdout by name. It
// wants exactly GH_TOKEN and CLAUDE_CODE_OAUTH_TOKEN, as valid.json grants.
func parseMint(t *testing.T, out string) map[string]string {
	t.Helper()
	toks := map[string]string{}
	for line := range strings.SplitSeq(strings.TrimSuffix(out, "\n"), "\n") {
		name, value, ok := strings.Cut(line, "=")
		if !ok || value == "" {
			t.Fatalf("mint stdout line %q is not NAME=VALUE", line)
		}
		toks[name] = value
	}
	if len(toks) != 2 || toks["GH_TOKEN"] == "" || toks["CLAUDE_CODE_OAUTH_TOKEN"] == "" {
		t.Fatalf("mint stdout %q", out)
	}
	return toks
}

// upstream is the fake GitHub and Anthropic server behind the broker. It
// records the Authorization header of every request it gets.
type upstream struct {
	errLog *lockedBuffer

	mu      sync.Mutex
	auths   []string
	respond http.HandlerFunc
}

// newUpstream starts the fake upstream and makes serve forward to it.
func newUpstream(t *testing.T) *upstream {
	t.Helper()
	u := &upstream{errLog: &lockedBuffer{}}
	certPEM, keyPEM, err := ca.New(ca.DefaultName, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	upCA, err := ca.Load(certPEM, keyPEM, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(u.serve))
	srv.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return upCA.Leaf(hello.ServerName)
	}}
	srv.Config.ErrorLog = log.New(u.errLog, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}
	t.Cleanup(tr.CloseIdleConnections)
	upstreamForTest = tr
	t.Cleanup(func() { upstreamForTest = nil })
	return u
}

func (u *upstream) serve(w http.ResponseWriter, r *http.Request) {
	io.Copy(io.Discard, r.Body)
	u.mu.Lock()
	u.auths = append(u.auths, r.Header.Get("Authorization"))
	respond := u.respond
	u.mu.Unlock()
	if respond != nil {
		respond(w, r)
		return
	}
	io.WriteString(w, "ok")
}

func (u *upstream) setRespond(f http.HandlerFunc) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.respond = f
}

// lastAuth returns the Authorization header of the last request and the
// number of requests so far.
func (u *upstream) lastAuth() (string, int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.auths) == 0 {
		return "", 0
	}
	return u.auths[len(u.auths)-1], len(u.auths)
}

// caCert returns the output of credenza ca-cert.
func caCert(t *testing.T, dir, passphrase string) []byte {
	t.Helper()
	return credenza(t, 0, []string{passphrase}, "ca-cert", "-dir", dir).out.Bytes()
}

// proxyClient returns a client that goes through the broker at proxyAddr
// and trusts only caPEM.
func proxyClient(t *testing.T, proxyAddr string, caPEM []byte) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("ca-cert output is not a PEM certificate")
	}
	tr := &http.Transport{
		Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr}
}

// get sends a GET with auth as the Authorization header and returns the
// status and body.
func get(t *testing.T, c *http.Client, rawURL, auth string) (int, string) {
	t.Helper()
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", auth)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

// rawConnect sends CONNECT target to the broker and returns the conn, its
// reader and the broker's response.
func rawConnect(t *testing.T, proxyAddr, target string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	return conn, br, resp
}

func assertNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s exists: %v", path, err)
	}
}

func TestServeRefusesMissingStore(t *testing.T) {
	dir := tempStateDir(t)
	sio := newServeIO(pass, time.Now)
	if got := run(context.Background(), serveArgs(dir), sio.env); got != 1 {
		t.Fatalf("exit %d, want 1; stderr %q", got, sio.errb)
	}
	errOut := sio.errb.String()
	assertOneLine(t, errOut)
	want := "credenza: store not found at " + filepath.Join(dir, "store.enc") + " (is its filesystem mounted?)\n"
	if errOut != want {
		t.Fatalf("stderr %q, want %q", errOut, want)
	}
	if n := sio.prompts.Load(); n != 0 {
		t.Fatalf("prompted %d times", n)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("serve created %v in the state dir", entries)
	}
}

func TestServeRequiresClients(t *testing.T) {
	dir := setupDir(t)
	for _, args := range [][]string{
		{"serve", "-dir", dir},
		{"serve", "-dir", dir, "-clients", ""},
		{"serve", "-dir", dir, "-clients", "10.0.0.0/8,"},
		{"serve", "-dir", dir, "-clients", "10.0.0.1"},
		{"serve", "-dir", dir, "-clients", "bogus"},
		{"serve", "-dir", dir, "-clients", "10.0.0.0/8", "extra"},
		{"serve", "-dir", dir, "-clients", "10.0.0.0/8", "-listen", "8888"},
	} {
		sio := newServeIO(pass, time.Now)
		if got := run(context.Background(), args, sio.env); got != 2 {
			t.Fatalf("%v: exit %d, want 2; stderr %q", args, got, sio.errb)
		}
		assertOneLine(t, sio.errb.String())
		if n := sio.prompts.Load(); n != 0 {
			t.Fatalf("%v: prompted %d times", args, n)
		}
	}
	assertNotExist(t, filepath.Join(dir, "run"))
}

func TestServeWrongPassphrase(t *testing.T) {
	dir := setupDir(t)
	sio := newServeIO("not the passphrase", time.Now)
	if got := run(context.Background(), serveArgs(dir), sio.env); got != 1 {
		t.Fatalf("exit %d, want 1", got)
	}
	if got := sio.errb.String(); got != "credenza: wrong passphrase or corrupted store\n" {
		t.Fatalf("stderr %q", got)
	}
	if n := sio.prompts.Load(); n != 3 {
		t.Fatalf("readSecret called %d times, want 3", n)
	}
	assertNotExist(t, filepath.Join(dir, "run"))
	assertNotExist(t, filepath.Join(dir, "audit.log"))
}

func TestServeRefusesBadPolicy(t *testing.T) {
	dir := setupDir(t)
	writePolicy(t, dir, missingSecretPolicy)
	sio := newServeIO(pass, time.Now)
	if got := run(context.Background(), serveArgs(dir), sio.env); got != 1 {
		t.Fatalf("exit %d, want 1", got)
	}
	errOut := sio.errb.String()
	assertOneLine(t, errOut)
	if !strings.HasPrefix(errOut, "credenza: policy: ") || !strings.Contains(errOut, `"missing-secret"`) {
		t.Fatalf("stderr %q", errOut)
	}
	assertNotExist(t, filepath.Join(dir, "run"))
}

func TestServeRefusesNoCA(t *testing.T) {
	dir := tempStateDir(t)
	credenza(t, 0, []string{pass, pass}, "init", "-dir", dir)
	sio := newServeIO(pass, time.Now)
	if got := run(context.Background(), serveArgs(dir), sio.env); got != 1 {
		t.Fatalf("exit %d, want 1", got)
	}
	if got := sio.errb.String(); got != "credenza: no CA in store; run credenza ca init\n" {
		t.Fatalf("stderr %q", got)
	}
	assertNotExist(t, filepath.Join(dir, "run"))
}

func TestServeRefusesHostOutsideCA(t *testing.T) {
	dir := setupDir(t)
	credenza(t, 0, []string{pass}, "ca", "init", "-dir", dir, "-force", "-domains", "github.com")
	sio := newServeIO(pass, time.Now)
	if got := run(context.Background(), serveArgs(dir), sio.env); got != 1 {
		t.Fatalf("exit %d, want 1", got)
	}
	errOut := sio.errb.String()
	assertOneLine(t, errOut)
	if !strings.HasPrefix(errOut, `credenza: policy: host "api.anthropic.com" not permitted by the CA: `) {
		t.Fatalf("stderr %q", errOut)
	}
	assertNotExist(t, filepath.Join(dir, "run"))
}

func TestServeInterruptedAtPrompt(t *testing.T) {
	dir := setupDir(t)
	sio := newServeIO(pass, time.Now)
	asked := make(chan struct{}, 10)
	sio.readSecret = func(ctx context.Context, prompt string) (string, error) {
		sio.prompts.Add(1)
		asked <- struct{}{}
		<-ctx.Done()
		return "", ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() { done <- run(ctx, serveArgs(dir), sio.env) }()
	select {
	case <-asked:
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not prompt")
	}
	cancel()
	select {
	case got := <-done:
		if got != 1 {
			t.Fatalf("exit %d, want 1", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not return within 2s of the interrupt")
	}
	if got := sio.errb.String(); got != "credenza: interrupted\n" {
		t.Fatalf("stderr %q", got)
	}
	if n := sio.prompts.Load(); n != 1 {
		t.Fatalf("readSecret called %d times, want 1", n)
	}
	assertNotExist(t, filepath.Join(dir, "run"))
}

func TestServeEndToEnd(t *testing.T) {
	dir := setupDir(t)
	up := newUpstream(t)
	s := launch(t, dir, newServeIO(pass, time.Now))
	if want := filepath.Join(dir, "run", "broker.sock"); s.socket != want {
		t.Fatalf("socket %q, want %q", s.socket, want)
	}
	adminSock := filepath.Join(dir, "run", "admin.sock")
	if want := fmt.Sprintf("credenza: serving proxy on %s, control on %s, admin on %s\n", s.proxyAddr, s.socket, adminSock); s.io.errb.String() != want {
		t.Fatalf("stderr %q, want %q", s.io.errb, want)
	}
	fi, err := os.Lstat(s.socket)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v", fi.Mode())
	}
	if fi, err := os.Lstat(adminSock); err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("admin socket: %v, %v", fi, err)
	}

	toks := mint(t, dir, "T1")
	client := proxyClient(t, s.proxyAddr, caCert(t, dir, pass))
	status, body := get(t, client, pulls, "token "+toks["GH_TOKEN"])
	if status != http.StatusOK || body != "ok" {
		t.Fatalf("allowed request: status %d, body %q", status, body)
	}
	if auth, n := up.lastAuth(); auth != "token "+ghReal || n != 1 {
		t.Fatalf("upstream got Authorization %q after %d requests", auth, n)
	}

	if code, out, errOut := sshCommand(t, dir, "revoke T1"); code != 0 || out != "" || errOut != "" {
		t.Fatalf("revoke: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	// The tunnel from the first request is reused: the inner check denies.
	if status, body := get(t, client, pulls, "token "+toks["GH_TOKEN"]); status != http.StatusForbidden {
		t.Fatalf("after revoke: status %d, body %q", status, body)
	}
	// A new tunnel is refused at CONNECT: no live token names the host.
	if _, _, resp := rawConnect(t, s.proxyAddr, "api.github.com:443"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("CONNECT after revoke: status %d", resp.StatusCode)
	}
	if _, n := up.lastAuth(); n != 1 {
		t.Fatalf("upstream hit %d times, want 1", n)
	}

	if code := s.stop(); code != 0 {
		t.Fatalf("stop: exit %d, stderr %q", code, s.io.errb)
	}
	assertNotExist(t, s.socket)
	assertNotExist(t, adminSock)
	if code, _, errOut := sshCommand(t, dir, "revoke T1"); code != 3 {
		t.Fatalf("revoke after stop: exit %d, stderr %q", code, errOut)
	}
}

func TestServeRestartInvalidatesTokens(t *testing.T) {
	dir := setupDir(t)
	proxyAddr, _, stop := startServe(t, dir)
	mint(t, dir, "T1")
	if _, _, resp := rawConnect(t, proxyAddr, "api.github.com:443"); resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT with a live token: status %d", resp.StatusCode)
	}
	if code := stop(); code != 0 {
		t.Fatalf("stop: exit %d", code)
	}
	proxyAddr, _, _ = startServe(t, dir)
	_, br, resp := rawConnect(t, proxyAddr, "api.github.com:443")
	body, _ := io.ReadAll(br)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "credenza: denied (host)") {
		t.Fatalf("CONNECT after restart: status %d, body %q", resp.StatusCode, body)
	}
}

func TestServeStaleSocket(t *testing.T) {
	dir := setupDir(t)
	runDir := filepath.Join(dir, "run")
	if err := os.Mkdir(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(runDir, "broker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	if _, err := os.Lstat(sock); err != nil {
		t.Fatalf("stale socket not left in place: %v", err)
	}
	_, socket, stop := startServe(t, dir)
	if code, _, errOut := sshCommand(t, dir, "revoke T1"); code != 0 {
		t.Fatalf("revoke: exit %d, stderr %q", code, errOut)
	}
	if code := stop(); code != 0 {
		t.Fatalf("stop: exit %d", code)
	}
	assertNotExist(t, socket)
}

func TestServeRefusesSecondServe(t *testing.T) {
	dir := setupDir(t)
	startServe(t, dir)
	sio := newServeIO(pass, time.Now)
	if got := run(context.Background(), serveArgs(dir), sio.env); got != 1 {
		t.Fatalf("second serve: exit %d, want 1", got)
	}
	if !strings.Contains(sio.errb.String(), "another credenza serve is running") {
		t.Fatalf("stderr %q", sio.errb)
	}
	if code, _, errOut := sshCommand(t, dir, "revoke T1"); code != 0 {
		t.Fatalf("first serve stopped answering: exit %d, stderr %q", code, errOut)
	}
}

func TestServePortInUse(t *testing.T) {
	dir := setupDir(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	sio := newServeIO(pass, time.Now)
	args := []string{"serve", "-dir", dir, "-listen", busy.Addr().String(), "-clients", "127.0.0.0/8"}
	if got := run(context.Background(), args, sio.env); got != 1 {
		t.Fatalf("exit %d, want 1; stderr %q", got, sio.errb)
	}
	assertOneLine(t, sio.errb.String())
	assertNotExist(t, filepath.Join(dir, "run", "broker.sock"))
}

func TestSSHCommandParsing(t *testing.T) {
	dir := tempStateDir(t)
	const usageText = "usage: mint <task-id> <project> [<env>...] | renew <task-id> | revoke <task-id>\n"
	cases := []struct {
		command string
		want    int
	}{
		{"", 2},
		{"mint", 2},
		{"mint T1", 2},
		{"mint T1 example/app extra", 2},
		{"mint T1 example/app gh_token", 2},
		{"mint T1 example/app GH_TOKEN a/b", 2},
		{"mint T1 example/app A B C D", 2},
		{"mint T1 example/app GH_TOKEN", 3},
		{"mint T1 example/app A B C", 3},
		{"mint a/b example/app", 2},
		{"mint T1 app", 2},
		{"revoke", 2},
		{"revoke T1 x", 2},
		{"sh -c id", 2},
		{"rm -rf /", 2},
		{"broker", 2},
		{"credenza", 2},
		{"broker broker mint T1 example/app", 2},
		{"credenza credenza mint T1 example/app", 2},
		{"credenza broker mint T1 example/app", 2},
		{"mint T1 example/app", 3},
		{"broker mint T1 example/app", 3},
		{"credenza mint T1 example/app", 3},
		{"  mint\tT1   example/app ", 3},
		{"revoke T1", 3},
		{"renew", 2},
		{"renew a b", 2},
		{"renew a/b", 2},
		{"renew t1", 3},
		{"broker renew t1", 3},
		{"credenza renew t1", 3},
	}
	for _, c := range cases {
		code, out, errOut := sshCommand(t, dir, c.command)
		if code != c.want || out != "" {
			t.Fatalf("%q: exit %d, want %d; stdout %q, stderr %q", c.command, code, c.want, out, errOut)
		}
		want := usageText
		if c.want == 3 {
			want = "credenza: broker is locked or not running\n"
		}
		if errOut != want {
			t.Fatalf("%q: stderr %q, want %q", c.command, errOut, want)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("ssh-command created %v", entries)
	}
}

func TestSSHCommandMintDenied(t *testing.T) {
	dir := setupDir(t)
	startServe(t, dir)
	code, out, errOut := sshCommand(t, dir, "mint T1 example/other")
	if code != 4 || out != "" || errOut != "credenza: policy denies the project \"example/other\"\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestServeMaxSessionFlag(t *testing.T) {
	if pruneEvery != 5*time.Second {
		t.Fatalf("pruneEvery = %v, want 5s", pruneEvery)
	}
	if defaultMaxSession != 24*time.Hour {
		t.Fatalf("defaultMaxSession = %v, want 24h", defaultMaxSession)
	}
	dir := setupDir(t)
	for _, v := range []string{"0", "59s", "721h", "-1h", "x", "1d"} {
		args := append(serveArgs(dir), "-max-session", v)
		sio := newServeIO(pass, time.Now)
		if got := run(context.Background(), args, sio.env); got != 2 {
			t.Fatalf("-max-session %s: exit %d, want 2; stderr %q", v, got, sio.errb)
		}
		assertOneLine(t, sio.errb.String())
		if !strings.Contains(sio.errb.String(), "-max-session") {
			t.Fatalf("-max-session %s: stderr %q does not name the flag", v, sio.errb)
		}
		if n := sio.prompts.Load(); n != 0 {
			t.Fatalf("-max-session %s: prompted %d times", v, n)
		}
	}
	assertNotExist(t, filepath.Join(dir, "run"))

	// A served -max-session bounds renew.
	c := &fakeClock{t: time.Now()}
	launchArgs(t, append(serveArgs(dir), "-max-session", "1m"), newServeIO(pass, c.Now))
	mint(t, dir, "t1")
	if code, out, errOut := sshCommand(t, dir, "renew t1"); code != 0 || out != "" || errOut != "" {
		t.Fatalf("renew: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	c.Advance(time.Minute)
	code, out, errOut := sshCommand(t, dir, "renew t1")
	if code != 5 || out != "" || !strings.HasPrefix(errOut, "credenza: max session") {
		t.Fatalf("renew past -max-session: exit %d, stdout %q, stderr %q; want 5", code, out, errOut)
	}
	if code, _, errOut := sshCommand(t, dir, "renew t1"); code != 5 || !strings.Contains(errOut, "no live tokens") {
		t.Fatalf("renew after max session: exit %d, stderr %q; want 5 no live tokens", code, errOut)
	}
}

const pulls = "https://api.github.com/repos/example/app/pulls"

// secretAdd runs broker secret add -replace name with value as the only
// answer, as with a running serve.
func secretAdd(t *testing.T, dir, name, value string) {
	t.Helper()
	f := credenza(t, 0, []string{value}, "secret", "add", "-dir", dir, "-replace", name)
	if got := f.errb.String(); got != "credenza: secret "+name+" saved; live\n" {
		t.Fatalf("secret add: stderr %q", got)
	}
}

func TestSecretSetLive(t *testing.T) {
	const rotated = "ghp_ROTATED_3333"
	dir := setupDir(t)
	up := newUpstream(t)
	s := launch(t, dir, newServeIO(pass, time.Now))
	toks := mint(t, dir, "t1")
	client := proxyClient(t, s.proxyAddr, caCert(t, dir, pass))
	if status, _ := get(t, client, pulls, "token "+toks["GH_TOKEN"]); status != http.StatusOK {
		t.Fatalf("before rotate: status %d", status)
	}
	if auth, _ := up.lastAuth(); auth != "token "+ghReal {
		t.Fatalf("before rotate: upstream got %q", auth)
	}
	secretAdd(t, dir, "github-app", rotated)
	// Same token, same tunnel: the next request carries the new value.
	if status, _ := get(t, client, pulls, "token "+toks["GH_TOKEN"]); status != http.StatusOK {
		t.Fatalf("after rotate: status %d", status)
	}
	if auth, n := up.lastAuth(); auth != "token "+rotated || n != 2 {
		t.Fatalf("after rotate: upstream got %q after %d requests", auth, n)
	}
	// A secret added live is usable by a policy that names it at once.
	secretAdd(t, dir, "missing-secret", "sk-new")
	writePolicy(t, dir, missingSecretPolicy)
	mint(t, dir, "t2")
	if strings.Contains(s.io.errb.String(), rotated) {
		t.Fatal("serve stderr carries the value")
	}
}

func TestSecretSetPersists(t *testing.T) {
	const rotated = "ghp_ROTATED_4444"
	dir := setupDir(t)
	up := newUpstream(t)
	_, _, stop := startServe(t, dir)
	secretAdd(t, dir, "github-app", rotated)
	if code := stop(); code != 0 {
		t.Fatalf("stop: exit %d", code)
	}
	d, err := store.Load(filepath.Join(dir, "store.enc"), pass)
	if err != nil {
		t.Fatal(err)
	}
	if d.Secrets["github-app"] != rotated || d.Secrets["claude-oauth"] != clReal || d.CA == nil {
		t.Fatalf("store after a live set: github-app ok %v, claude-oauth ok %v, CA %v",
			d.Secrets["github-app"] == rotated, d.Secrets["claude-oauth"] == clReal, d.CA != nil)
	}
	s := launch(t, dir, newServeIO(pass, time.Now))
	toks := mint(t, dir, "t1")
	client := proxyClient(t, s.proxyAddr, caCert(t, dir, pass))
	if status, _ := get(t, client, pulls, "token "+toks["GH_TOKEN"]); status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if auth, _ := up.lastAuth(); auth != "token "+rotated {
		t.Fatal("after restart the upstream did not get the rotated value")
	}
}

// TestSecretSetAfterPasswd: a passphrase changed while serve runs makes a
// live set fail, instead of saving the store under the old passphrase.
func TestSecretSetAfterPasswd(t *testing.T) {
	dir := setupDir(t)
	startServe(t, dir)
	credenza(t, 0, []string{pass, newPass, newPass}, "passwd", "-dir", dir)
	before := storeBytes(t, dir)
	f := credenza(t, 1, []string{"ghp_after_passwd"}, "secret", "add", "-dir", dir, "-replace", "github-app")
	assertOneLine(t, f.errb.String())
	if !strings.Contains(f.errb.String(), "passphrase") {
		t.Fatalf("stderr %q", f.errb)
	}
	if !bytes.Equal(before, storeBytes(t, dir)) {
		t.Fatal("store.enc changed")
	}
	if _, err := store.Load(filepath.Join(dir, "store.enc"), newPass); err != nil {
		t.Fatalf("store no longer opens with the new passphrase: %v", err)
	}
}

func TestSecretRmLive(t *testing.T) {
	dir := setupDir(t)
	newUpstream(t)
	s := launch(t, dir, newServeIO(pass, time.Now))
	toks := mint(t, dir, "t1")
	client := proxyClient(t, s.proxyAddr, caCert(t, dir, pass))
	f := credenza(t, 0, nil, "secret", "rm", "-dir", dir, "github-app")
	if got := f.errb.String(); got != "credenza: secret github-app removed; live\n" {
		t.Fatalf("stderr %q", got)
	}
	code, out, errOut := sshCommand(t, dir, "mint t2 example/app")
	if code != 1 || out != "" || errOut != "credenza: policy: secret \"github-app\" not in store\n" {
		t.Fatalf("mint after rm: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	// A live token of the removed secret is denied, not forwarded empty.
	if status, body := get(t, client, pulls, "token "+toks["GH_TOKEN"]); status != http.StatusForbidden || body != "credenza: denied (secret)\n" {
		t.Fatalf("live token after rm: status %d, body %q", status, body)
	}
}

func TestSecretSetLiveRace(t *testing.T) {
	dir := initStore(t)
	path := filepath.Join(dir, "store.enc")
	d, err := store.Load(path, pass)
	if err != nil {
		t.Fatal(err)
	}
	live := newLiveSecrets(path, []byte(pass), d.Secrets)
	if err := live.Set("github-app", "v0"); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				if v, ok := live.Get("github-app"); !ok || !strings.HasPrefix(v, "v") {
					t.Errorf("Get = %q, %v", v, ok)
					return
				}
				live.Get("claude-oauth")
			}
		})
	}
	for i := 1; i <= 3; i++ {
		if err := live.Set("github-app", fmt.Sprintf("v%d", i)); err != nil {
			t.Error(err)
		}
		if err := live.Set("claude-oauth", "x"); err != nil {
			t.Error(err)
		}
		if err := live.Remove("claude-oauth"); err != nil {
			t.Error(err)
		}
	}
	close(stop)
	wg.Wait()
	if v, _ := live.Get("github-app"); v != "v3" {
		t.Fatalf("Get = %q, want v3", v)
	}
	if err := live.Remove("claude-oauth"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("Remove of a missing secret: %v", err)
	}
	if err := live.Set("Bad", "v"); err == nil {
		t.Fatal("Set accepted an invalid name")
	}
	if err := live.Set("ok", "a\nb"); err == nil || strings.Contains(err.Error(), "a\nb") {
		t.Fatalf("Set with a bad value: %v", err)
	}
}

func TestSSHCommandRejectsAdminVerbs(t *testing.T) {
	dir := setupDir(t)
	startServe(t, dir)
	before := storeBytes(t, dir)
	for _, command := range []string{
		"secret-set github-app",
		"secret-set github-app replace",
		"credenza secret-set github-app",
		"secret-rm github-app",
		"credenza secret-rm github-app",
		"policy-load",
		"broker policy-load",
	} {
		code, out, errOut := sshCommand(t, dir, command)
		if code != 2 || out != "" || errOut != sshUsage+"\n" {
			t.Fatalf("%q: exit %d, stdout %q, stderr %q", command, code, out, errOut)
		}
	}
	if !bytes.Equal(before, storeBytes(t, dir)) {
		t.Fatal("store.enc changed")
	}
	b, err := os.ReadFile(filepath.Join(dir, "audit.log"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"event":"secret"`) {
		t.Fatalf("audit log has a secret event:\n%s", b)
	}
}

// sshAdmin runs ssh-admin with SSH_ORIGINAL_COMMAND set to command and
// stdin as its standard input.
func sshAdmin(t *testing.T, dir, command string, stdin []byte) (code int, stdout, stderr string) {
	t.Helper()
	f := fakeEnv()
	f.getenv = func(k string) string {
		if k == "SSH_ORIGINAL_COMMAND" {
			return command
		}
		return ""
	}
	f.stdin = bytes.NewReader(stdin)
	code = f.run(t, "ssh-admin", "-dir", dir)
	return code, f.out.String(), f.errb.String()
}

// validPolicyWith returns valid.json changed by edit.
func validPolicyWith(t *testing.T, edit func(string) string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../internal/policy/testdata/valid.json")
	if err != nil {
		t.Fatal(err)
	}
	return []byte(edit(string(b)))
}

func policyBytes(t *testing.T, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// otherProject adds example/other, with the GH_TOKEN grant of
// example/app, to valid.json.
func otherProject(s string) string {
	return strings.Replace(s, `"projects": {`, `"projects": {
    "example/other": [{"env": "GH_TOKEN", "secret": "github-app", "ttl": "5m",
      "allow": [{"host": "api.github.com", "methods": ["GET"], "paths": ["/repos/example/other/"]}]}],`, 1)
}

func TestPolicyLoadValid(t *testing.T) {
	dir := setupDir(t)
	startServe(t, dir)
	if code, _, _ := sshCommand(t, dir, "mint t1 example/other"); code != 4 {
		t.Fatalf("mint before load: exit %d, want 4", code)
	}
	body := validPolicyWith(t, otherProject)
	if code, out, errOut := sshAdmin(t, dir, "policy-load", body); code != 0 || out != "" || errOut != "" {
		t.Fatalf("policy-load: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	if !bytes.Equal(policyBytes(t, dir), body) {
		t.Fatal("policy.json is not the loaded body")
	}
	fi, err := os.Stat(filepath.Join(dir, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("policy.json mode %04o, want 0644", fi.Mode().Perm())
	}
	// The next mint uses the loaded policy, without a restart.
	code, out, errOut := sshCommand(t, dir, "mint t2 example/other")
	if code != 0 || !strings.HasPrefix(out, "GH_TOKEN=") || strings.Count(out, "\n") != 1 {
		t.Fatalf("mint after load: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	// "credenza policy-load" and the legacy "broker policy-load" are accepted as well.
	for _, command := range []string{"credenza policy-load", "broker policy-load"} {
		if code, _, errOut := sshAdmin(t, dir, command, body); code != 0 {
			t.Fatalf("%s: exit %d, stderr %q", command, code, errOut)
		}
	}
	audit, err := os.ReadFile(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf(`"event":"policy","decision":"allow","reason":"sha256=%x"`, sha256.Sum256(body))
	if strings.Count(string(audit), want) != 3 {
		t.Fatalf("audit log lacks three %s lines:\n%s", want, audit)
	}
}

// policyLoadRefused loads body, wants exit 1 with one stderr line that
// starts with "credenza: invalid policy: " and contains msg, and wants
// policy.json unchanged.
func policyLoadRefused(t *testing.T, dir string, body []byte, msg string) {
	t.Helper()
	before := policyBytes(t, dir)
	code, out, errOut := sshAdmin(t, dir, "policy-load", body)
	if code != 1 || out != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q; want 1", code, out, errOut)
	}
	assertOneLine(t, errOut)
	if !strings.HasPrefix(errOut, "credenza: invalid policy: ") || !strings.Contains(errOut, msg) {
		t.Fatalf("stderr %q, want invalid policy with %q", errOut, msg)
	}
	if !bytes.Equal(before, policyBytes(t, dir)) {
		t.Fatal("policy.json changed")
	}
}

func TestPolicyLoadRejectsMissingSecret(t *testing.T) {
	dir := setupDir(t)
	startServe(t, dir)
	policyLoadRefused(t, dir, validPolicyWith(t, missingSecretPolicy), `secret "missing-secret" not in store`)
	// Added live, the secret makes the same policy load.
	secretAdd(t, dir, "missing-secret", "sk-new")
	if code, _, errOut := sshAdmin(t, dir, "policy-load", validPolicyWith(t, missingSecretPolicy)); code != 0 {
		t.Fatalf("policy-load after secret add: exit %d, stderr %q", code, errOut)
	}
}

func TestPolicyLoadRejectsHostOutsideCA(t *testing.T) {
	dir := setupDir(t)
	startServe(t, dir)
	body := validPolicyWith(t, func(s string) string {
		return strings.Replace(s, `"host": "api.anthropic.com"`, `"host": "api.example.com"`, 1)
	})
	policyLoadRefused(t, dir, body, `host "api.example.com" not permitted by the CA`)
}

func TestPolicyLoadRejectsUnknownMember(t *testing.T) {
	dir := setupDir(t)
	startServe(t, dir)
	for _, c := range []struct {
		edit func(string) string
		msg  string
	}{
		{func(s string) string { return strings.Replace(s, `"version": 1,`, `"version": 1, "extra": true,`, 1) }, "extra"},
		{func(s string) string { return strings.Replace(s, `"version": 1,`, `"version": 2,`, 1) }, "version"},
		{func(s string) string { return s + "{}" }, ""},
		{func(string) string { return "" }, ""},
	} {
		policyLoadRefused(t, dir, validPolicyWith(t, c.edit), c.msg)
	}
	b, err := os.ReadFile(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), `"event":"policy","decision":"deny","reason":"invalid sha256=`); n != 4 {
		t.Fatalf("audit log has %d policy deny lines, want 4:\n%s", n, b)
	}
}

func TestPolicyLoadAtomic(t *testing.T) {
	dir := setupDir(t)
	startServe(t, dir)
	old := policyBytes(t, dir)
	other := validPolicyWith(t, otherProject)
	bad := validPolicyWith(t, missingSecretPolicy)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			b, err := os.ReadFile(filepath.Join(dir, "policy.json"))
			if err != nil {
				t.Errorf("read policy.json: %v", err)
				return
			}
			if !bytes.Equal(b, old) && !bytes.Equal(b, other) {
				t.Errorf("policy.json is partly written: %d bytes", len(b))
				return
			}
		}
	})
	for i := range 6 {
		body := other
		if i%2 == 1 {
			body = old
		}
		if code, _, errOut := sshAdmin(t, dir, "policy-load", body); code != 0 {
			t.Errorf("load %d: exit %d, stderr %q", i, code, errOut)
		}
		if code, _, _ := sshAdmin(t, dir, "policy-load", bad); code != 1 {
			t.Errorf("bad load %d: exit %d, want 1", i, code)
		}
	}
	close(stop)
	wg.Wait()
	// The last good load wins; no temp file is left behind.
	if !bytes.Equal(policyBytes(t, dir), old) {
		t.Fatal("policy.json is not the last good body")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		switch e.Name() {
		case "store.enc", "store.enc.lock", "policy.json", "audit.log", "run":
		default:
			t.Fatalf("state dir has %q after loads", e.Name())
		}
	}
}

func TestSSHAdminOnlyPolicyLoad(t *testing.T) {
	dir := tempStateDir(t)
	cases := []struct {
		command string
		stdin   []byte
		want    int
	}{
		{"", nil, 2},
		{"mint x y", nil, 2},
		{"mint t1 example/app", nil, 2},
		{"renew t1", nil, 2},
		{"revoke t1", nil, 2},
		{"secret-set github-app", []byte("v\n"), 2},
		{"secret-rm github-app", nil, 2},
		{"policy-load x", []byte("{}"), 2},
		{"policy-load < /etc/passwd", nil, 2},
		{"broker broker policy-load", []byte("{}"), 2},
		{"credenza credenza policy-load", []byte("{}"), 2},
		{"sh -c id", nil, 2},
		{"broker", nil, 2},
		{"credenza", nil, 2},
		{"policy-load", bytes.Repeat([]byte("a"), 256<<10+1), 2},
		// With no serve, a well-formed request finds the socket down.
		{"policy-load", []byte("{}"), 3},
		{"broker policy-load", []byte("{}"), 3},
		{"credenza policy-load", []byte("{}"), 3},
		{"  policy-load\t", bytes.Repeat([]byte("a"), 256<<10), 3},
	}
	for _, c := range cases {
		code, out, errOut := sshAdmin(t, dir, c.command, c.stdin)
		if code != c.want || out != "" {
			t.Fatalf("%q: exit %d, want %d; stdout %q, stderr %q", c.command, code, c.want, out, errOut)
		}
		assertOneLine(t, errOut)
		want := sshAdminUsage + "\n"
		if c.want == 3 {
			want = "credenza: broker is locked or not running\n"
		}
		if errOut != want {
			t.Fatalf("%q: stderr %q, want %q", c.command, errOut, want)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("ssh-admin created %v", entries)
	}
}

// TestSSHAdminDialsAdminSock: ssh-admin sends "policy-load\n<body>" to
// admin.sock and never touches broker.sock.
func TestSSHAdminDialsAdminSock(t *testing.T) {
	dir := tempStateDir(t)
	if err := os.Mkdir(filepath.Join(dir, "run"), 0o700); err != nil {
		t.Fatal(err)
	}
	listen := func(name string) net.Listener {
		l, err := net.Listen("unix", filepath.Join(dir, "run", name))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		return l
	}
	session, admin := listen("broker.sock"), listen("admin.sock")
	var sessionHits atomic.Int32
	go func() {
		for {
			c, err := session.Accept()
			if err != nil {
				return
			}
			sessionHits.Add(1)
			c.Close()
		}
	}()
	got := make(chan []byte, 1)
	go func() {
		c, err := admin.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b, _ := io.ReadAll(c)
		got <- b
		io.WriteString(c, "ok\n")
	}()
	body := []byte(`{"version": 1, "projects": {}}`)
	if code, out, errOut := sshAdmin(t, dir, "policy-load", body); code != 0 || out != "" || errOut != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	select {
	case b := <-got:
		if string(b) != "policy-load\n"+string(body) {
			t.Fatalf("admin.sock got %q", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("admin.sock got nothing")
	}
	if n := sessionHits.Load(); n != 0 {
		t.Fatalf("broker.sock dialed %d times", n)
	}
}
