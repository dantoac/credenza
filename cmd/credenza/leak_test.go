// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stdLog records everything written to the standard log package, which
// is where a server or ReverseProxy with a nil ErrorLog would write.
var stdLog = &lockedBuffer{}

func init() { log.SetOutput(stdLog) }

// TestSecretNeverLeaks runs one full session with canary secrets and checks every output.
func TestSecretNeverLeaks(t *testing.T) {
	const (
		ghCanary   = "ghp_CANARY_GH_7f3a"
		clCanary   = "sk-ant-oat01-CANARY_CL_9b2c"
		passCanary = "CANARY passphrase 5e1d"
		// Set live through admin.sock while serve runs.
		rotCanary = "ghp_CANARY_ROTATED_c4d8"
		badCanary = "ghp_CANARY_BAD_0a6e"
	)
	secrets := []string{ghCanary, clCanary, passCanary, rotCanary, badCanary,
		// The git Basic credential as the broker rewrites it.
		base64.StdEncoding.EncodeToString([]byte("x-access-token:" + ghCanary)),
		base64.StdEncoding.EncodeToString([]byte("x-access-token:" + rotCanary)),
	}
	// logs must hold neither a secret nor a minted token; responses (what a
	// client gets back, and mint's own stdout) must hold no secret.
	var logs, responses []string
	var tokens []string

	fx := &fixture{pass: passCanary, gh: ghCanary, cl: clCanary}
	dir := setupDirWith(t, fx)
	logs = append(logs, fx.outputs...)
	var caPEM []byte
	for _, s := range []struct {
		want    int
		answers []string
		args    []string
	}{
		{0, []string{passCanary}, []string{"secret", "list", "-dir", dir}},
		{0, []string{passCanary}, []string{"ca-cert", "-dir", dir}},
		{0, nil, []string{"policy", "check", "-dir", dir}},
		{1, []string{"wrong " + passCanary}, []string{"secret", "list", "-dir", dir}},
	} {
		f := credenza(t, s.want, s.answers, s.args...)
		logs = append(logs, f.out.String(), f.errb.String())
		if s.args[0] == "ca-cert" {
			caPEM = f.out.Bytes()
		}
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("ca-cert output is not a PEM certificate")
	}

	up := newUpstream(t)
	clock := &fakeClock{t: time.Now()}
	s := launch(t, dir, newServeIO(passCanary, clock.Now))
	client := proxyClient(t, s.proxyAddr, caPEM)

	// ssh runs ssh-command and returns its stdout on exit 0, else its stderr.
	ssh := func(want int, command string) string {
		t.Helper()
		code, out, errOut := sshCommand(t, dir, command)
		if code != want {
			t.Fatalf("ssh-command %q: exit %d, want %d; stderr %q", command, code, want, errOut)
		}
		logs = append(logs, errOut)
		responses = append(responses, out)
		if code == 0 {
			return out
		}
		return errOut
	}
	mintTask := func(task string) map[string]string {
		t.Helper()
		toks := parseMint(t, ssh(0, "mint "+task+" example/app"))
		for _, v := range toks {
			tokens = append(tokens, v)
		}
		return toks
	}
	record := func(resp *http.Response, body string) {
		responses = append(responses, body)
		for _, h := range []http.Header{resp.Header, resp.Trailer} {
			for k, vs := range h {
				responses = append(responses, k+": "+strings.Join(vs, ", "))
			}
		}
	}
	send := func(req *http.Request) (*http.Response, string) {
		t.Helper()
		resp, err := client.Do(req)
		if err != nil {
			responses = append(responses, err.Error())
			t.Fatalf("%s %s: %v", req.Method, req.URL, err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		record(resp, string(b))
		return resp, string(b)
	}
	request := func(method, rawURL, auth string) *http.Request {
		t.Helper()
		req, err := http.NewRequest(method, rawURL, strings.NewReader(""))
		if err != nil {
			t.Fatal(err)
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		return req
	}
	basic := func(tok string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+tok))
	}
	// rawTunnel opens a CONNECT tunnel to api.github.com, writes raw inside
	// it and returns the status of the answer.
	rawTunnel := func(raw string) int {
		t.Helper()
		conn, _, resp := rawConnect(t, s.proxyAddr, "api.github.com:443")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("CONNECT: status %d", resp.StatusCode)
		}
		tc := tls.Client(conn, &tls.Config{ServerName: "api.github.com", RootCAs: pool})
		defer tc.Close()
		if _, err := io.WriteString(tc, raw); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		record(resp, string(b))
		return resp.StatusCode
	}
	auditLog := func() string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, "audit.log"))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	t1 := mintTask("T1")
	gh, cl := t1["GH_TOKEN"], t1["CLAUDE_CODE_OAUTH_TOKEN"]

	// Allowed requests of the three clients: gh, git over HTTPS, Claude Code.
	for _, c := range []struct {
		method, url, auth, upstreamAuth string
	}{
		{"GET", "https://api.github.com/repos/example/app/pulls", "token " + gh, "token " + ghCanary},
		{"GET", "https://github.com/example/app.git/info/refs?service=git-upload-pack", basic(gh), basic(ghCanary)},
		{"POST", "https://api.anthropic.com/v1/messages?beta=true", "Bearer " + cl, "Bearer " + clCanary},
	} {
		if resp, body := send(request(c.method, c.url, c.auth)); resp.StatusCode != http.StatusOK {
			t.Fatalf("%s %s: status %d, body %q", c.method, c.url, resp.StatusCode, body)
		}
		if got, _ := up.lastAuth(); got != c.upstreamAuth {
			t.Fatalf("%s %s: upstream did not get the real secret", c.method, c.url)
		}
	}

	// The deny cases of TestProxyDenies (internal/proxy), through serve.
	t9 := mintTask("T9")
	ssh(0, "revoke T9")
	for _, c := range []struct {
		name, method, url, opaque string
		auth                      func() []string
		reason                    string
	}{
		{"merge PR", "PUT", "https://api.github.com/repos/example/app/pulls/1/merge", "", nil, "scope"},
		{"delete repo", "DELETE", "https://api.github.com/repos/example/app", "", nil, "scope"},
		{"merge async", "PUT", "https://api.github.com/repos/example/app/pulls/1/merge-async", "", nil, "scope"},
		{"REST POST", "POST", "https://api.github.com/repos/example/app/merges", "", nil, "scope"},
		{"sibling repo", "GET", "https://api.github.com/repos/example/app-evil/pulls", "", nil, "scope"},
		{"dot dot", "GET", "https://api.github.com/", "/repos/example/app/../app-evil/pulls", nil, "path"},
		{"encoded slash", "GET", "https://api.github.com/repos/example%2Fapp/pulls", "", nil, "path"},
		{"git settings", "GET", "https://github.com/example/app/settings", "",
			func() []string { return []string{basic(gh)} }, "scope"},
		{"claude bridge", "POST", "https://api.anthropic.com/v1/environments/bridge", "",
			func() []string { return []string{"Bearer " + cl} }, "scope"},
		{"claude token on github", "GET", "https://api.github.com/repos/example/app/pulls", "",
			func() []string { return []string{"Bearer " + cl} }, "scope"},
		{"unknown token", "GET", "https://api.github.com/repos/example/app/pulls", "",
			func() []string { return []string{"token fbt_nope"} }, "token"},
		{"revoked token", "GET", "https://api.github.com/repos/example/app/pulls", "",
			func() []string { return []string{"token " + t9["GH_TOKEN"]} }, "token"},
		{"two Authorization headers", "GET", "https://api.github.com/repos/example/app/pulls", "",
			func() []string { return []string{"token " + gh, "token " + gh} }, "token"},
		{"unparsable", "GET", "https://api.github.com/repos/example/app/pulls", "",
			func() []string { return []string{"Digest " + gh} }, "token"},
		// Last: it moves the clock past T1's TTL and mints T2.
		{"expired token", "GET", "https://api.github.com/repos/example/app/pulls", "",
			func() []string {
				clock.Advance(9 * time.Hour)
				t2 := mintTask("T2")
				old := gh
				gh, cl = t2["GH_TOKEN"], t2["CLAUDE_CODE_OAUTH_TOKEN"]
				return []string{"token " + old}
			}, "token"},
	} {
		req := request(c.method, c.url, "")
		if c.opaque != "" {
			req.URL.Opaque = c.opaque
		}
		auth := []string{"token " + gh}
		if c.auth != nil {
			auth = c.auth()
		}
		req.Header["Authorization"] = auth
		_, before := up.lastAuth()
		resp, body := send(req)
		if want := "credenza: denied (" + c.reason + ")\n"; resp.StatusCode != http.StatusForbidden || body != want {
			t.Fatalf("%s: status %d, body %q, want 403 %q", c.name, resp.StatusCode, body, want)
		}
		if _, after := up.lastAuth(); after != before {
			t.Fatalf("%s: forwarded upstream", c.name)
		}
	}

	// A request with no Authorization header.
	if resp, _ := send(request("GET", "https://api.github.com/repos/example/app/pulls", "")); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: status %d", resp.StatusCode)
	}

	// An upstream that closes the connection: 502 and an ErrorLog line.
	up.setRespond(func(w http.ResponseWriter, r *http.Request) {
		if conn, _, err := http.NewResponseController(w).Hijack(); err == nil {
			conn.Close()
		}
	})
	if resp, _ := send(request("GET", "https://api.github.com/repos/example/app/pulls", "token "+gh)); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("upstream closed: status %d", resp.StatusCode)
	}

	// An upstream that echoes the Authorization header back.
	up.setRespond(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		_, cred, _ := strings.Cut(auth, " ")
		w.Header().Set("Trailer", "X-Echo-Trailer")
		w.Header().Set("X-Echo", auth)
		w.Header().Set("X-Echo-Cred", cred)
		io.WriteString(w, "ok")
		w.Header().Set("X-Echo-Trailer", auth)
	})
	for _, auth := range []string{"token " + gh, basic(gh)} {
		url := "https://api.github.com/repos/example/app/pulls"
		if strings.HasPrefix(auth, "Basic ") {
			url = "https://github.com/example/app.git/info/refs?service=git-upload-pack"
		}
		if resp, _ := send(request("GET", url, auth)); resp.StatusCode != http.StatusOK {
			t.Fatalf("echo %s: status %d", url, resp.StatusCode)
		}
	}
	up.setRespond(nil)

	// An Upgrade request with a valid token, and a malformed request line,
	// both inside a tunnel.
	if got := rawTunnel("GET /repos/example/app/pulls HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: token " +
		gh + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); got != http.StatusForbidden {
		t.Fatalf("upgrade: status %d", got)
	}
	if got := rawTunnel("GET /repos/example/app/pulls HTTP/1.1 junk\r\nHost: api.github.com\r\nAuthorization: token " +
		gh + "\r\n\r\n"); got != http.StatusBadRequest {
		t.Fatalf("malformed request line: status %d", got)
	}

	// 50 absolute-URI requests without CONNECT: denied, counted, not audited.
	auditBefore := strings.Count(auditLog(), "\n")
	for range 50 {
		conn, err := net.Dial("tcp", s.proxyAddr)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "GET http://api.github.com/repos/example/app/pulls HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: token %s\r\n\r\n", gh)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		conn.Close()
		record(resp, string(b))
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("absolute URI: status %d", resp.StatusCode)
		}
	}
	if after := strings.Count(auditLog(), "\n"); after != auditBefore {
		t.Fatalf("absolute-URI denies wrote %d audit lines", after-auditBefore)
	}

	// Live secret writes through admin.sock: a refused value, a rotation
	// the next request carries, and an add and remove of another name.
	for _, c := range []struct {
		want    int
		answers []string
		args    []string
	}{
		{1, []string{badCanary + "\r"}, []string{"secret", "add", "-dir", dir, "-replace", "github-app"}},
		{1, []string{" " + badCanary}, []string{"secret", "add", "-dir", dir, "-replace", "github-app"}},
		{1, []string{badCanary}, []string{"secret", "add", "-dir", dir, "github-app"}},
		{0, []string{rotCanary}, []string{"secret", "add", "-dir", dir, "-replace", "github-app"}},
		{0, []string{badCanary}, []string{"secret", "add", "-dir", dir, "spare"}},
		{0, nil, []string{"secret", "rm", "-dir", dir, "spare"}},
	} {
		f := credenza(t, c.want, c.answers, c.args...)
		logs = append(logs, f.out.String(), f.errb.String())
	}
	if resp, _ := send(request("GET", "https://api.github.com/repos/example/app/pulls", "token "+gh)); resp.StatusCode != http.StatusOK {
		t.Fatalf("after live rotate: status %d", resp.StatusCode)
	}
	if got, _ := up.lastAuth(); got != "token "+rotCanary {
		t.Fatal("after live rotate: upstream did not get the rotated secret")
	}
	if resp, _ := send(request("GET", "https://github.com/example/app.git/info/refs?service=git-upload-pack", basic(gh))); resp.StatusCode != http.StatusOK {
		t.Fatalf("git after live rotate: status %d", resp.StatusCode)
	}

	// A mint whose policy names a secret that is not in the store.
	writePolicy(t, dir, missingSecretPolicy)
	if errOut := ssh(1, "mint T3 example/app"); errOut != "credenza: policy: secret \"missing-secret\" not in store\n" {
		t.Fatalf("mint with a missing secret: stderr %q", errOut)
	}
	writePolicy(t, dir, nil)

	ssh(0, "revoke T1")
	ssh(0, "revoke T2")
	client.CloseIdleConnections()
	if code := s.stop(); code != 0 {
		t.Fatalf("stop: exit %d, stderr %q", code, s.io.errb)
	}

	errorLog := s.io.errb.String()
	for _, want := range []string{
		"credenza: serving proxy on ",
		"credenza: proxy: upstream error (task T2): ",
		"credenza: proxy: dropped response header X-Echo ",
		"credenza: proxy: dropped response header X-Echo-Cred ",
		"credenza: proxy: dropped response header X-Echo-Trailer ",
		"unaudited denials (client 0, not-connect 1, conn-limit 0, rate-limited 0)",
	} {
		if !strings.Contains(errorLog, want) {
			t.Errorf("serve stderr lacks %q:\n%s", want, errorLog)
		}
	}
	audit := auditLog()
	for _, want := range []string{`"secret":"github-app","host":"github.com"`, `"secret":"claude-oauth","host":"api.anthropic.com"`, `"reason":"upgrade"`,
		`"event":"secret","secret":"github-app","decision":"allow","reason":"replace"`,
		`"event":"secret","secret":"spare","decision":"allow","reason":"add"`,
		`"event":"secret","secret":"spare","decision":"allow","reason":"rm"`} {
		if !strings.Contains(audit, want) {
			t.Errorf("audit log lacks %s", want)
		}
	}

	if out := s.io.out.String(); out != "" {
		t.Errorf("serve wrote to stdout: %q", out)
	}
	logs = append(logs, errorLog, audit, s.io.out.String())
	for i, text := range logs {
		for _, v := range append(secrets, tokens...) {
			if strings.Contains(text, v) {
				t.Errorf("log or output %d carries %q:\n%s", i, v, text)
			}
		}
	}
	for i, text := range append(responses, logs...) {
		for _, v := range secrets {
			if strings.Contains(text, v) {
				t.Errorf("response %d carries %q:\n%s", i, v, text)
			}
		}
	}
	if got := stdLog.String(); got != "" {
		t.Errorf("the standard log package was written to:\n%s", got)
	}
	if n := len(tokens); n != 6 {
		t.Errorf("collected %d tokens, want 6", n)
	}
}
