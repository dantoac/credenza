// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: GPL-3.0-or-later

// Package control is the broker's control plane, one request per
// connection on two Unix sockets, and the client that turns the answer
// into the contract exit codes.
//
// Session socket (Serve, broker.sock): "mint <task> <project>
// [<env>...]\n" (at most MaxMintEnvs env names),
// "renew <task>\n" or "revoke <task>\n".
//
// Admin socket (ServeAdmin, admin.sock): "secret-set <name> [replace]\n"
// followed by one "<value>\n" line and the end of the client's writes,
// "secret-rm <name>\n", or "policy-load\n" followed by the policy file
// and the end of the client's writes.
//
// Each socket answers the other's verbs with "usage". Response: a first
// line "ok", "usage <msg>", "deny <msg>", "gone <msg>" (renew only) or
// "error <msg>"; after "ok" for mint, one "NAME=VALUE" line per token;
// then the server closes.
package control

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/dantoac/credenza/internal/audit"
	"github.com/dantoac/credenza/internal/policy"
	"github.com/dantoac/credenza/internal/store"
	"github.com/dantoac/credenza/internal/token"
)

// Exit codes of the mint, renew and revoke contract.
const (
	ExitOK     = 0
	ExitErr    = 1
	ExitUsage  = 2
	ExitLocked = 3
	ExitDenied = 4
	ExitGone   = 5 // renew: the task has no live tokens
)

// DefaultMaxSession is the absolute session limit when
// Service.MaxSession is zero.
const DefaultMaxSession = 24 * time.Hour

var (
	ErrUsage  = errors.New("usage")
	ErrDenied = errors.New("policy denies the project")
	// ErrInvalidPolicy marks a LoadPolicy error for a body that is not a
	// policy serve can enforce, as opposed to a failed write.
	ErrInvalidPolicy = errors.New("invalid policy")
)

const (
	// deadline bounds each session connection, on both sides.
	deadline = 10 * time.Second
	// adminDeadline bounds an admin connection, on both sides: a secret
	// verb loads and saves the store, two key derivations and an fsync,
	// possibly on slow removable storage.
	adminDeadline = time.Minute
	// maxRequest is more than the longest valid request line:
	// "mint " + 64 + " " + 201 + MaxMintEnvs * (" " + 64) + "\n" is 466
	// bytes. It bounds the first line on both sockets.
	maxRequest = 512
	// maxResponse bounds what Call reads back.
	maxResponse    = 64 << 10
	usageText      = "mint <task-id> <project> [<env>...] | renew <task-id> | revoke <task-id>"
	adminUsageText = "secret-set <name> [replace] | secret-rm <name> | policy-load"
	lockedText     = "broker is locked or not running"
)

// MaxMintEnvs is the most env names a mint may list to narrow its grants.
const MaxMintEnvs = 3

// MaxSecretValue is the longest value secret-set accepts, in bytes; with
// its request line the request stays within 16 KiB plus maxRequest.
const MaxSecretValue = 16 << 10

// MaxPolicy is the longest policy file policy-load accepts, in bytes.
const MaxPolicy = 256 << 10

// Service runs mint, renew and revoke, and with ServeAdmin the secret
// verbs. Every field is required except MaxSession, and SetSecret,
// RemoveSecret and LoadPolicy, which only ServeAdmin needs.
type Service struct {
	Policy    func() (*policy.Policy, error) // serve passes func() { return policy.Load(path) }: re-read on every mint and renew
	HasSecret func(name string) bool
	CheckHost func(host string) error // serve passes ca.CA.CheckHost
	Tokens    *token.Registry
	Audit     *audit.Log
	// MaxSession bounds a task's lease from its mint; zero means
	// DefaultMaxSession.
	MaxSession time.Duration
	// SetSecret stores value under name, on disk and live; RemoveSecret
	// deletes name. Their errors never quote a value. serve wires them
	// to its liveSecrets.
	SetSecret    func(name, value string) error
	RemoveSecret func(name string) error
	// LoadPolicy validates body as the policy file and replaces the file
	// with it; the next mint and renew read it. An error for a body serve
	// refuses wraps ErrInvalidPolicy. serve wires it to its loadPolicy.
	LoadPolicy func(body []byte) error

	// adminMu serializes the admin verbs, so the existence check of a
	// secret-set without replace holds until its write.
	adminMu sync.Mutex

	// mintMu serializes the cap check, the audit allow lines and the
	// registry insert, so a mint that passed the check cannot be refused
	// by the registry after its allow lines are written.
	mintMu sync.Mutex
}

// Mint issues one token per grant of project for task. With envs, only
// the grants with those env names, which must all be grants of project:
// the caller can narrow a mint, never widen it, and renew only extends
// tokens already minted. The audit allow lines are written before the
// registry insert, so an audit failure leaves the registry untouched and
// earlier tokens of task stay valid. A mint beyond token.MaxLive fails
// before any allow line.
func (s *Service) Mint(task, project string, envs ...string) ([]token.Issued, error) {
	if !token.ValidTaskID(task) {
		return nil, fmt.Errorf("%w: invalid task id", ErrUsage)
	}
	if !policy.ValidProject(project) {
		return nil, fmt.Errorf("%w: invalid project, want owner/repo", ErrUsage)
	}
	if err := checkEnvs(envs); err != nil {
		return nil, err
	}
	// policy.Load errors already start with "policy: ".
	p, err := s.Policy()
	if err != nil {
		return nil, err
	}
	grants, _ := p.Grants(project)
	if len(grants) == 0 {
		if err := s.Audit.Write(audit.Event{Event: "mint", Task: task, Project: project, Decision: "deny", Reason: "project"}); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w %q", ErrDenied, project)
	}
	if len(envs) > 0 {
		var missing string
		grants, missing = selectGrants(grants, envs)
		if missing != "" {
			if err := s.Audit.Write(audit.Event{Event: "mint", Task: task, Project: project, Decision: "deny", Reason: "env"}); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("%w %q: no grant for %s", ErrDenied, project, missing)
		}
	}
	if err := s.checkGrants(grants); err != nil {
		return nil, err
	}
	s.mintMu.Lock()
	defer s.mintMu.Unlock()
	if err := s.Tokens.CheckProject(task, project); err != nil {
		return nil, err
	}
	if err := s.Tokens.Room(len(grants)); err != nil {
		return nil, err
	}
	for _, g := range grants {
		if err := s.Audit.Write(audit.Event{Event: "mint", Task: task, Project: project, Secret: g.Secret, Decision: "allow"}); err != nil {
			return nil, err
		}
	}
	return s.Tokens.Mint(task, project, grants)
}

// checkEnvs refuses more than MaxMintEnvs env names, an invalid one or a
// repeated one.
func checkEnvs(envs []string) error {
	if len(envs) > MaxMintEnvs {
		return fmt.Errorf("%w: at most %d env names", ErrUsage, MaxMintEnvs)
	}
	for i, e := range envs {
		if !policy.ValidEnv(e) {
			return fmt.Errorf("%w: invalid env name", ErrUsage)
		}
		if slices.Contains(envs[:i], e) {
			return fmt.Errorf("%w: env %s repeated", ErrUsage, e)
		}
	}
	return nil
}

// selectGrants returns the grants whose env is in envs, in policy order,
// or the first env of envs that no grant has.
func selectGrants(grants []policy.Grant, envs []string) ([]policy.Grant, string) {
	var sel []policy.Grant
	for _, e := range envs {
		i := slices.IndexFunc(grants, func(g policy.Grant) bool { return g.Env == e })
		if i < 0 {
			return nil, e
		}
	}
	for _, g := range grants {
		if slices.Contains(envs, g.Env) {
			sel = append(sel, g)
		}
	}
	return sel, ""
}

// checkGrants refuses grants whose secret is missing from the store or
// whose host the CA cannot serve.
func (s *Service) checkGrants(grants []policy.Grant) error {
	for _, g := range grants {
		if !s.HasSecret(g.Secret) {
			return fmt.Errorf("policy: secret %q not in store", g.Secret)
		}
	}
	checked := map[string]bool{}
	for _, g := range grants {
		for _, r := range g.Allow {
			if checked[r.Host] {
				continue
			}
			checked[r.Host] = true
			if err := s.CheckHost(r.Host); err != nil {
				return fmt.Errorf("policy: host %q not permitted by the CA: %v", r.Host, err)
			}
		}
	}
	return nil
}

// Renew re-reads the policy, applies the grants of the task's project to
// its live tokens and extends their lease (token.Registry.Renew). It
// returns the live count. A project the policy no longer grants revokes
// the task and returns ErrDenied. token.ErrNoTokens and
// token.ErrMaxSession pass through; the answer maps both to "gone". A
// policy, secret or host error changes nothing: the lease runs out.
func (s *Service) Renew(task string) (int, error) {
	if !token.ValidTaskID(task) {
		return 0, fmt.Errorf("%w: invalid task id", ErrUsage)
	}
	project, ok := s.Tokens.Project(task)
	if !ok {
		if err := s.Audit.Write(audit.Event{Event: "renew", Task: task, Decision: "deny", Reason: "gone"}); err != nil {
			return 0, err
		}
		return 0, token.ErrNoTokens
	}
	p, err := s.Policy()
	if err != nil {
		return 0, err
	}
	grants, _ := p.Grants(project)
	if len(grants) == 0 {
		s.Tokens.Revoke(task)
		if err := s.Audit.Write(audit.Event{Event: "renew", Task: task, Project: project, Decision: "deny", Reason: "project"}); err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("%w %q", ErrDenied, project)
	}
	if err := s.checkGrants(grants); err != nil {
		return 0, err
	}
	maxSession := s.MaxSession
	if maxSession == 0 {
		maxSession = DefaultMaxSession
	}
	live, err := s.Tokens.Renew(task, grants, maxSession)
	if err != nil {
		reason := "gone"
		if errors.Is(err, token.ErrMaxSession) {
			reason = "max-session"
		}
		if werr := s.Audit.Write(audit.Event{Event: "renew", Task: task, Project: project, Decision: "deny", Reason: reason}); werr != nil {
			return 0, werr
		}
		return 0, err
	}
	// The lease is already extended; a failed write here is harmless
	// because the proxy forwards nothing while the audit log fails.
	if err := s.Audit.Write(audit.Event{Event: "renew", Task: task, Project: project, Decision: "allow", Reason: fmt.Sprintf("live=%d", live)}); err != nil {
		return live, err
	}
	return live, nil
}

// Revoke removes every token of task and returns how many it removed.
// The tokens are gone before the audit write, so a failed write leaves
// the safe side.
func (s *Service) Revoke(task string) (int, error) {
	if !token.ValidTaskID(task) {
		return 0, fmt.Errorf("%w: invalid task id", ErrUsage)
	}
	n := s.Tokens.Revoke(task)
	if err := s.Audit.Write(audit.Event{Event: "revoke", Task: task, Decision: "allow"}); err != nil {
		return n, err
	}
	return n, nil
}

// SecretSet stores value under name. Without replace, an existing name
// is refused. The audit event names the secret and the action, never the
// value; it is written after the store, so a failed audit write reports
// an error for a value that is already live.
func (s *Service) SecretSet(name, value string, replace bool) error {
	if !store.ValidSecretName(name) {
		return fmt.Errorf("%w: invalid secret name", ErrUsage)
	}
	if err := CheckSecretValue(value); err != nil {
		return err
	}
	s.adminMu.Lock()
	defer s.adminMu.Unlock()
	action := "add"
	if s.HasSecret(name) {
		if !replace {
			return fmt.Errorf("secret %s exists; use -replace to overwrite it", name)
		}
		action = "replace"
	}
	if err := s.SetSecret(name, value); err != nil {
		return err
	}
	return s.Audit.Write(audit.Event{Event: "secret", Secret: name, Decision: "allow", Reason: action})
}

// CheckSecretValue refuses an empty value, any control byte and outer
// spaces: the value goes into an HTTP header, where CR or LF would split
// it. The error never quotes the value.
func CheckSecretValue(v string) error {
	if v == "" {
		return errors.New("secret value is empty")
	}
	for i := 0; i < len(v); i++ {
		if b := v[i]; b < 0x20 || b == 0x7f {
			return errors.New("secret value contains a control character")
		}
	}
	// HTTP trims header values, so the upstream would see another value.
	if strings.TrimSpace(v) != v {
		return errors.New("secret value starts or ends with a space")
	}
	// The store is JSON, which would save U+FFFD in place of invalid
	// bytes: the value used now and the one used after a restart differ.
	if !utf8.ValidString(v) {
		return errors.New("secret value is not valid UTF-8")
	}
	return nil
}

// SecretRemove deletes name from the store and the live map.
func (s *Service) SecretRemove(name string) error {
	if !store.ValidSecretName(name) {
		return fmt.Errorf("%w: invalid secret name", ErrUsage)
	}
	s.adminMu.Lock()
	defer s.adminMu.Unlock()
	if err := s.RemoveSecret(name); err != nil {
		return err
	}
	return s.Audit.Write(audit.Event{Event: "secret", Secret: name, Decision: "allow", Reason: "rm"})
}

// PolicyLoad passes body to LoadPolicy. The audit event "policy" carries
// the body's sha256, "allow" after the file is replaced, "deny" with
// "invalid" or "failed" otherwise. It is written after LoadPolicy, so a
// failed audit write reports an error for a policy that is already in
// force.
func (s *Service) PolicyLoad(body []byte) error {
	s.adminMu.Lock()
	defer s.adminMu.Unlock()
	sum := fmt.Sprintf("sha256=%x", sha256.Sum256(body))
	err := s.LoadPolicy(body)
	ev := audit.Event{Event: "policy", Decision: "allow", Reason: sum}
	switch {
	case errors.Is(err, ErrInvalidPolicy):
		ev.Decision, ev.Reason = "deny", "invalid "+sum
	case err != nil:
		ev.Decision, ev.Reason = "deny", "failed "+sum
	}
	if werr := s.Audit.Write(ev); werr != nil && err == nil {
		return werr
	}
	return err
}

// Listen creates the socket directory with mode 0700 and listens on path
// with mode 0600. A socket left at path by a broker that died is removed;
// a socket that still answers means another serve runs, and Listen fails.
// The parent of the socket directory must exist: Listen creates nothing
// above it, so a missing state directory is not recreated.
func Listen(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("socket directory %s is not a directory", dir)
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		return nil, fmt.Errorf("socket directory %s has mode %04o, want 0700", dir, perm)
	}
	if err := removeStale(path); err != nil {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// removeStale removes a socket at path that refuses connections. It
// leaves anything else in place and returns an error for it.
func removeStale(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSocket == 0 {
		return fmt.Errorf("%s exists and is not a socket", path)
	}
	c, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		c.Close()
		return fmt.Errorf("another credenza serve is running on %s", path)
	}
	// Treat only a refused connection as stale. On Linux a live server
	// with a full backlog gives EAGAIN, not ECONNREFUSED; darwin and
	// FreeBSD refuse in that case too, which needs a stopped serve.
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("check socket %s: %w", path, err)
	}
	return os.Remove(path)
}

// Serve answers the session verbs on l, each connection in its own
// goroutine. It returns nil when l is closed, after the connections in
// progress are done.
func Serve(l net.Listener, s *Service) error {
	return serve(l, s.handle)
}

// ServeAdmin is Serve for the admin verbs.
func ServeAdmin(l net.Listener, s *Service) error {
	return serve(l, s.handleAdmin)
}

func serve(l net.Listener, handle func(net.Conn)) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	var backoff time.Duration
	for {
		c, err := l.Accept()
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		if err != nil {
			// EMFILE and similar pass; retry like net/http does.
			backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		wg.Add(1)
		go func() {
			defer wg.Done()
			handle(c)
		}()
	}
}

func (s *Service) handle(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(deadline))
	line, err := bufio.NewReader(io.LimitReader(c, maxRequest)).ReadString('\n')
	if err != nil {
		io.WriteString(c, "usage "+usageError().Error()+"\n")
		return
	}
	io.WriteString(c, s.answer(strings.TrimSuffix(line, "\n")))
}

func (s *Service) handleAdmin(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(adminDeadline))
	lr := &io.LimitedReader{R: c, N: maxRequest}
	r := bufio.NewReader(lr)
	line, err := r.ReadString('\n')
	if err != nil {
		io.WriteString(c, "usage "+adminUsageError().Error()+"\n")
		return
	}
	args := strings.Split(strings.TrimSuffix(line, "\n"), " ")
	switch {
	case (len(args) == 2 || len(args) == 3 && args[2] == "replace") && args[0] == "secret-set":
		// The value line and the end of the writes: one byte more than
		// the longest value line shows a value that is too long.
		lr.N += MaxSecretValue + 2
		value, err := readValue(r)
		if err == nil {
			err = s.SecretSet(args[1], value, len(args) == 3)
		}
		io.WriteString(c, response(err))
	case len(args) == 2 && args[0] == "secret-rm":
		io.WriteString(c, response(s.SecretRemove(args[1])))
	case len(args) == 1 && args[0] == "policy-load":
		// One byte more than MaxPolicy shows a body that is too long.
		lr.N += MaxPolicy + 1
		body, err := io.ReadAll(r)
		switch {
		case err != nil:
			err = fmt.Errorf("%w: read policy", ErrUsage)
		case len(body) > MaxPolicy:
			err = fmt.Errorf("%w: policy longer than %d bytes", ErrUsage, MaxPolicy)
		default:
			err = s.PolicyLoad(body)
		}
		io.WriteString(c, response(err))
	default:
		io.WriteString(c, response(adminUsageError()))
	}
}

// readValue reads the rest of a secret-set request: exactly one line of
// at most MaxSecretValue bytes, then the end of the client's writes. The
// error never quotes the value.
func readValue(r io.Reader) (string, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("%w: read secret value", ErrUsage)
	}
	v, ok := strings.CutSuffix(string(b), "\n")
	if !ok || strings.Contains(v, "\n") || len(v) > MaxSecretValue {
		return "", fmt.Errorf("%w: want one secret value line of at most %d bytes", ErrUsage, MaxSecretValue)
	}
	return v, nil
}

// answer runs one request line and returns the whole response.
func (s *Service) answer(line string) string {
	args := strings.Split(line, " ")
	var issued []token.Issued
	var err error
	switch {
	case len(args) >= 3 && len(args) <= 3+MaxMintEnvs && args[0] == "mint":
		issued, err = s.Mint(args[1], args[2], args[3:]...)
	case len(args) == 2 && args[0] == "renew":
		_, err = s.Renew(args[1])
	case len(args) == 2 && args[0] == "revoke":
		_, err = s.Revoke(args[1])
	default:
		err = usageError()
	}
	if err != nil {
		return response(err)
	}
	var b strings.Builder
	b.WriteString("ok\n")
	for _, is := range issued {
		b.WriteString(is.Env + "=" + is.Token + "\n")
	}
	return b.String()
}

// response is the first line for err, "ok" when it is nil.
func response(err error) string {
	switch {
	case err == nil:
		return "ok\n"
	case errors.Is(err, ErrUsage):
		return "usage " + oneLine(err.Error()) + "\n"
	case errors.Is(err, ErrDenied):
		return "deny " + oneLine(err.Error()) + "\n"
	case errors.Is(err, token.ErrNoTokens), errors.Is(err, token.ErrMaxSession):
		return "gone " + oneLine(err.Error()) + "\n"
	}
	return "error " + oneLine(err.Error()) + "\n"
}

func usageError() error {
	return fmt.Errorf("%w: %s", ErrUsage, usageText)
}

func adminUsageError() error {
	return fmt.Errorf("%w: %s", ErrUsage, adminUsageText)
}

// oneLine replaces control bytes with spaces so a message stays one line.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// Up reports whether a server answers on the socket at path. It only
// connects: the server sees an empty request and closes.
func Up(path string) bool {
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// Call sends args as one request to the socket at socketPath, copies the
// NAME=VALUE lines of an ok answer to stdout and returns the exit code
// and, unless it is ExitOK, a one-line message without the "credenza: "
// prefix. stdout gets nothing unless the whole answer was read.
func Call(socketPath string, args []string, stdout io.Writer) (exit int, errLine string) {
	return CallBody(socketPath, args, nil, stdout)
}

// CallBody is Call with body sent after the request line; a non-nil
// body is followed by the end of the writes, which secret-set needs, and
// marks an admin call, which gets adminDeadline. Neither the body nor
// anything derived from it is ever in errLine.
func CallBody(socketPath string, args []string, body []byte, stdout io.Writer) (exit int, errLine string) {
	if len(args) == 0 {
		return ExitUsage, usageError().Error()
	}
	for _, a := range args {
		// Spaces and newlines would change the request's framing.
		if a == "" || strings.ContainsFunc(a, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
			return ExitUsage, usageError().Error()
		}
	}
	// One deadline covers the dial and the whole exchange.
	end := time.Now().Add(deadline)
	if body != nil {
		end = time.Now().Add(adminDeadline)
	}
	c, err := (&net.Dialer{Deadline: end}).Dial("unix", socketPath)
	if err != nil {
		return ExitLocked, lockedText
	}
	defer c.Close()
	c.SetDeadline(end)
	if _, err := io.WriteString(c, strings.Join(args, " ")+"\n"); err != nil {
		return ExitErr, oneLine("send request: " + err.Error())
	}
	if body != nil {
		// A server that refused the request line may close before the
		// body is written; its answer still says why.
		if _, err := c.Write(body); err == nil {
			if uc, ok := c.(*net.UnixConn); ok {
				uc.CloseWrite()
			}
		}
	}
	resp, err := io.ReadAll(io.LimitReader(c, maxResponse+1))
	if err != nil {
		return ExitErr, oneLine("read response: " + err.Error())
	}
	if len(resp) > maxResponse {
		return ExitErr, "response too long"
	}
	first, rest, ok := strings.Cut(string(resp), "\n")
	if !ok {
		return ExitErr, "truncated response"
	}
	kind, msg, _ := strings.Cut(first, " ")
	switch kind {
	case "ok":
		if rest != "" && !strings.HasSuffix(rest, "\n") {
			return ExitErr, "truncated response"
		}
		if _, err := io.WriteString(stdout, rest); err != nil {
			return ExitErr, oneLine("write output: " + err.Error())
		}
		return ExitOK, ""
	case "usage":
		return ExitUsage, oneLine(msg)
	case "deny":
		return ExitDenied, oneLine(msg)
	case "gone":
		return ExitGone, oneLine(msg)
	case "error":
		return ExitErr, oneLine(msg)
	}
	return ExitErr, "unexpected response"
}
