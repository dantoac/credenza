// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: GPL-3.0-or-later

// Package token keeps the temporary tokens handed out by mint, in memory
// only. Each token carries the scope it was minted with: task, project,
// grant env and secret name, the grant's rules, its start and a lease
// expiry that Renew extends.
package token

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/dantoac/credenza/internal/policy"
)

// DefaultPrefix starts every token whose grant has no token_prefix.
const DefaultPrefix = "fbt_"

const tokenBytes = 32

// MaxLive caps the live tokens a registry holds. Each repeated mint adds
// tokens until revoke or TTL, so without a cap a looping minter could
// grow the registry, and every audit allow line, without bound.
const MaxLive = 1024

// ErrFull is returned by Room and Mint when the cap would be exceeded.
var ErrFull = fmt.Errorf("token limit reached (%d live tokens); revoke finished tasks", MaxLive)

var taskID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// ErrNoTokens is returned by Renew when the task has no live token.
var ErrNoTokens = errors.New("no live tokens")

// ErrMaxSession is returned by Renew when the task's session reached its
// absolute limit; its tokens are revoked.
var ErrMaxSession = errors.New("max session reached; tokens revoked")

// Scope is what a token allows: the rules of one grant until Expires.
// Started is the mint time and never changes. Done is closed when the
// token leaves the registry: on Revoke, when Prune drops it expired and
// when Renew drops it; requests in flight with the token end then.
type Scope struct {
	Task, Project, Env, Secret string
	Rules                      []policy.Rule
	Started, Expires           time.Time
	Done                       <-chan struct{}
}

// entry is a stored token: its scope and the channel behind Scope.Done.
type entry struct {
	scope Scope
	done  chan struct{}
}

// Issued is one minted token and the env name the client stores it under.
type Issued struct{ Env, Token string }

// Registry maps live tokens to their scope. It is safe for concurrent use.
type Registry struct {
	mu      sync.RWMutex
	byToken map[string]*entry
	now     func() time.Time
	max     int
}

// NewRegistry returns an empty registry that reads the time from now,
// or from time.Now when now is nil.
func NewRegistry(now func() time.Time) *Registry {
	if now == nil {
		now = time.Now
	}
	return &Registry{byToken: map[string]*entry{}, now: now, max: MaxLive}
}

// ValidTaskID reports whether s matches ^[A-Za-z0-9._-]{1,64}$.
func ValidTaskID(s string) bool {
	return taskID.MatchString(s)
}

// Mint issues one token per grant (prefix = grant.TokenPrefix or
// DefaultPrefix, then base64.RawURLEncoding of 32 bytes from crypto/rand),
// Expires = now + grant.TTL. Result sorted by Env. Existing tokens of the
// task stay valid. A task holds tokens of one project only: a mint for
// another project while the task has live tokens fails, because Renew
// applies one project's grants to every token of the task. On error,
// ErrFull included, no token is added.
func (r *Registry) Mint(task, project string, grants []policy.Grant) ([]Issued, error) {
	if !ValidTaskID(task) {
		return nil, errors.New("invalid task id")
	}
	if !policy.ValidProject(project) {
		return nil, errors.New("invalid project")
	}
	if len(grants) == 0 {
		return nil, errors.New("no grants to mint")
	}
	now := r.now()
	issued := make([]Issued, 0, len(grants))
	scopes := make([]Scope, 0, len(grants))
	for _, g := range grants {
		if g.TTL <= 0 {
			return nil, fmt.Errorf("grant %q has no positive TTL", g.Env)
		}
		tok, err := newToken(g.TokenPrefix)
		if err != nil {
			return nil, err
		}
		issued = append(issued, Issued{Env: g.Env, Token: tok})
		scopes = append(scopes, Scope{
			Task: task, Project: project, Env: g.Env, Secret: g.Secret,
			Rules: cloneRules(g.Allow), Started: now, Expires: now.Add(g.TTL),
		})
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.otherProject(now, task, project); err != nil {
		return nil, err
	}
	// Expired tokens of the task from another project would still be
	// renewed by name; drop them now rather than at the next Prune.
	for tok, e := range r.byToken {
		if e.scope.Task == task && e.scope.Project != project {
			r.drop(tok, e)
		}
	}
	if err := r.room(now, len(issued)); err != nil {
		return nil, err
	}
	for _, is := range issued {
		// 256 random bits never collide in practice; refuse rather than
		// hand one task's token to another.
		if _, dup := r.byToken[is.Token]; dup {
			return nil, errors.New("token collision")
		}
	}
	for i, is := range issued {
		done := make(chan struct{})
		scopes[i].Done = done
		r.byToken[is.Token] = &entry{scope: scopes[i], done: done}
	}
	sort.Slice(issued, func(i, j int) bool { return issued[i].Env < issued[j].Env })
	return issued, nil
}

// CheckProject returns the error Mint would give because task has live
// tokens of a project other than project. A caller that serializes its
// mints can check before writing an audit allow.
func (r *Registry) CheckProject(task, project string) error {
	now := r.now()
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.otherProject(now, task, project)
}

// otherProject is CheckProject with r.mu held.
func (r *Registry) otherProject(now time.Time, task, project string) error {
	for _, e := range r.byToken {
		if e.scope.Task == task && e.scope.Project != project && now.Before(e.scope.Expires) {
			return fmt.Errorf("task %q has live tokens of another project; revoke it first", task)
		}
	}
	return nil
}

// Room returns ErrFull when n more tokens would exceed the cap. A caller
// that serializes its mints can check before writing an audit allow.
func (r *Registry) Room(n int) error {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.room(now, n)
}

// room drops expired tokens when n more would exceed the cap, then
// checks again. r.mu must be held.
func (r *Registry) room(now time.Time, n int) error {
	if len(r.byToken)+n <= r.max {
		return nil
	}
	r.prune(now)
	if len(r.byToken)+n > r.max {
		return ErrFull
	}
	return nil
}

// Revoke removes every token of task, expired or not, closes their Done
// channels and returns the count.
func (r *Registry) Revoke(task string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.revoke(task)
}

// revoke is Revoke with r.mu held.
func (r *Registry) revoke(task string) int {
	n := 0
	for tok, e := range r.byToken {
		if e.scope.Task == task {
			r.drop(tok, e)
			n++
		}
	}
	return n
}

// drop removes tok and closes its Done channel. r.mu must be held.
func (r *Registry) drop(tok string, e *entry) {
	delete(r.byToken, tok)
	close(e.done)
}

// Renew re-applies grants to the live tokens of task and extends their
// lease. Each token takes the grant with the same Env: Secret and Rules
// become the grant's, Expires becomes min(now+grant.TTL, Started+maxSession).
// When Secret or Rules change, the token's Done closes and a new one
// replaces it, so requests in flight under the old scope end and new ones
// are checked against the new rules; an unchanged scope keeps them open.
// A token whose Env has no grant is dropped, and so is an expired one.
// It returns the live count after the renew; ErrNoTokens when none is
// left, and ErrMaxSession, with every token of task revoked, when now is
// at or past Started+maxSession of any of its tokens, expired or not:
// a renewed lease ends at that bound, so the check comes first.
func (r *Registry) Renew(task string, grants []policy.Grant, maxSession time.Duration) (live int, err error) {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.byToken {
		if e.scope.Task == task && !now.Before(e.scope.Started.Add(maxSession)) {
			r.revoke(task)
			return 0, ErrMaxSession
		}
	}
	for tok, e := range r.byToken {
		if e.scope.Task != task {
			continue
		}
		if !now.Before(e.scope.Expires) {
			r.drop(tok, e)
			continue
		}
		i := slices.IndexFunc(grants, func(g policy.Grant) bool { return g.Env == e.scope.Env })
		if i < 0 || grants[i].TTL <= 0 {
			r.drop(tok, e)
			continue
		}
		g := grants[i]
		if e.scope.Secret != g.Secret || !sameRules(e.scope.Rules, g.Allow) {
			close(e.done)
			e.done = make(chan struct{})
			e.scope.Done = e.done
		}
		e.scope.Secret = g.Secret
		e.scope.Rules = cloneRules(g.Allow)
		e.scope.Expires = now.Add(g.TTL)
		if end := e.scope.Started.Add(maxSession); end.Before(e.scope.Expires) {
			e.scope.Expires = end
		}
		live++
	}
	if live == 0 {
		return 0, ErrNoTokens
	}
	return live, nil
}

// Project returns the project of task's tokens, false when the registry
// holds none. Expired tokens that Prune has not dropped yet count, so a
// renew in the seconds before that Prune still reports a session at its
// limit as ErrMaxSession; after it, the same session gets ErrNoTokens.
func (r *Registry) Project(task string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, e := range r.byToken {
		if e.scope.Task == task {
			return e.scope.Project, true
		}
	}
	return "", false
}

// Lookup returns the scope of tok, false when tok is unknown or expired.
// The returned Rules are a copy the caller may modify.
func (r *Registry) Lookup(tok string) (Scope, bool) {
	now := r.now()
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.byToken[tok]
	if !ok || !now.Before(e.scope.Expires) {
		return Scope{}, false
	}
	s := e.scope
	s.Rules = cloneRules(s.Rules)
	return s, true
}

// HostAllowed reports whether some live token has a rule for host.
func (r *Registry) HostAllowed(host string) bool {
	now := r.now()
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, e := range r.byToken {
		if !now.Before(e.scope.Expires) {
			continue
		}
		for _, rule := range e.scope.Rules {
			if rule.Host == host {
				return true
			}
		}
	}
	return false
}

// Prune drops expired tokens, closes their Done channels and returns how
// many it dropped. Run often: it is what ends the requests in flight of
// an expired token.
func (r *Registry) Prune() int {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.prune(now)
}

// prune is Prune with r.mu held.
func (r *Registry) prune(now time.Time) int {
	n := 0
	for tok, e := range r.byToken {
		if !now.Before(e.scope.Expires) {
			r.drop(tok, e)
			n++
		}
	}
	return n
}

func newToken(prefix string) (string, error) {
	if prefix == "" {
		prefix = DefaultPrefix
	}
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random token: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// sameRules reports whether a and b allow the same, rule by rule.
func sameRules(a, b []policy.Rule) bool {
	return slices.EqualFunc(a, b, func(x, y policy.Rule) bool {
		return x.Host == y.Host && slices.Equal(x.Methods, y.Methods) && slices.Equal(x.Paths, y.Paths)
	})
}

func cloneRules(rules []policy.Rule) []policy.Rule {
	out := make([]policy.Rule, len(rules))
	for i, rule := range rules {
		// Copy the whole struct so a field added to Rule is kept, not dropped.
		rule.Methods = slices.Clone(rule.Methods)
		rule.Paths = slices.Clone(rule.Paths)
		out[i] = rule
	}
	return out
}
