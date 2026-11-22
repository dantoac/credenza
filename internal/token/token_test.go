// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dantoac/credenza/internal/policy"
)

var t0 = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

// clock is a fake time source safe for concurrent use.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

func ghGrant() policy.Grant {
	return policy.Grant{
		Env:    "GH_TOKEN",
		Secret: "gh-app",
		TTL:    time.Hour,
		Allow: []policy.Rule{
			{Host: "api.github.com", Methods: []string{"GET", "POST"}, Paths: []string{"/repos/example/app/"}},
			{Host: "github.com", Methods: []string{"GET", "POST"}, Paths: []string{"/example/app.git/"}},
		},
	}
}

func claudeGrant() policy.Grant {
	return policy.Grant{
		Env:         "CLAUDE_CODE_OAUTH_TOKEN",
		Secret:      "claude",
		TTL:         2 * time.Hour,
		TokenPrefix: "sk-ant-oat01-",
		Allow: []policy.Rule{
			{Host: "api.anthropic.com", Methods: []string{"POST"}, Paths: []string{"/v1/messages"}},
		},
	}
}

func TestMintFormatAndOrder(t *testing.T) {
	c := &clock{now: t0}
	r := NewRegistry(c.Now)
	gh, cl := ghGrant(), claudeGrant()
	got, err := r.Mint("T1", "example/app", []policy.Grant{gh, cl})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if len(got) != 2 || got[0].Env != "CLAUDE_CODE_OAUTH_TOKEN" || got[1].Env != "GH_TOKEN" {
		t.Fatalf("Mint order = %+v, want [CLAUDE_CODE_OAUTH_TOKEN GH_TOKEN]", got)
	}
	formats := []struct {
		re    *regexp.Regexp
		grant policy.Grant
	}{
		{regexp.MustCompile(`^sk-ant-oat01-[A-Za-z0-9_-]{43}$`), cl},
		{regexp.MustCompile(`^fbt_[A-Za-z0-9_-]{43}$`), gh},
	}
	for i, f := range formats {
		if !f.re.MatchString(got[i].Token) {
			t.Errorf("token %d = %q, want match %s", i, got[i].Token, f.re)
		}
		s, ok := r.Lookup(got[i].Token)
		if !ok {
			t.Fatalf("Lookup(%s token) = false, want true", got[i].Env)
		}
		want := Scope{
			Task: "T1", Project: "example/app", Env: f.grant.Env, Secret: f.grant.Secret,
			Rules: f.grant.Allow, Expires: t0.Add(f.grant.TTL), Started: t0,
		}
		if s.Done == nil {
			t.Errorf("Lookup(%s token) has no Done channel", got[i].Env)
		}
		want.Done = s.Done
		if !reflect.DeepEqual(s, want) {
			t.Errorf("Lookup(%s token) = %+v, want %+v", got[i].Env, s, want)
		}
	}
}

func TestMintTwiceKeepsOldTokens(t *testing.T) {
	r := NewRegistry((&clock{now: t0}).Now)
	grants := []policy.Grant{ghGrant(), claudeGrant()}
	seen := map[string]bool{}
	for range 2 {
		got, err := r.Mint("T", "example/app", grants)
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		for _, is := range got {
			seen[is.Token] = true
		}
	}
	if len(seen) != 4 {
		t.Fatalf("distinct tokens = %d, want 4", len(seen))
	}
	for tok := range seen {
		if _, ok := r.Lookup(tok); !ok {
			t.Errorf("Lookup(%q) = false after a second Mint, want true", tok)
		}
	}
}

func TestRevoke(t *testing.T) {
	cases := []struct {
		name, task string
		want       int
		gone       bool // T's tokens are gone after Revoke
	}{
		{"task with two tokens", "T", 2, true},
		{"unknown task", "nope", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRegistry((&clock{now: t0}).Now)
			mine, err := r.Mint("T", "example/app", []policy.Grant{ghGrant(), claudeGrant()})
			if err != nil {
				t.Fatalf("Mint: %v", err)
			}
			// "T1" shares the prefix "T": Revoke must match the task exactly.
			other, err := r.Mint("T1", "example/app", []policy.Grant{ghGrant()})
			if err != nil {
				t.Fatalf("Mint: %v", err)
			}
			if n := r.Revoke(tc.task); n != tc.want {
				t.Fatalf("Revoke(%q) = %d, want %d", tc.task, n, tc.want)
			}
			for _, is := range mine {
				if _, ok := r.Lookup(is.Token); ok == tc.gone {
					t.Errorf("Lookup(T %s) = %v, want %v", is.Env, ok, !tc.gone)
				}
			}
			if _, ok := r.Lookup(other[0].Token); !ok {
				t.Errorf("Lookup(T1 token) = false, want true")
			}
		})
	}
}

func TestExpiry(t *testing.T) {
	c := &clock{now: t0}
	r := NewRegistry(c.Now)
	got, err := r.Mint("T", "example/app", []policy.Grant{ghGrant()})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	tok := got[0].Token
	c.Set(t0.Add(59 * time.Minute))
	if _, ok := r.Lookup(tok); !ok {
		t.Fatalf("Lookup at +59m = false, want true")
	}
	if !r.HostAllowed("api.github.com") {
		t.Fatalf("HostAllowed at +59m = false, want true")
	}
	if n := r.Prune(); n != 0 {
		t.Fatalf("Prune at +59m = %d, want 0", n)
	}
	c.Set(t0.Add(60 * time.Minute))
	if _, ok := r.Lookup(tok); ok {
		t.Fatalf("Lookup at +60m = true, want false")
	}
	if r.HostAllowed("api.github.com") {
		t.Fatalf("HostAllowed after expiry = true, want false")
	}
	if n := r.Prune(); n != 1 {
		t.Fatalf("Prune = %d, want 1", n)
	}
	if n := r.Prune(); n != 0 {
		t.Fatalf("second Prune = %d, want 0", n)
	}
}

// TestMixedExpiry is beyond the plan list: one expired token must not
// hide a live one for the same host, nor take it along on Prune.
func TestMixedExpiry(t *testing.T) {
	c := &clock{now: t0}
	r := NewRegistry(c.Now)
	long := ghGrant()
	long.Env, long.TTL = "GH_TOKEN_LONG", 2*time.Hour
	got, err := r.Mint("T", "example/app", []policy.Grant{ghGrant(), long})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	c.Set(t0.Add(90 * time.Minute))
	if !r.HostAllowed("api.github.com") {
		t.Fatalf("HostAllowed with one live token = false, want true")
	}
	if n := r.Prune(); n != 1 {
		t.Fatalf("Prune = %d, want 1", n)
	}
	for _, is := range got {
		_, ok := r.Lookup(is.Token)
		if want := is.Env == "GH_TOKEN_LONG"; ok != want {
			t.Errorf("Lookup(%s) at +90m = %v, want %v", is.Env, ok, want)
		}
	}
}

func TestHostAllowed(t *testing.T) {
	empty := NewRegistry((&clock{now: t0}).Now)
	r := NewRegistry((&clock{now: t0}).Now)
	if _, err := r.Mint("T", "example/app", []policy.Grant{ghGrant()}); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	cases := []struct {
		name string
		reg  *Registry
		host string
		want bool
	}{
		{"api.github.com", r, "api.github.com", true},
		{"github.com", r, "github.com", true},
		{"other host", r, "api.anthropic.com", false},
		{"empty registry", empty, "api.github.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.reg.HostAllowed(tc.host); got != tc.want {
				t.Fatalf("HostAllowed(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

func TestValidTaskID(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"t-1.a_B", true},
		{strings.Repeat("a", 64), true},
		{strings.Repeat("a", 65), false},
		{"", false},
		{"a/b", false},
		{"a b", false},
		{"a;b", false},
		// Cases beyond the plan list.
		{"a\n", false},
		{"é", false},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%q", tc.in), func(t *testing.T) {
			if got := ValidTaskID(tc.in); got != tc.want {
				t.Fatalf("ValidTaskID(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestMintRejects is beyond the plan list: Mint refuses input that would
// put an unvalidated task or project into a Scope, and issues no token.
func TestMintRejects(t *testing.T) {
	zeroTTL := ghGrant()
	zeroTTL.TTL = 0
	cases := []struct {
		name, task, project string
		grants              []policy.Grant
	}{
		{"bad task", "a/b", "example/app", []policy.Grant{ghGrant()}},
		{"bad project", "T", "app", []policy.Grant{ghGrant()}},
		{"no grants", "T", "example/app", nil},
		{"zero TTL", "T", "example/app", []policy.Grant{claudeGrant(), zeroTTL}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRegistry((&clock{now: t0}).Now)
			got, err := r.Mint(tc.task, tc.project, tc.grants)
			if err == nil || got != nil {
				t.Fatalf("Mint = %v, %v; want nil and an error", got, err)
			}
			if r.HostAllowed("api.anthropic.com") || r.Prune() != 0 || r.Revoke(tc.task) != 0 {
				t.Fatalf("a refused Mint left tokens in the registry")
			}
		})
	}
}

// TestScopeIsolated is beyond the plan list: neither the caller's grant
// slices nor a Lookup result can change the rules of a stored token.
func TestScopeIsolated(t *testing.T) {
	r := NewRegistry((&clock{now: t0}).Now)
	g := ghGrant()
	got, err := r.Mint("T", "example/app", []policy.Grant{g})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	g.Allow[0].Host = "evil.example.com"
	g.Allow[0].Paths[0] = "/"
	s, _ := r.Lookup(got[0].Token)
	s.Rules[1].Methods[0] = "DELETE"
	s, _ = r.Lookup(got[0].Token)
	if !reflect.DeepEqual(s.Rules, ghGrant().Allow) {
		t.Fatalf("stored rules = %+v, want %+v", s.Rules, ghGrant().Allow)
	}
	if r.HostAllowed("evil.example.com") {
		t.Fatalf("HostAllowed follows a change to the caller's grant")
	}
}

func TestNilClockUsesTimeNow(t *testing.T) {
	r := NewRegistry(nil)
	got, err := r.Mint("T", "example/app", []policy.Grant{ghGrant()})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	s, ok := r.Lookup(got[0].Token)
	if !ok {
		t.Fatalf("Lookup = false, want true")
	}
	if d := time.Until(s.Expires); d <= 0 || d > time.Hour {
		t.Fatalf("Expires in %v, want within (0, 1h]", d)
	}
}

func TestConcurrentUse(t *testing.T) {
	c := &clock{now: t0}
	r := NewRegistry(c.Now)
	grants := []policy.Grant{ghGrant(), claudeGrant()}
	var wg sync.WaitGroup
	for w := range 4 {
		task := fmt.Sprintf("T%d", w)
		wg.Go(func() {
			for i := range 200 {
				got, err := r.Mint(task, "example/app", grants)
				if err != nil {
					t.Errorf("Mint: %v", err)
					return
				}
				r.Lookup(got[0].Token)
				r.HostAllowed("api.github.com")
				if i%7 == 0 {
					r.Renew(task, grants, time.Hour)
				}
				if i%10 == 0 {
					r.Revoke(task)
				}
			}
		})
	}
	wg.Go(func() {
		for i := range 200 {
			c.Set(t0.Add(time.Duration(i) * time.Minute))
			r.Prune()
		}
	})
	wg.Wait()
}

func TestMintCap(t *testing.T) {
	if r := NewRegistry(nil); r.max != MaxLive || MaxLive != 1024 {
		t.Fatalf("cap = %d (MaxLive %d), want 1024", r.max, MaxLive)
	}
	c := &clock{now: t0}
	r := NewRegistry(c.Now)
	r.max = 3
	first, err := r.Mint("A", "example/app", []policy.Grant{ghGrant(), claudeGrant()})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if err := r.Room(1); err != nil {
		t.Fatalf("Room(1) = %v, want nil", err)
	}
	if err := r.Room(2); !errors.Is(err, ErrFull) {
		t.Fatalf("Room(2) = %v, want ErrFull", err)
	}
	got, err := r.Mint("B", "example/app", []policy.Grant{ghGrant(), claudeGrant()})
	if !errors.Is(err, ErrFull) || got != nil {
		t.Fatalf("Mint beyond the cap = %v, %v; want ErrFull", got, err)
	}
	if n := r.Revoke("B"); n != 0 {
		t.Fatalf("a refused Mint added %d tokens", n)
	}
	// Expired tokens that Prune has not dropped yet do not count.
	c.Set(t0.Add(3 * time.Hour))
	if _, err := r.Mint("B", "example/app", []policy.Grant{ghGrant(), claudeGrant()}); err != nil {
		t.Fatalf("Mint after expiry: %v", err)
	}
	if _, ok := r.Lookup(first[0].Token); ok {
		t.Fatal("expired token still live")
	}
}

func closed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func TestDoneSignal(t *testing.T) {
	c := &clock{now: t0}
	r := NewRegistry(c.Now)
	a, _ := r.Mint("T", "example/app", []policy.Grant{ghGrant()})
	b, _ := r.Mint("T", "example/app", []policy.Grant{ghGrant()})
	other, _ := r.Mint("U", "example/app", []policy.Grant{ghGrant()})
	sa, _ := r.Lookup(a[0].Token)
	sb, _ := r.Lookup(b[0].Token)
	su, _ := r.Lookup(other[0].Token)
	if closed(sa.Done) || closed(sb.Done) || closed(su.Done) {
		t.Fatal("Done closed before Revoke")
	}
	r.Revoke("T")
	if !closed(sa.Done) || !closed(sb.Done) || closed(su.Done) {
		t.Fatal("Revoke(T) must close the Done channels of T's tokens and only those")
	}
	again, _ := r.Mint("T", "example/app", []policy.Grant{ghGrant()})
	if s, _ := r.Lookup(again[0].Token); closed(s.Done) {
		t.Fatal("a mint after Revoke got a closed channel")
	}
}

// TestPruneClosesDone: an expired token's requests in flight end when
// Prune drops it; a live token of the same task is untouched.
func TestPruneClosesDone(t *testing.T) {
	c := &clock{now: t0}
	r := NewRegistry(c.Now)
	long := ghGrant()
	long.Env, long.TTL = "GH_TOKEN_LONG", 2*time.Hour
	got, err := r.Mint("T", "example/app", []policy.Grant{ghGrant(), long})
	if err != nil {
		t.Fatal(err)
	}
	done := map[string]<-chan struct{}{}
	for _, is := range got {
		s, _ := r.Lookup(is.Token)
		done[is.Env] = s.Done
	}
	c.Set(t0.Add(90 * time.Minute))
	if closed(done["GH_TOKEN"]) {
		t.Fatal("Done closed before Prune")
	}
	if n := r.Prune(); n != 1 {
		t.Fatalf("Prune = %d, want 1", n)
	}
	if !closed(done["GH_TOKEN"]) || closed(done["GH_TOKEN_LONG"]) {
		t.Fatal("Prune must close the expired token's Done and only that one")
	}
}

const maxSession = 24 * time.Hour

func TestRenewExtendsExpiry(t *testing.T) {
	c := &clock{now: t0}
	r := NewRegistry(c.Now)
	got, err := r.Mint("T", "example/app", []policy.Grant{ghGrant(), claudeGrant()})
	if err != nil {
		t.Fatal(err)
	}
	c.Set(t0.Add(50 * time.Minute))
	live, err := r.Renew("T", []policy.Grant{ghGrant(), claudeGrant()}, maxSession)
	if err != nil || live != 2 {
		t.Fatalf("Renew = %d, %v; want 2, nil", live, err)
	}
	for _, is := range got {
		s, ok := r.Lookup(is.Token)
		if !ok {
			t.Fatalf("Lookup(%s) after Renew = false", is.Env)
		}
		ttl := ghGrant().TTL
		if is.Env == "CLAUDE_CODE_OAUTH_TOKEN" {
			ttl = claudeGrant().TTL
		}
		if want := t0.Add(50*time.Minute + ttl); !s.Expires.Equal(want) {
			t.Errorf("%s Expires = %v, want %v", is.Env, s.Expires, want)
		}
		if !s.Started.Equal(t0) {
			t.Errorf("%s Started = %v, want %v (renew keeps it)", is.Env, s.Started, t0)
		}
	}
	// Past the first expiry, the renewed tokens still work.
	c.Set(t0.Add(70 * time.Minute))
	for _, is := range got {
		if _, ok := r.Lookup(is.Token); !ok {
			t.Errorf("Lookup(%s) past the first expiry = false", is.Env)
		}
	}
	if n := r.Prune(); n != 0 {
		t.Fatalf("Prune after Renew = %d, want 0", n)
	}
}

func TestRenewAfterExpiryFails(t *testing.T) {
	c := &clock{now: t0}
	r := NewRegistry(c.Now)
	got, err := r.Mint("T", "example/app", []policy.Grant{ghGrant()})
	if err != nil {
		t.Fatal(err)
	}
	s, _ := r.Lookup(got[0].Token)
	c.Set(t0.Add(time.Hour))
	live, err := r.Renew("T", []policy.Grant{ghGrant()}, maxSession)
	if !errors.Is(err, ErrNoTokens) || live != 0 {
		t.Fatalf("Renew after expiry = %d, %v; want 0, ErrNoTokens", live, err)
	}
	if _, ok := r.Lookup(got[0].Token); ok {
		t.Fatal("an expired token came back to life")
	}
	if !closed(s.Done) {
		t.Fatal("Renew left the expired token's Done open")
	}
	if live, err := r.Renew("nope", []policy.Grant{ghGrant()}, maxSession); !errors.Is(err, ErrNoTokens) || live != 0 {
		t.Fatalf("Renew of an unknown task = %d, %v; want 0, ErrNoTokens", live, err)
	}
}

// TestRenewAppliesCurrentPolicy: renew replaces the rules with the
// grant's current ones, so a rule removed from the policy stops working.
func TestRenewAppliesCurrentPolicy(t *testing.T) {
	c := &clock{now: t0}
	r := NewRegistry(c.Now)
	got, err := r.Mint("T", "example/app", []policy.Grant{ghGrant()})
	if err != nil {
		t.Fatal(err)
	}
	tight := ghGrant()
	tight.Allow = tight.Allow[:1] // github.com removed
	tight.Allow[0].Methods = []string{"GET"}
	tight.TTL = 5 * time.Minute
	if _, err := r.Renew("T", []policy.Grant{tight}, maxSession); err != nil {
		t.Fatal(err)
	}
	s, ok := r.Lookup(got[0].Token)
	if !ok {
		t.Fatal("token gone after Renew")
	}
	if !reflect.DeepEqual(s.Rules, tight.Allow) {
		t.Fatalf("rules after Renew = %+v, want %+v", s.Rules, tight.Allow)
	}
	if r.HostAllowed("github.com") {
		t.Fatal("HostAllowed(github.com) after the rule was removed")
	}
	if want := t0.Add(5 * time.Minute); !s.Expires.Equal(want) {
		t.Fatalf("Expires = %v, want %v (the new TTL)", s.Expires, want)
	}
	// The caller's grant cannot change the stored rules afterwards.
	tight.Allow[0].Host = "evil.example.com"
	if r.HostAllowed("evil.example.com") {
		t.Fatal("Renew kept a reference to the caller's rules")
	}
}

func TestRenewDropsRemovedGrant(t *testing.T) {
	c := &clock{now: t0}
	r := NewRegistry(c.Now)
	got, err := r.Mint("T", "example/app", []policy.Grant{ghGrant(), claudeGrant()})
	if err != nil {
		t.Fatal(err)
	}
	scopes := map[string]Scope{}
	for _, is := range got {
		scopes[is.Env], _ = r.Lookup(is.Token)
	}
	live, err := r.Renew("T", []policy.Grant{claudeGrant()}, maxSession)
	if err != nil || live != 1 {
		t.Fatalf("Renew = %d, %v; want 1, nil", live, err)
	}
	for _, is := range got {
		_, ok := r.Lookup(is.Token)
		if want := is.Env == "CLAUDE_CODE_OAUTH_TOKEN"; ok != want {
			t.Errorf("Lookup(%s) = %v, want %v", is.Env, ok, want)
		}
	}
	if !closed(scopes["GH_TOKEN"].Done) || closed(scopes["CLAUDE_CODE_OAUTH_TOKEN"].Done) {
		t.Fatal("Renew must close the dropped token's Done and only that one")
	}
	if live, err := r.Renew("T", nil, maxSession); !errors.Is(err, ErrNoTokens) || live != 0 {
		t.Fatalf("Renew with no grants = %d, %v; want 0, ErrNoTokens", live, err)
	}
}

func TestRenewMaxSession(t *testing.T) {
	c := &clock{now: t0}
	r := NewRegistry(c.Now)
	got, err := r.Mint("T", "example/app", []policy.Grant{ghGrant()})
	if err != nil {
		t.Fatal(err)
	}
	s, _ := r.Lookup(got[0].Token)
	// Near the cap, the lease ends at Started+max, not now+TTL.
	c.Set(t0.Add(50 * time.Minute))
	if _, err := r.Renew("T", []policy.Grant{ghGrant()}, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	c.Set(t0.Add(100 * time.Minute))
	if _, err := r.Renew("T", []policy.Grant{ghGrant()}, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	if s, _ := r.Lookup(got[0].Token); !s.Expires.Equal(t0.Add(2 * time.Hour)) {
		t.Fatalf("Expires = %v, want Started+max %v", s.Expires, t0.Add(2*time.Hour))
	}
	c.Set(t0.Add(119 * time.Minute))
	if _, err := r.Renew("T", []policy.Grant{ghGrant()}, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	// The renewed lease ends at the bound; at the bound, renew reports
	// the limit, not a lapsed lease.
	c.Set(t0.Add(2 * time.Hour))
	if _, ok := r.Lookup(got[0].Token); ok {
		t.Fatal("token live at Started+max")
	}
	if _, err := r.Renew("T", []policy.Grant{ghGrant()}, 2*time.Hour); !errors.Is(err, ErrMaxSession) {
		t.Fatalf("Renew at Started+max = %v, want ErrMaxSession", err)
	}
	got, _ = r.Mint("T", "example/app", []policy.Grant{ghGrant()})
	s, _ = r.Lookup(got[0].Token)
	c.Set(t0.Add(3*time.Hour - time.Minute))
	// A shorter max later still cuts at its own bound.
	live, err := r.Renew("T", []policy.Grant{ghGrant()}, 30*time.Minute)
	if !errors.Is(err, ErrMaxSession) || live != 0 {
		t.Fatalf("Renew past max = %d, %v; want 0, ErrMaxSession", live, err)
	}
	if _, ok := r.Lookup(got[0].Token); ok {
		t.Fatal("token live after ErrMaxSession")
	}
	if !closed(s.Done) {
		t.Fatal("ErrMaxSession must close Done")
	}
	if n := r.Revoke("T"); n != 0 {
		t.Fatalf("ErrMaxSession left %d tokens", n)
	}
}

// TestRenewOtherTaskUntouched is beyond the plan list: renew changes
// only the tokens of its task.
func TestRenewOtherTaskUntouched(t *testing.T) {
	c := &clock{now: t0}
	r := NewRegistry(c.Now)
	if _, err := r.Mint("T", "example/app", []policy.Grant{ghGrant()}); err != nil {
		t.Fatal(err)
	}
	other, err := r.Mint("T1", "example/app", []policy.Grant{ghGrant()})
	if err != nil {
		t.Fatal(err)
	}
	c.Set(t0.Add(30 * time.Minute))
	if _, err := r.Renew("T", nil, maxSession); !errors.Is(err, ErrNoTokens) {
		t.Fatalf("Renew = %v, want ErrNoTokens", err)
	}
	if s, ok := r.Lookup(other[0].Token); !ok || !s.Expires.Equal(t0.Add(time.Hour)) || closed(s.Done) {
		t.Fatalf("T1 token changed by Renew(T): %+v, %v", s, ok)
	}
	if p, ok := r.Project("T1"); !ok || p != "example/app" {
		t.Fatalf("Project(T1) = %q, %v", p, ok)
	}
	if _, ok := r.Project("T"); ok {
		t.Fatal("Project of a task without tokens = true")
	}
	// An expired token not yet pruned still names its project.
	c.Set(t0.Add(2 * time.Hour))
	if p, ok := r.Project("T1"); !ok || p != "example/app" {
		t.Fatalf("Project(T1) after expiry, before Prune = %q, %v", p, ok)
	}
	r.Prune()
	if _, ok := r.Project("T1"); ok {
		t.Fatal("Project after Prune = true")
	}
}

// TestRenewScopeChangeClosesDone: a renew that changes a token's rules or
// secret ends the requests in flight under the old scope; one that
// changes nothing keeps them.
func TestRenewScopeChangeClosesDone(t *testing.T) {
	c := &clock{now: t0}
	r := NewRegistry(c.Now)
	got, err := r.Mint("T", "example/app", []policy.Grant{ghGrant()})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := r.Lookup(got[0].Token)
	if _, err := r.Renew("T", []policy.Grant{ghGrant()}, maxSession); err != nil {
		t.Fatal(err)
	}
	same, _ := r.Lookup(got[0].Token)
	if closed(before.Done) || same.Done != before.Done {
		t.Fatal("an unchanged renew replaced or closed Done")
	}
	tight := ghGrant()
	tight.Allow = tight.Allow[:1]
	if _, err := r.Renew("T", []policy.Grant{tight}, maxSession); err != nil {
		t.Fatal(err)
	}
	after, _ := r.Lookup(got[0].Token)
	if !closed(before.Done) || closed(after.Done) {
		t.Fatal("a rule change must close the old Done and give an open new one")
	}
	moved := tight
	moved.Secret = "gh-other"
	if _, err := r.Renew("T", []policy.Grant{moved}, maxSession); err != nil {
		t.Fatal(err)
	}
	last, _ := r.Lookup(got[0].Token)
	if !closed(after.Done) || closed(last.Done) || last.Secret != "gh-other" {
		t.Fatalf("a secret change must close Done and switch the secret: %+v", last)
	}
	// Revoke closes the current channel without a double close.
	r.Revoke("T")
	if !closed(last.Done) {
		t.Fatal("Revoke left the current Done open")
	}
}

// TestMintRefusesOtherProject: one task id cannot hold tokens of two
// projects, since Renew applies one project's grants to all of them.
func TestMintRefusesOtherProject(t *testing.T) {
	c := &clock{now: t0}
	r := NewRegistry(c.Now)
	mine, err := r.Mint("T", "example/app", []policy.Grant{ghGrant()})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.CheckProject("T", "other/repo"); err == nil {
		t.Fatal("CheckProject for another project = nil")
	}
	if err := r.CheckProject("T", "example/app"); err != nil {
		t.Fatalf("CheckProject for the same project = %v", err)
	}
	if got, err := r.Mint("T", "other/repo", []policy.Grant{ghGrant()}); err == nil || got != nil {
		t.Fatalf("Mint for another project = %v, %v; want an error", got, err)
	}
	if _, ok := r.Lookup(mine[0].Token); !ok {
		t.Fatal("the refused Mint dropped the task's tokens")
	}
	// Once the task's tokens expire, the task id can serve another project.
	c.Set(t0.Add(time.Hour))
	if _, err := r.Mint("T", "other/repo", []policy.Grant{ghGrant()}); err != nil {
		t.Fatalf("Mint after expiry: %v", err)
	}
	if p, _ := r.Project("T"); p != "other/repo" {
		t.Fatalf("Project(T) = %q, want other/repo (expired tokens of the old project dropped)", p)
	}
	if n := r.Revoke("T"); n != 1 {
		t.Fatalf("Revoke = %d, want 1", n)
	}
}
