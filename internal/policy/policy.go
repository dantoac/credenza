// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: Apache-2.0

// Package policy reads the broker's policy file: which grants each
// project gets on mint, and which host, method and path each grant's
// token may reach. Every error starts with "policy: ".
package policy

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Policy is the content of policy.json.
type Policy struct {
	Version  int                `json:"version"` // must be 1
	Projects map[string][]Grant `json:"projects"`
}

// Grant is one secret a project's tasks may use through a temporary token.
type Grant struct {
	Env         string        `json:"env"`          // ^[A-Z_][A-Z0-9_]{0,63}$, unique per project
	Secret      string        `json:"secret"`       // store.ValidSecretName rules
	TTLText     string        `json:"ttl"`          // time.ParseDuration, 0 < ttl <= 24h
	TokenPrefix string        `json:"token_prefix"` // optional, ^[A-Za-z0-9_-]{0,32}$, empty means "fbt_"
	Allow       []Rule        `json:"allow"`        // at least one
	TTL         time.Duration `json:"-"`            // set by Parse
}

// Rule allows requests to one host with the listed methods and paths.
type Rule struct {
	Host    string   `json:"host"`    // see ValidHost
	Methods []string `json:"methods"` // subset of GET HEAD POST PUT PATCH DELETE, at least one
	Paths   []string `json:"paths"`   // at least one; ending "/" = prefix, otherwise exact
}

const maxTTL = 24 * time.Hour

var (
	envName     = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)
	secretName  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`) // same as store.ValidSecretName
	tokenPrefix = regexp.MustCompile(`^[A-Za-z0-9_-]{0,32}$`)
	projectName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)
	hostName    = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	methods     = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}
)

// ValidProject reports whether s is an "owner/repo" project name.
func ValidProject(s string) bool {
	return projectName.MatchString(s)
}

// ValidEnv reports whether s is a grant env name, ^[A-Z_][A-Z0-9_]{0,63}$.
func ValidEnv(s string) bool {
	return envName.MatchString(s)
}

// ValidHost reports whether s is a lowercase DNS name with at least one
// dot, at most 253 bytes, no port, no trailing dot and not an IP literal.
// An all-digit last label is refused too, so short IPv4 forms such as
// "127.1", which netip.ParseAddr does not parse, are not names.
func ValidHost(s string) bool {
	if len(s) > 253 || !hostName.MatchString(s) {
		return false
	}
	last := s[strings.LastIndexByte(s, '.')+1:]
	if strings.Trim(last, "0123456789") == "" {
		return false
	}
	_, err := netip.ParseAddr(s)
	return err != nil
}

// Parse decodes a policy file and validates it. The decoding is strict:
// unknown members, member names that differ only in case, duplicate
// member names and trailing data are errors, so the policy enforced is
// the policy a reader of the file sees.
func Parse(b []byte) (*Policy, error) {
	var p Policy
	if err := json.Unmarshal(b, &p, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Load reads and parses the policy file at path. It refuses a file that
// is not a regular file, is not owned by the running user, or is group or
// world writable. O_NONBLOCK keeps the open of a FIFO from waiting for a
// writer; it does not change reads of a regular file.
func Load(path string) (*Policy, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("policy: %s: not a regular file", path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("policy: %s: cannot read file owner", path)
	}
	if uint64(st.Uid) != uint64(os.Getuid()) {
		return nil, fmt.Errorf("policy: %s: owned by uid %d, want uid %d", path, st.Uid, os.Getuid())
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return nil, fmt.Errorf("policy: %s: group or world writable (mode %04o)", path, perm)
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return Parse(b)
}

// Grants returns the grants of project and whether the policy lists it.
// A listed project may have no grants; mint denies it like a missing one.
func (p *Policy) Grants(project string) ([]Grant, bool) {
	g, ok := p.Projects[project]
	return g, ok
}

// Hosts returns the distinct rule hosts of every grant, sorted.
func (p *Policy) Hosts() []string {
	seen := map[string]bool{}
	var hosts []string
	for _, grants := range p.Projects {
		for _, g := range grants {
			for _, r := range g.Allow {
				if !seen[r.Host] {
					seen[r.Host] = true
					hosts = append(hosts, r.Host)
				}
			}
		}
	}
	sort.Strings(hosts)
	return hosts
}

// Allows reports whether a request to host with method and cleanPath (the
// result of CleanRequestPath) matches r. A rule path ending in "/" is a
// prefix; any other rule path must equal cleanPath.
func (r Rule) Allows(host, method, cleanPath string) bool {
	if host != r.Host || !slices.Contains(r.Methods, method) {
		return false
	}
	for _, p := range r.Paths {
		if p == cleanPath || (strings.HasSuffix(p, "/") && strings.HasPrefix(cleanPath, p)) {
			return true
		}
	}
	return false
}

func (p *Policy) validate() error {
	if p.Version != 1 {
		return fmt.Errorf("policy: version: must be 1, got %d", p.Version)
	}
	names := make([]string, 0, len(p.Projects))
	for name := range p.Projects {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !ValidProject(name) {
			return fmt.Errorf("policy: projects[%q]: must be owner/repo matching %s", name, projectName)
		}
		grants := p.Projects[name]
		envs := map[string]bool{}
		for i := range grants {
			g := &grants[i]
			at := fmt.Sprintf("projects[%q][%d]", name, i)
			if err := g.validate(at); err != nil {
				return err
			}
			if envs[g.Env] {
				return fmt.Errorf("policy: %s.env: duplicate env %q in project", at, g.Env)
			}
			envs[g.Env] = true
		}
	}
	return nil
}

// validate checks g and sets g.TTL. at names the grant in errors.
func (g *Grant) validate(at string) error {
	if !envName.MatchString(g.Env) {
		return fmt.Errorf("policy: %s.env: must match %s", at, envName)
	}
	if !secretName.MatchString(g.Secret) {
		return fmt.Errorf("policy: %s.secret: must match %s", at, secretName)
	}
	ttl, err := time.ParseDuration(g.TTLText)
	if err != nil {
		return fmt.Errorf("policy: %s.ttl: %w", at, err)
	}
	if ttl <= 0 || ttl > maxTTL {
		return fmt.Errorf("policy: %s.ttl: must be > 0 and <= 24h", at)
	}
	g.TTL = ttl
	if !tokenPrefix.MatchString(g.TokenPrefix) {
		return fmt.Errorf("policy: %s.token_prefix: must match %s", at, tokenPrefix)
	}
	if len(g.Allow) == 0 {
		return fmt.Errorf("policy: %s.allow: must have at least one rule", at)
	}
	for j, r := range g.Allow {
		if err := r.validate(fmt.Sprintf("%s.allow[%d]", at, j)); err != nil {
			return err
		}
	}
	return nil
}

func (r Rule) validate(at string) error {
	if !ValidHost(r.Host) {
		return fmt.Errorf("policy: %s.host: %q must be a lowercase DNS name with a dot, no port, not an IP address", at, r.Host)
	}
	if len(r.Methods) == 0 {
		return fmt.Errorf("policy: %s.methods: must have at least one method", at)
	}
	for k, m := range r.Methods {
		if !slices.Contains(methods, m) {
			return fmt.Errorf("policy: %s.methods[%d]: %q must be one of %v", at, k, m, methods)
		}
	}
	if len(r.Paths) == 0 {
		return fmt.Errorf("policy: %s.paths: must have at least one path", at)
	}
	for k, p := range r.Paths {
		if err := checkPolicyPath(p); err != nil {
			return fmt.Errorf("policy: %s.paths[%d]: %q %w", at, k, p, err)
		}
	}
	return nil
}
