// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: GPL-3.0-or-later

package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

// fakeClock is a settable clock safe for concurrent use.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeClock) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeClock) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
}

func newCA(t *testing.T, domains []string, clock func() time.Time) *CA {
	t.Helper()
	certPEM, keyPEM, err := New(DefaultName, domains, testNow)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c, err := Load(certPEM, keyPEM, clock)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return c
}

func fixedClock() time.Time { return testNow }

// verifyLeaf runs x509 Verify on the leaf for host against the CA alone.
func verifyLeaf(t *testing.T, c *CA, host string, at time.Time) error {
	t.Helper()
	cert, err := c.Leaf(host)
	if err != nil {
		t.Fatalf("Leaf(%q): %v", host, err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(c.CertPEM()) {
		t.Fatal("CertPEM is not a usable PEM certificate")
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:       pool,
		DNSName:     host,
		CurrentTime: at,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

func TestNewCAVerifiesLeaf(t *testing.T) {
	certPEM, keyPEM, err := New(DefaultName, nil, testNow)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("cert PEM block = %v, want CERTIFICATE", block)
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	if caCert.Subject.CommonName != DefaultName {
		t.Errorf("CN = %q", caCert.Subject.CommonName)
	}
	if !caCert.IsCA || !caCert.BasicConstraintsValid || !caCert.MaxPathLenZero || caCert.MaxPathLen != 0 {
		t.Errorf("basic constraints: IsCA %v valid %v zero %v len %d",
			caCert.IsCA, caCert.BasicConstraintsValid, caCert.MaxPathLenZero, caCert.MaxPathLen)
	}
	if caCert.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Errorf("KeyUsage = %v", caCert.KeyUsage)
	}
	if !caCert.NotBefore.Equal(testNow.Add(-time.Hour)) || !caCert.NotAfter.Equal(testNow.AddDate(10, 0, 0)) {
		t.Errorf("validity %v to %v", caCert.NotBefore, caCert.NotAfter)
	}
	if caCert.SerialNumber.BitLen() < 64 {
		t.Errorf("serial %v looks too short", caCert.SerialNumber)
	}
	if len(caCert.PermittedDNSDomains) != 0 {
		t.Errorf("unconstrained CA has PermittedDNSDomains %v", caCert.PermittedDNSDomains)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil || kb.Type != "PRIVATE KEY" {
		t.Fatalf("key PEM block = %v, want PRIVATE KEY", kb)
	}
	if _, err := x509.ParsePKCS8PrivateKey(kb.Bytes); err != nil {
		t.Fatalf("key is not PKCS#8: %v", err)
	}

	c, err := Load(certPEM, keyPEM, fixedClock)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(c.CertPEM()) != string(certPEM) {
		t.Error("CertPEM differs from the loaded PEM")
	}
	if err := verifyLeaf(t, c, "api.github.com", testNow); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	cert, _ := c.Leaf("api.github.com")
	leaf := cert.Leaf
	if leaf == nil {
		t.Fatal("tls.Certificate.Leaf is nil")
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "api.github.com" {
		t.Errorf("DNSNames = %v", leaf.DNSNames)
	}
	if !leaf.NotBefore.Equal(testNow.Add(-time.Hour)) || !leaf.NotAfter.Equal(testNow.Add(7*24*time.Hour)) {
		t.Errorf("leaf validity %v to %v", leaf.NotBefore, leaf.NotAfter)
	}
	if leaf.IsCA {
		t.Error("leaf is a CA")
	}
	if !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Errorf("ExtKeyUsage = %v, want [ServerAuth]", leaf.ExtKeyUsage)
	}
	if k, ok := cert.PrivateKey.(*ecdsa.PrivateKey); !ok || k.Curve != elliptic.P256() {
		t.Errorf("leaf key is %T, want ECDSA P-256", cert.PrivateKey)
	}
	if leaf.Subject.CommonName != "" {
		t.Errorf("leaf CN = %q, want empty (SAN only)", leaf.Subject.CommonName)
	}
}

func TestCertPEMOnlyFirstBlock(t *testing.T) {
	certPEM, keyPEM, err := New(DefaultName, nil, testNow)
	if err != nil {
		t.Fatal(err)
	}
	joined := append(append([]byte(nil), certPEM...), keyPEM...)
	c, err := Load(joined, keyPEM, fixedClock)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(c.CertPEM()) != string(certPEM) {
		t.Fatalf("CertPEM returned more than the CA certificate:\n%s", c.CertPEM())
	}
}

func TestNameConstraints(t *testing.T) {
	c := newCA(t, []string{"github.com", "anthropic.com"}, fixedClock)
	if !c.cert.PermittedDNSDomainsCritical {
		t.Error("name constraints are not critical")
	}
	if !slices.Equal(c.cert.PermittedDNSDomains, []string{"github.com", "anthropic.com"}) {
		t.Errorf("PermittedDNSDomains = %v", c.cert.PermittedDNSDomains)
	}
	tests := []struct {
		host string
		ok   bool
	}{
		{"api.github.com", true},
		{"api.anthropic.com", true},
		{"example.org", false},
		{"github.com.example.org", false},
		{"evilgithub.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			err := verifyLeaf(t, c, tt.host, testNow)
			if tt.ok && err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !tt.ok {
				var inv x509.CertificateInvalidError
				if err == nil {
					t.Fatal("Verify succeeded for a host outside the constraints")
				}
				if !errors.As(err, &inv) || inv.Reason != x509.CANotAuthorizedForThisName {
					t.Fatalf("Verify error = %v, want CANotAuthorizedForThisName", err)
				}
			}
		})
	}
}

func TestNewRejectsEmptyDomain(t *testing.T) {
	for _, domains := range [][]string{{""}, {"github.com", ""}} {
		if _, _, err := New(DefaultName, domains, testNow); err == nil {
			t.Errorf("New(%q) succeeded, an empty constraint would permit every name", domains)
		}
	}
}

func TestLeafCachedAndRenewed(t *testing.T) {
	clock := &fakeClock{t: testNow}
	c := newCA(t, nil, clock.now)

	first, err := c.Leaf("api.github.com")
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	second, err := c.Leaf("api.github.com")
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	if first != second {
		t.Fatal("second call issued a new certificate")
	}

	clock.advance(6*24*time.Hour - time.Second) // 24h+1s left
	if third, _ := c.Leaf("api.github.com"); third != first {
		t.Fatal("certificate with 24h+1s left was reissued")
	}

	clock.advance(2 * time.Second) // 24h-1s left
	renewed, err := c.Leaf("api.github.com")
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	if renewed == first {
		t.Fatal("certificate with 24h-1s left was not reissued")
	}
	if !renewed.Leaf.NotAfter.Equal(clock.now().Add(7 * 24 * time.Hour)) {
		t.Errorf("renewed NotAfter = %v", renewed.Leaf.NotAfter)
	}
	if err := verifyLeaf(t, c, "api.github.com", clock.now()); err != nil {
		t.Fatalf("Verify renewed: %v", err)
	}
}

func TestLeafReissuedAfterClockStepsBack(t *testing.T) {
	// Start a day after the CA was made, so the CA stays valid after the step.
	clock := &fakeClock{t: testNow.Add(24 * time.Hour)}
	c := newCA(t, nil, clock.now)
	first, err := c.Leaf("api.github.com")
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	clock.advance(-3 * time.Hour) // before the leaf's NotBefore (now-1h)
	again, err := c.Leaf("api.github.com")
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	if again == first {
		t.Fatal("served a leaf that is not yet valid")
	}
	if err := c.CheckHost("api.github.com"); err != nil {
		t.Fatalf("CheckHost after clock step: %v", err)
	}
}

func TestLoadRejectsMismatchedKey(t *testing.T) {
	certA, _, err := New(DefaultName, nil, testNow)
	if err != nil {
		t.Fatal(err)
	}
	_, keyB, err := New(DefaultName, nil, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(certA, keyB, fixedClock); err == nil {
		t.Fatal("Load accepted the key of another CA")
	}
}

func TestLoadRejects(t *testing.T) {
	certPEM, keyPEM, err := New(DefaultName, nil, testNow)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := pem.Decode(keyPEM)
	parsed, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	scalar := parsed.(*ecdsa.PrivateKey).D
	// A truncated key carries the real private scalar but cannot be parsed.
	truncated := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb.Bytes[:len(kb.Bytes)-8]})
	// Forms the key could leak in: PEM body past the fixed ASN.1 header, hex and decimal of D.
	leaks := []string{
		strings.Split(string(keyPEM), "\n")[1][24:],
		fmt.Sprintf("%x", kb.Bytes[36:52]),
		fmt.Sprintf("%x", scalar.Bytes()),
		scalar.String(),
	}
	tests := []struct {
		name      string
		cert, key []byte
		clock     func() time.Time
	}{
		{"empty cert", nil, keyPEM, fixedClock},
		{"empty key", certPEM, nil, fixedClock},
		{"garbage cert", []byte("not pem"), keyPEM, fixedClock},
		{"key as cert", keyPEM, keyPEM, fixedClock},
		{"cert as key", certPEM, certPEM, fixedClock},
		{"wrong key block type", certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb.Bytes}), fixedClock},
		{"corrupt key", certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("corrupt")}), fixedClock},
		{"truncated key", certPEM, truncated, fixedClock},
		{"nil clock", certPEM, keyPEM, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(tt.cert, tt.key, tt.clock)
			if err == nil {
				t.Fatal("Load succeeded")
			}
			for _, leak := range leaks {
				if strings.Contains(err.Error(), leak) {
					t.Fatalf("error quotes key material: %v", err)
				}
			}
		})
	}
}

func TestLoadRejectsLeafAsCA(t *testing.T) {
	c := newCA(t, nil, fixedClock)
	leaf, err := c.Leaf("api.github.com")
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]})
	keyDER, err := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if _, err := Load(leafPEM, keyPEM, fixedClock); err == nil {
		t.Fatal("Load accepted a non-CA certificate")
	}
}

func TestCheckHost(t *testing.T) {
	constrained := newCA(t, []string{"github.com", "anthropic.com"}, fixedClock)
	unconstrained := newCA(t, nil, fixedClock)
	tests := []struct {
		name string
		c    *CA
		host string
		ok   bool
	}{
		{"constrained subdomain", constrained, "api.github.com", true},
		{"constrained apex", constrained, "github.com", true},
		{"constrained other domain", constrained, "api.anthropic.com", true},
		{"constrained outside", constrained, "example.org", false},
		{"unconstrained", unconstrained, "example.org", true},
		{"empty host", unconstrained, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.c.CheckHost(tt.host)
			if tt.ok && err != nil {
				t.Fatalf("CheckHost(%q): %v", tt.host, err)
			}
			if !tt.ok && err == nil {
				t.Fatalf("CheckHost(%q) = nil, want error", tt.host)
			}
		})
	}
}

func TestLeafConcurrent(t *testing.T) {
	c := newCA(t, nil, fixedClock)
	hosts := []string{"api.github.com", "github.com", "api.anthropic.com", "codeload.github.com"}
	const workers = 32
	type result struct {
		host string
		cert *tls.Certificate
		err  error
	}
	results := make([]result, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			host := hosts[i%len(hosts)]
			cert, err := c.Leaf(host)
			results[i] = result{host, cert, err}
		}()
	}
	wg.Wait()

	seen := map[string]*tls.Certificate{}
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("worker %d Leaf(%q): %v", i, r.host, r.err)
		}
		if prev, ok := seen[r.host]; ok && prev != r.cert {
			t.Errorf("host %q got more than one certificate", r.host)
		}
		seen[r.host] = r.cert
	}
	if len(seen) != len(hosts) {
		t.Fatalf("got certificates for %d hosts, want %d", len(seen), len(hosts))
	}
	for _, h := range hosts {
		if err := verifyLeaf(t, c, h, testNow); err != nil {
			t.Errorf("Verify %q: %v", h, err)
		}
	}
}

// signLeaf signs a leaf with the CA's key outside Leaf, as a stolen key
// would, and verifies it against the CA alone.
func signLeaf(t *testing.T, c *CA, tmpl *x509.Certificate, opts x509.VerifyOptions) error {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.SerialNumber = big.NewInt(42)
	tmpl.NotBefore = testNow.Add(-time.Hour)
	tmpl.NotAfter = testNow.Add(time.Hour)
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	opts.Roots = x509.NewCertPool()
	opts.Roots.AddCert(c.cert)
	opts.CurrentTime = testNow
	_, err = leaf.Verify(opts)
	return err
}

// TestCAConstraintsBeyondDNS: DNS name constraints say nothing about IP
// SANs (RFC 5280 4.2.1.10), so a constrained CA also excludes every IP
// range, and every CA is limited to server authentication.
func TestCAConstraintsBeyondDNS(t *testing.T) {
	serverAuth := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	cases := []struct {
		name    string
		domains []string
		leaf    x509.Certificate
		opts    x509.VerifyOptions
		ok      bool
	}{
		{"constrained ipv4", []string{"github.com"},
			x509.Certificate{IPAddresses: []net.IP{net.ParseIP("192.168.1.10")}, ExtKeyUsage: serverAuth},
			x509.VerifyOptions{KeyUsages: serverAuth}, false},
		{"constrained ipv6", []string{"github.com"},
			x509.Certificate{IPAddresses: []net.IP{net.ParseIP("fd00::1")}, ExtKeyUsage: serverAuth},
			x509.VerifyOptions{KeyUsages: serverAuth}, false},
		{"constrained dns and ip", []string{"github.com"},
			x509.Certificate{DNSNames: []string{"api.github.com"}, IPAddresses: []net.IP{net.ParseIP("10.0.0.1")}, ExtKeyUsage: serverAuth},
			x509.VerifyOptions{DNSName: "api.github.com", KeyUsages: serverAuth}, false},
		{"constrained dns", []string{"github.com"},
			x509.Certificate{DNSNames: []string{"api.github.com"}, ExtKeyUsage: serverAuth},
			x509.VerifyOptions{DNSName: "api.github.com", KeyUsages: serverAuth}, true},
		{"constrained client auth", []string{"github.com"},
			x509.Certificate{DNSNames: []string{"api.github.com"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
			x509.VerifyOptions{KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, false},
		{"unconstrained client auth", nil,
			x509.Certificate{DNSNames: []string{"example.org"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
			x509.VerifyOptions{KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, false},
		{"unconstrained code signing", nil,
			x509.Certificate{DNSNames: []string{"example.org"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}},
			x509.VerifyOptions{KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}, false},
		{"unconstrained dns", nil,
			x509.Certificate{DNSNames: []string{"example.org"}, ExtKeyUsage: serverAuth},
			x509.VerifyOptions{DNSName: "example.org", KeyUsages: serverAuth}, true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c := newCA(t, tt.domains, fixedClock)
			err := signLeaf(t, c, &tt.leaf, tt.opts)
			if tt.ok && err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("Verify accepted a leaf the CA must not vouch for")
			}
		})
	}
}

func TestCAFields(t *testing.T) {
	c := newCA(t, []string{"github.com"}, fixedClock)
	var got []string
	for _, r := range c.cert.ExcludedIPRanges {
		got = append(got, r.String())
	}
	if !slices.Equal(got, []string{"0.0.0.0/0", "::/0"}) {
		t.Errorf("ExcludedIPRanges = %v", got)
	}
	if !slices.Equal(c.cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Errorf("ExtKeyUsage = %v", c.cert.ExtKeyUsage)
	}
	// -unconstrained is the fallback for a client that rejects name
	// constraints, so it carries no name constraints extension at all.
	u := newCA(t, nil, fixedClock)
	if len(u.cert.ExcludedIPRanges) != 0 || len(u.cert.PermittedDNSDomains) != 0 {
		t.Errorf("unconstrained CA has name constraints: %v %v", u.cert.ExcludedIPRanges, u.cert.PermittedDNSDomains)
	}
	if !slices.Equal(u.cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Errorf("unconstrained ExtKeyUsage = %v", u.cert.ExtKeyUsage)
	}
}

func TestValidName(t *testing.T) {
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{DefaultName, true},
		{"fleet-broker CA", true},
		{"Home Lab CA", true},
		{"Café CA", true},
		{strings.Repeat("x", MaxNameLen), true},
		{strings.Repeat("é", MaxNameLen), true},
		{"", false},
		{" CA", false},
		{"CA ", false},
		{"a\nb", false},
		{"a\x00b", false},
		{"\xff", false},
		{strings.Repeat("x", MaxNameLen+1), false},
	} {
		if err := ValidName(tc.name); (err == nil) != tc.ok {
			t.Errorf("ValidName(%q) = %v, want ok %v", tc.name, err, tc.ok)
		}
		if !tc.ok {
			if _, _, err := New(tc.name, nil, testNow); err == nil {
				t.Errorf("New(%q) succeeded", tc.name)
			}
		}
	}
}

// A CA created before the name was configurable (CN "fleet-broker CA") or
// under any -name loads and signs leaves as before: nothing checks the CN.
func TestLoadKeepsAnyName(t *testing.T) {
	for _, name := range []string{"fleet-broker CA", DefaultName, "Home Lab CA"} {
		certPEM, keyPEM, err := New(name, []string{"github.com"}, testNow)
		if err != nil {
			t.Fatalf("New(%q): %v", name, err)
		}
		c, err := Load(certPEM, keyPEM, fixedClock)
		if err != nil {
			t.Fatalf("Load(%q): %v", name, err)
		}
		if err := c.CheckHost("api.github.com"); err != nil {
			t.Fatalf("CheckHost under %q: %v", name, err)
		}
		leaf, err := c.Leaf("api.github.com")
		if err != nil {
			t.Fatal(err)
		}
		if got := leaf.Leaf.Issuer.CommonName; got != name {
			t.Fatalf("leaf issuer CN %q, want %q", got, name)
		}
	}
}
