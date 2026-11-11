// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: GPL-3.0-or-later

// Package ca creates the credenza CA and issues the per-host leaf certificates
// the proxy presents when it intercepts a CONNECT tunnel.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// DefaultName is the CA common name when ca init gets no -name.
	DefaultName = "credenza CA"
	// MaxNameLen is ub-common-name, the upper bound RFC 5280 (appendix A.1) sets on a common name.
	MaxNameLen   = 64
	caValidYears = 10
	backdate     = time.Hour
	leafValidity = 7 * 24 * time.Hour
	leafRenewal  = 24 * time.Hour
)

// New creates an ECDSA P-256 CA: CN name (see ValidName), NotBefore now-1h, NotAfter now+10y,
// IsCA, BasicConstraintsValid, MaxPathLenZero, KeyUsageCertSign|KeyUsageCRLSign,
// ExtKeyUsage ServerAuth (verifiers that check EKU along the chain refuse
// a leaf for any other purpose). With domains non-empty:
// PermittedDNSDomains = domains, ExcludedIPRanges = every IPv4 and IPv6
// address, PermittedDNSDomainsCritical = true. RFC 5280 4.2.1.10: a
// constraint applies only to its own name form, so DNS constraints alone
// would let the key sign a leaf for an IP address. Without domains the CA
// has no name constraints extension: it is the fallback for a client that
// rejects one.
func New(name string, domains []string, now time.Time) (certPEM, keyPEM []byte, err error) {
	if err := ValidName(name); err != nil {
		return nil, nil, err
	}
	for _, d := range domains {
		// An empty constraint matches every name, which would silently
		// turn a constrained CA into an unconstrained one.
		if d == "" {
			return nil, nil, errors.New("CA name constraint domain is empty")
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.AddDate(caValidYears, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if len(domains) > 0 {
		tmpl.PermittedDNSDomains = append([]string(nil), domains...)
		tmpl.ExcludedIPRanges = []*net.IPNet{
			{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
			{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		}
		tmpl.PermittedDNSDomainsCritical = true
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CA certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("encode CA key: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// ValidName reports why name cannot be a CA common name: it must be valid
// UTF-8, 1 to MaxNameLen characters, without control characters and without
// leading or trailing spaces. The name is a label for people reading the
// certificate (trust store listings, openssl x509 -subject); nothing checks
// it when a CA is loaded, so a CA created with any name keeps working.
func ValidName(name string) error {
	switch {
	case name == "":
		return errors.New("CA name is empty")
	case !utf8.ValidString(name):
		return errors.New("CA name is not valid UTF-8")
	case utf8.RuneCountInString(name) > MaxNameLen:
		return fmt.Errorf("CA name is longer than %d characters", MaxNameLen)
	case strings.TrimSpace(name) != name:
		return errors.New("CA name starts or ends with a space")
	case strings.IndexFunc(name, unicode.IsControl) >= 0:
		return errors.New("CA name has a control character")
	}
	return nil
}

// CA is a loaded CA that issues and caches leaf certificates.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	now     func() time.Time

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// Load parses the CA certificate and its PKCS#8 key, and checks that the
// certificate is a CA and that the key belongs to it. Errors never quote
// key material.
func Load(certPEM, keyPEM []byte, now func() time.Time) (*CA, error) {
	if now == nil {
		return nil, errors.New("CA clock is nil")
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, errors.New("CA certificate is not a CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("certificate is not a signing CA")
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil || kb.Type != "PRIVATE KEY" {
		return nil, errors.New("CA key is not a PRIVATE KEY PEM block")
	}
	// The parse error is dropped: it may describe the key bytes.
	parsed, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, errors.New("CA key is not a valid PKCS#8 key")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("CA key is not an ECDSA key")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !key.PublicKey.Equal(pub) {
		return nil, errors.New("CA key does not match the CA certificate")
	}
	return &CA{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(cb), // only the first block, never trailing data
		now:     now,
		cache:   make(map[string]*tls.Certificate),
	}, nil
}

// CertPEM returns the CA certificate in PEM form.
func (c *CA) CertPEM() []byte {
	return append([]byte(nil), c.certPEM...)
}

// Leaf returns a cached ECDSA P-256 leaf for host (SAN DNS host, ExtKeyUsageServerAuth,
// NotBefore now-1h, NotAfter now+7d), issuing a new one when less than 24h remain.
func (c *CA) Leaf(host string) (*tls.Certificate, error) {
	if host == "" {
		return nil, errors.New("leaf host is empty")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	// A clock stepped back before NotBefore (a host without an RTC, such as a Raspberry Pi) also reissues.
	if cert, ok := c.cache[host]; ok && !now.Before(cert.Leaf.NotBefore) && cert.Leaf.NotAfter.Sub(now) >= leafRenewal {
		return cert, nil
	}
	cert, err := c.issue(host, now)
	if err != nil {
		return nil, err
	}
	c.cache[host] = cert
	return cert, nil
}

func (c *CA) issue(host string, now time.Time) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	// No Subject: the SAN alone names the host, and Go marks it critical
	// as RFC 5280 requires. A CN would also cap the host at 64 bytes.
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		DNSNames:              []string{host},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(leafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("create leaf for %s: %w", host, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse leaf for %s: %w", host, err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// CheckHost issues Leaf(host) and runs x509 Verify on it with Roots = the CA
// alone, DNSName = host, KeyUsages ServerAuth. A host outside the CA's name
// constraints fails here, at serve start or at mint, instead of at the client.
func (c *CA) CheckHost(host string) error {
	cert, err := c.Leaf(host)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(c.cert)
	_, err = cert.Leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		DNSName:     host,
		CurrentTime: c.now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf("CA cannot serve %s: %w", host, err)
	}
	return nil
}

// newSerial returns a random 128-bit serial number. RFC 5280 requires it
// positive and at most 20 octets; 128 bits encode in at most 17.
func newSerial() (*big.Int, error) {
	b := make([]byte, 16)
	for {
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("generate serial: %w", err)
		}
		if serial := new(big.Int).SetBytes(b); serial.Sign() > 0 {
			return serial, nil
		}
	}
}
