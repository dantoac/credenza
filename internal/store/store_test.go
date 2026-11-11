// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: GPL-3.0-or-later

package store

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	DefaultIterations = MinIterations
	os.Exit(m.Run())
}

func sampleData() *Data {
	return &Data{
		Version: 1,
		Secrets: map[string]string{"github-app": "ghp_example", "claude.oauth_1": "sk-example"},
		CA:      &CA{CertPEM: "-----BEGIN CERTIFICATE-----\n", KeyPEM: "-----BEGIN PRIVATE KEY-----\n"},
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	want := sampleData()
	blob, err := Seal(want, "right passphrase", MinIterations)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(blob, "right passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestOpenWrongPassphrase(t *testing.T) {
	blob, err := Seal(&Data{Version: 1, Secrets: map[string]string{"gh": "CANARY-VALUE"}}, "right passphrase", MinIterations)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Open(blob, "wrong passphrase")
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatal(err)
	}
	if strings.Contains(err.Error(), "CANARY-VALUE") {
		t.Fatal("secret in error")
	}
}

func TestOpenTampered(t *testing.T) {
	blob, err := Seal(sampleData(), "right passphrase", MinIterations)
	if err != nil {
		t.Fatal(err)
	}
	flip := func(off int) []byte {
		b := bytes.Clone(blob)
		b[off] ^= 0x01
		return b
	}
	tests := []struct {
		name      string
		blob      []byte
		wrongPass bool
		errSubstr string
	}{
		{"magic", flip(0), false, "not a broker store"},
		{"version", flip(4), false, "format version"},
		{"iterations", flip(8), true, ""},
		{"salt", flip(9), true, ""},
		{"nonce", flip(25), true, ""},
		{"ciphertext", flip(37), true, ""},
		{"tag", flip(len(blob) - 1), true, ""},
		{"truncated 36", blob[:36], false, "too short"},
		{"truncated 52", blob[:52], false, "too short"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Open(tt.blob, "right passphrase")
			if err == nil {
				t.Fatal("tampered blob opened")
			}
			if got := errors.Is(err, ErrWrongPassphrase); got != tt.wrongPass {
				t.Fatalf("errors.Is(ErrWrongPassphrase) = %v, want %v: %v", got, tt.wrongPass, err)
			}
			if !strings.Contains(err.Error(), tt.errSubstr) {
				t.Fatalf("error %q does not contain %q", err, tt.errSubstr)
			}
		})
	}
}

// sealRaw encrypts plain as Seal would, so Open can be fed contents that
// Seal itself refuses to produce.
func sealRaw(t *testing.T, plain []byte) []byte {
	t.Helper()
	header := make([]byte, headerSize)
	copy(header, magic)
	header[4] = formatVersion
	binary.BigEndian.PutUint32(header[5:9], MinIterations)
	aead, err := newAEAD("right passphrase", header[9:25], MinIterations)
	if err != nil {
		t.Fatal(err)
	}
	return aead.Seal(bytes.Clone(header), header[25:37], plain, header)
}

func TestOpenDataContents(t *testing.T) {
	tests := []struct {
		name      string
		plain     string
		errSubstr string
	}{
		{"data version 2", `{"version":2,"secrets":{}}`, "data version 2"},
		{"invalid json", `{"version":1,"secrets":{"gh":CANARY-VALUE}}`, "cannot decode"},
		{"null secrets", `{"version":1,"secrets":null}`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := Open(sealRaw(t, []byte(tt.plain)), "right passphrase")
			if tt.errSubstr == "" {
				if err != nil {
					t.Fatal(err)
				}
				if d.Secrets == nil || len(d.Secrets) != 0 {
					t.Fatalf("Secrets = %#v, want an empty map", d.Secrets)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.errSubstr) {
				t.Fatalf("got %v, want an error containing %q", err, tt.errSubstr)
			}
			if strings.Contains(err.Error(), "CANARY") {
				t.Fatal("plaintext in error")
			}
		})
	}
}

func TestSealRejects(t *testing.T) {
	tests := []struct {
		name      string
		d         *Data
		iter      int
		errSubstr string
	}{
		{"nil data", nil, MinIterations, "nil"},
		{"version 0", &Data{Secrets: map[string]string{}}, MinIterations, "version 1"},
		{"iterations below min", sampleData(), MinIterations - 1, "iterations"},
		{"iterations above max", sampleData(), MaxIterations + 1, "iterations"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Seal(tt.d, "right passphrase", tt.iter)
			if err == nil || !strings.Contains(err.Error(), tt.errSubstr) {
				t.Fatalf("got %v, want an error containing %q", err, tt.errSubstr)
			}
		})
	}
}

func TestSaveFailureLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.enc")
	// A non-empty directory at path makes the final rename fail.
	if err := os.MkdirAll(filepath.Join(path, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, sampleData(), "right passphrase"); err == nil {
		t.Fatal("Save over a non-empty directory succeeded")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "store.enc" {
		t.Fatalf("dir holds %d entries, want only store.enc", len(entries))
	}
}

func TestOpenIterationBounds(t *testing.T) {
	blob, err := Seal(sampleData(), "right passphrase", MinIterations)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		iter uint32
	}{
		{"below min", MinIterations - 1},
		{"above max", MaxIterations + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := bytes.Clone(blob)
			binary.BigEndian.PutUint32(b[5:9], tt.iter)
			_, err := Open(b, "right passphrase")
			if err == nil || !strings.Contains(err.Error(), "iterations") {
				t.Fatalf("got %v, want an iterations error", err)
			}
			if errors.Is(err, ErrWrongPassphrase) {
				t.Fatal("bound check ran after PBKDF2")
			}
		})
	}
}

func TestSaveAtomicAndMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.enc")
	first := &Data{Version: 1, Secrets: map[string]string{"a": "1"}}
	second := sampleData()
	for _, d := range []*Data{first, second} {
		if err := Save(path, d, "right passphrase"); err != nil {
			t.Fatal(err)
		}
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode != 0o600 {
		t.Fatalf("mode %o, want 600", mode)
	}
	got, err := Load(path, "right passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, second) {
		t.Fatalf("got %+v, want %+v", got, second)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "store.enc" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("dir holds %v, want only store.enc", names)
	}
}

func TestLoadMissing(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "store.enc"), "right passphrase")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("got %v, want fs.ErrNotExist", err)
	}
}

func TestSaveNewSaltEachTime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.enc")
	var headers [][]byte
	for range 2 {
		if err := Save(path, sampleData(), "right passphrase"); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		headers = append(headers, b[9:37])
	}
	if bytes.Equal(headers[0], headers[1]) {
		t.Fatal("salt and nonce reused across saves")
	}
}

func TestLockExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.enc")
	unlock, err := Lock(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(path); err == nil {
		t.Fatal("second Lock succeeded while the first is held")
	}
	unlock()
	unlock2, err := Lock(path)
	if err != nil {
		t.Fatalf("Lock after unlock: %v", err)
	}
	unlock2()
}

func TestValidSecretName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"github-app", true},
		{"claude.oauth_1", true},
		{"", false},
		{"Gh", false},
		{"-x", false},
		{strings.Repeat("a", 64), true},
		{strings.Repeat("a", 65), false},
		{"a/b", false},
	}
	for _, tt := range tests {
		if got := ValidSecretName(tt.name); got != tt.want {
			t.Errorf("ValidSecretName(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}
