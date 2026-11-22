// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: Apache-2.0

// Package store keeps the secrets and the CA in one file
// encrypted with AES-256-GCM under a PBKDF2-HMAC-SHA256 key.
//
// File layout (big endian); the 37 header bytes are the GCM additional data:
//
//	0   4  magic "FBST"
//	4   1  format version 1
//	5   4  PBKDF2 iterations (uint32)
//	9   16 salt
//	25  12 nonce
//	37  .. ciphertext plus 16-byte tag of json.Marshal(Data)
package store

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
)

// Data is the plaintext content of the store.
type Data struct {
	Version int               `json:"version"` // 1
	Secrets map[string]string `json:"secrets"`
	CA      *CA               `json:"ca,omitempty"`
}

// CA holds the CA certificate and private key in PEM form.
type CA struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

const (
	MinIterations = 100_000
	MaxIterations = 10_000_000
)

// DefaultIterations is used by Save. Tests may lower it to MinIterations.
var DefaultIterations = 600_000

// ErrWrongPassphrase is returned for any authentication failure, so a
// wrong passphrase and a modified file look the same.
var ErrWrongPassphrase = errors.New("wrong passphrase or corrupted store")

const (
	magic         = "FBST"
	formatVersion = 1
	dataVersion   = 1
	saltSize      = 16
	nonceSize     = 12
	tagSize       = 16
	keySize       = 32
	headerSize    = 4 + 1 + 4 + saltSize + nonceSize
)

var secretName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ValidSecretName reports whether name is usable as a secret name.
func ValidSecretName(name string) bool {
	return secretName.MatchString(name)
}

// Seal encrypts d under passphrase with iter PBKDF2 iterations, a new
// random salt and a new random nonce.
func Seal(d *Data, passphrase string, iter int) ([]byte, error) {
	if d == nil {
		return nil, errors.New("store data is nil")
	}
	if d.Version != dataVersion {
		return nil, errors.New("store data must have version 1")
	}
	if err := checkIterations(int64(iter)); err != nil {
		return nil, err
	}
	plain, err := json.Marshal(d)
	if err != nil {
		return nil, errors.New("cannot encode store data")
	}
	defer clear(plain)

	header := make([]byte, headerSize, headerSize+len(plain)+tagSize)
	copy(header, magic)
	header[4] = formatVersion
	binary.BigEndian.PutUint32(header[5:9], uint32(iter))
	salt, nonce := header[9:25], header[25:37]
	if _, err := rand.Read(header[9:37]); err != nil {
		return nil, fmt.Errorf("read random salt and nonce: %w", err)
	}
	aead, err := newAEAD(passphrase, salt, iter)
	if err != nil {
		return nil, err
	}
	// Seal forbids dst and additionalData to overlap, so the AAD is a copy.
	return aead.Seal(header, nonce, plain, bytes.Clone(header)), nil
}

// Open decrypts a blob made by Seal. Any authentication failure returns
// ErrWrongPassphrase without a cause.
func Open(blob []byte, passphrase string) (*Data, error) {
	if len(blob) < headerSize+tagSize {
		return nil, errors.New("store file too short")
	}
	if !bytes.Equal(blob[:4], []byte(magic)) {
		return nil, errors.New("not a broker store file")
	}
	if blob[4] != formatVersion {
		return nil, fmt.Errorf("unsupported store format version %d", blob[4])
	}
	iter := binary.BigEndian.Uint32(blob[5:9])
	if err := checkIterations(int64(iter)); err != nil {
		return nil, err
	}
	header := blob[:headerSize]
	aead, err := newAEAD(passphrase, header[9:25], int(iter))
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, header[25:37], blob[headerSize:], header)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	defer clear(plain)

	var d Data
	if err := json.Unmarshal(plain, &d); err != nil {
		// The cause text could quote plaintext bytes.
		return nil, errors.New("cannot decode store data")
	}
	if d.Version != dataVersion {
		return nil, fmt.Errorf("unsupported store data version %d", d.Version)
	}
	if d.Secrets == nil {
		d.Secrets = map[string]string{}
	}
	return &d, nil
}

func checkIterations(iter int64) error {
	if iter < MinIterations || iter > MaxIterations {
		return fmt.Errorf("store iterations %d out of range [%d, %d]", iter, MinIterations, MaxIterations)
	}
	return nil
}

func newAEAD(passphrase string, salt []byte, iter int) (cipher.AEAD, error) {
	key, err := pbkdf2.Key(sha256.New, passphrase, salt, iter, keySize)
	if err != nil {
		return nil, errors.New("cannot derive store key")
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Load reads and decrypts the store at path. A missing file gives an
// error that wraps fs.ErrNotExist.
func Load(path, passphrase string) (*Data, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Open(blob, passphrase)
}

// Save seals d with DefaultIterations, a new salt and a new nonce, and
// replaces path atomically with a 0600 file.
func Save(path string, d *Data, passphrase string) (err error) {
	blob, err := Seal(d, passphrase, DefaultIterations)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".store-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err = f.Chmod(0o600); err != nil {
		return err
	}
	if _, err = f.Write(blob); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("store saved, but syncing %s failed: %w", dir, err)
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Lock takes an exclusive, non-blocking flock on path+".lock". The
// returned unlock releases it and is safe to call more than once.
func Lock(path string) (unlock func(), err error) {
	f, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("store %s is locked by another credenza process", path)
		}
		return nil, fmt.Errorf("lock %s: %w", path+".lock", err)
	}
	var once sync.Once
	return func() { once.Do(func() { f.Close() }) }, nil
}
