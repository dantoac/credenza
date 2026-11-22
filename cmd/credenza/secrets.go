// Copyright (C) 2026 Daniel Aguayo
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"maps"
	"sync"

	"github.com/dantoac/credenza/internal/control"
	"github.com/dantoac/credenza/internal/store"
)

// liveSecrets is serve's secret map. The proxy and the control service
// read it with Get; the admin socket changes it with Set and Remove,
// which write the store first, so the map never holds a value the disk
// lacks.
type liveSecrets struct {
	path string
	// pass is the passphrase given at unlock, kept for serve's lifetime
	// to save the store. serve already holds every decrypted secret, so
	// keeping it exposes nothing new.
	pass []byte

	mu sync.RWMutex
	m  map[string]string
}

// newLiveSecrets returns the live map of the store at path, which secrets
// was loaded from with pass. It keeps its own copy of secrets.
func newLiveSecrets(path string, pass []byte, secrets map[string]string) *liveSecrets {
	return &liveSecrets{path: path, pass: pass, m: maps.Clone(secrets)}
}

// Get returns the value of name.
func (l *liveSecrets) Get(name string) (string, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	v, ok := l.m[name]
	return v, ok
}

// Set stores value under name, on disk and then in the map.
func (l *liveSecrets) Set(name, value string) error {
	if !store.ValidSecretName(name) {
		return errors.New("invalid secret name")
	}
	if err := control.CheckSecretValue(value); err != nil {
		return err
	}
	return l.edit(func(d *store.Data) error {
		d.Secrets[name] = value
		return nil
	})
}

// Remove deletes name, on disk and then from the map.
func (l *liveSecrets) Remove(name string) error {
	return l.edit(func(d *store.Data) error {
		if _, ok := d.Secrets[name]; !ok {
			return fmt.Errorf("secret %s not found", name)
		}
		delete(d.Secrets, name)
		return nil
	})
}

// edit runs fn on the store as it is on disk, under the store lock, saves
// it with the kept passphrase and then swaps the map. Reading the disk,
// not serve's copy, keeps a CA replaced meanwhile, and a passphrase
// changed meanwhile makes the edit fail instead of saving the store under
// the old one. The swap waits for no reader: Get holds the read lock only
// to look a name up.
func (l *liveSecrets) edit(fn func(d *store.Data) error) error {
	unlock, err := store.Lock(l.path)
	if err != nil {
		return err
	}
	defer unlock()
	d, err := store.Load(l.path, string(l.pass))
	if errors.Is(err, store.ErrWrongPassphrase) {
		return errors.New("the store no longer opens with serve's passphrase (changed with credenza passwd?); restart serve")
	}
	if err != nil {
		return err
	}
	if err := fn(d); err != nil {
		return err
	}
	if err := store.Save(l.path, d, string(l.pass)); err != nil {
		// Save can fail after its rename (the directory sync): the map
		// follows whatever the disk now holds.
		if now, lerr := store.Load(l.path, string(l.pass)); lerr == nil {
			l.swap(now.Secrets)
		}
		return err
	}
	l.swap(d.Secrets)
	return nil
}

func (l *liveSecrets) swap(secrets map[string]string) {
	m := maps.Clone(secrets)
	l.mu.Lock()
	l.m = m
	l.mu.Unlock()
}
