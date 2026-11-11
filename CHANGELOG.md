# Changelog

## 2.0.0

### Breaking

- First public release, under the GNU GPL v3 or later.
- The project is renamed from fleet-broker to credenza. An existing install
  that reissues its CA as `credenza CA` must give every client the new
  certificate and rebuild its images.
  - Go module `github.com/dantoac/fleet-broker` is now
    `github.com/dantoac/credenza`.
  - The command is `credenza` (`cmd/credenza`), built as
    `dist/credenza-<os>-<arch>`; it was `broker` (`dist/broker-<os>-<arch>`).
  - Errors on stderr start with `credenza: ` instead of `broker: `, and the
    proxy's denial bodies read `credenza: denied (<reason>)`.
  - The default `-dir` is `/srv/credenza` (was `/srv/broker`). An install
    that keeps its old directory must pass `-dir /srv/broker` everywhere,
    forced commands included.
  - The 401 answer carries `WWW-Authenticate: Basic realm="credenza"` (was
    `realm="fleet-broker"`).
  - A missing state directory or store now says `(is its filesystem
    mounted?)` instead of `(is the USB stick mounted?)`.
  - The reference deployment (docs/runbook.md) uses user `credenza`,
    `/srv/credenza`, filesystem label `credenzadata`, sshd drop-in
    `10-credenza.conf`, `/usr/local/bin/credenza`, tmux session `credenza`
    and hostname `credenza`.

Unchanged: exit codes, the session and admin protocols, the store, policy
and audit log formats, the socket names (`run/broker.sock`,
`run/admin.sock`). `ssh-command` and `ssh-admin` accept a leading
`credenza` and, for old clients, still a leading `broker`.

### Added

- `credenza ca init -name <cn>` sets the CA certificate's common name,
  `credenza CA` by default (1 to 64 characters, no control characters, no
  leading or trailing space). CAs created before keep their name
  (`fleet-broker CA`) and keep working: nothing checks the common name.
- [docs/spec.md](docs/spec.md): the product specification.

## 1.2.0

- `mint <task> <project> <env>...` narrows a mint to the named grants
  (at most 3).

## 1.1.0

- Renewable leases: `renew` and `serve -max-session`.
- Secrets added, rotated and removed live through `serve`'s admin socket.
- Policy loaded over a separate admin channel (`ssh-admin`,
  `policy-load`).

## 1.0.0

- First release: encrypted store, per-task tokens with leases, TLS
  intercepting proxy, append-only audit log.
