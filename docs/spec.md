# credenza specification

credenza is a credential broker for LLM agents. It keeps real secrets in an
encrypted store, hands each agent task temporary surrogate tokens, and runs
an HTTPS proxy that swaps a surrogate for the real secret on the way out.
The agent never holds a real credential.

Commands, flags and exit codes: [README](../README.md). Policy format:
[policy.md](policy.md). Reference deployment: [runbook.md](runbook.md).

## Hard rule

Secrets never live in the environment of any LLM. credenza never returns a
real secret to anyone: it injects it into the outgoing request.

## Surrogate tokens and leases

- One surrogate token per policy grant, per task. The grant names the
  environment variable the task receives it in, for example `GH_TOKEN` or
  `CLAUDE_CODE_OAUTH_TOKEN`.
- A token lives as long as the task that holds it:
  - `mint` issues the task's tokens with a short lease (the grant's `ttl`
    in the policy).
  - `renew` extends the lease of every token of the task. The caller
    renews periodically while the task runs (every 60 seconds in the
    reference integration).
  - `revoke` invalidates every token of the task when it ends.
  - If the caller dies, nobody renews and the lease runs out on its own
    soon after.
  - Absolute cap per task: `serve -max-session`, 24 h by default. At the
    cap `renew` fails (exit 5) and the caller stops the task; work
    continues in a new task.
- `renew` applies the current policy to the task's tokens: a permission
  removed from the policy reaches open tasks at their next renew, with no
  restart. When the policy no longer grants the project, `renew` revokes
  the task and exits 4.
- `mint <task> <project> <env>...` narrows the mint to the named grants of
  the project (at most 3). It only restricts, never widens: `renew` only
  extends the tokens the mint issued.
- A request in flight, such as a long streamed LLM reply, is cut when its
  token is revoked or its lease runs out, not at the expiry it had when it
  started.
- Tokens live only in memory. A restart of `serve` invalidates all of them.
- Each token has a scope: host, HTTP methods and path prefixes.
- The real secret's own scope is the primary limit (for example a GitHub
  fine-grained PAT limited to one repository: Contents RW, Pull requests
  RW, no Workflows). credenza's scope is the second layer.

## Who issues

No LLM chooses which secret it receives.

- The policy, `project -> {secret, host, methods, path prefixes, ttl}`, is
  a file owned by the service user. `serve` reads it again at every `mint`
  and every `renew`.
- The caller asks for "task T on project P"; credenza issues only what the
  policy grants.

## Control plane

- `credenza serve` listens on two Unix sockets, mode 0600:
  `<dir>/run/broker.sock` accepts only `mint`, `renew` and `revoke`;
  `<dir>/run/admin.sock` accepts only secret and policy administration
  (`secret-set`, `secret-rm`, `policy-load`). A verb on the wrong socket is
  refused.
- Session channel: `ssh credenza@<host> mint <task> <project> [<env>...] |
  renew <task> | revoke <task>`, with a key whose `authorized_keys` line is
  `restrict,from="<caller>/32",command="credenza ssh-command ..."`. That
  limits the key to the three verbs. `restrict` is mandatory: a forced
  command alone does not stop `ssh -L` from forwarding to `admin.sock`.
  Exit codes: 0 ok, 1 error, 2 usage, 3 locked or not running, 4 the
  policy denies, 5 the task has no live tokens (`renew`).
- Admin channel, separate: a second key with
  `restrict,from="<caller>/32",command="credenza ssh-admin ..."`, which
  accepts only `policy-load` (the new policy on stdin, at most 256 KiB).
  `serve` validates it (format, secrets present in the store, hosts inside
  the CA's name constraints) before replacing the file atomically.
  `ssh-admin` talks only to `admin.sock`; the session key never reaches it.
- Both forced commands accept an optional leading `credenza` (and the
  legacy `broker`) before the verb.
- Secrets are managed only on the credenza host: `credenza secret add|rm
  <name>` as the service user, with the value typed without echo. With
  `serve` running, the command talks to `admin.sock`: `serve` updates the
  in-memory map and saves the encrypted store with the passphrase it kept
  from the unlock. Without `serve`, the command writes the store itself. No
  secret verb goes over SSH.
- Rotating a secret does not touch tokens: the proxy looks the value up by
  name on each request, so open tasks use the new value on their next
  request.
- There is no HTTP control API.

## Data plane

- HTTP(S) proxy on `serve -listen` (`:8888` by default). It answers
  `CONNECT` only, from the clients listed in `serve -clients`, and
  intercepts the TLS tunnel with a leaf certificate signed by the credenza
  CA.
- It replaces the surrogate in `Authorization` with the real secret when
  host, method, path and lease allow it; otherwise it refuses (401 without
  `Authorization`, 403 in every other case) and never forwards.
- The CA (`credenza ca init`) is ECDSA P-256, valid 10 years, limited to
  server authentication, and normally name-constrained to the policy's
  domains (`-domains`), with every IP address excluded. `-unconstrained` is
  the fallback for a client that rejects name constraints. `-name` sets the
  common name, `credenza CA` by default; nothing checks it, so a CA created
  under another name keeps working.
- Clients trust the CA through their system trust store, installed at
  image build time, or through a per-command CA file. Not through
  `SSL_CERT_FILE`, which replaces the default locations instead of adding
  to them.
- Covers HTTPS APIs whose credential travels in `Authorization`: the
  GitHub API, git over HTTPS and LLM APIs.

## Store and unlock

- Store encrypted with AES-256-GCM; the key is derived with
  PBKDF2-HMAC-SHA256 (`crypto/pbkdf2`, standard library since Go 1.24).
- The CA's private key lives in the store.
- No service manager: the operator starts `serve` (in tmux in the reference
  deployment) and types the passphrase. Reading without echo uses
  `stty -echo` through `os/exec`, because the standard library has no
  no-echo read and `golang.org/x/term` is outside the standard-library-only
  rule.
- `serve` keeps the passphrase in memory while it runs, to save secret
  changes; it already holds the decrypted secrets, so this exposes nothing
  new. Core dumps are disabled (`RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`).
- After a reboot credenza stays down until it is unlocked (fails closed).

## Audit log

Append-only (`chattr +a` on Linux). Per event: task, secret name, host,
method, path, time, decision and reason. Events `mint`, `renew`, `revoke`,
`proxy`, `secret` and `policy`. Never secret values. When an allow cannot
be written, the request is refused (fails closed).

## Security model

- Trust boundary: the credenza host and its service user. The agents and
  the hosts they run on are untrusted; they hold only surrogates.
- A stolen surrogate is worth only its scope (host, methods, paths) for
  the remainder of its lease, and only from a listed client.
- A stolen CA key can impersonate only the constrained domains, only for
  server authentication, and never for an IP address.
- The policy key can change the policy but cannot read secrets or mint;
  the session key can mint but cannot change policy or secrets.
- Out of scope: what a valid token does inside its scope (for example a
  GraphQL mutation on an allowed `POST /graphql`). Branch protection and
  the real secret's own scope cover that.

## Moving parts

One binary, one encrypted store, one policy file, one audit log.

## Implementation

- Go, standard library only, `CGO_ENABLED=0`, one static binary.
- Targets: linux/arm (v7), linux/arm64, linux/amd64, darwin, freebsd. No
  Windows.
- Why not Python/FastAPI: Python's standard library has no AES and cannot
  create certificates; FastAPI shipped 122 releases in 12 months and is
  still 0.x. Go releases every six months, supports each release until two
  newer ones exist, and keeps the Go 1 compatibility promise.

## Hosting

Any small Linux host that runs no LLM. The reference deployment is a
Raspberry Pi 2 Model B (rev 1.1: 32-bit Cortex-A7, armhf, `GOARCH=arm
GOARM=7`) with Raspberry Pi OS Lite:

- CPU does not matter at personal scale: the 100 Mb/s Ethernet is the
  bottleneck, as on a Pi 3B, and also the ceiling for large clones.
- No Wi-Fi or Bluetooth on the board: less attack surface than a Pi 3B.
- 1 GB of RAM. Expected footprint (estimate, not measured): tens of MB of
  RAM, a binary of about 10 MB, a store of KB, logs of MB.
- AES runs in software; credenza does not depend on AES instructions.
- Store and audit log on a separate filesystem when possible (a USB stick),
  with a backup of the encrypted store on another machine.

## Non-HTTP secrets

git always over HTTPS. Other protocols (SSH to servers, databases) are
future work: credenza would run predefined, bounded actions instead of
issuing tokens.

## Integration

credenza does not start agents. A launcher on your side does, and drives
credenza over the two SSH channels. The reference integration:

- The launcher, as user `launcher` on a controller host, calls `mint`,
  `renew` (every 60 seconds) and `revoke` over the session channel for each
  agent session container, and passes the minted variables into the
  container's environment. A job that needs one secret only, such as a git
  cache refresh, narrows its mint: `mint <task> <project> GH_TOKEN`.
- A separate user, `policyadmin`, renders the policy from its own
  configuration (lease `5m` by default) and loads it over the admin channel
  (`ssh broker-admin policy-load`).
- The only proxy client is the host that runs the agent containers: their
  egress goes through credenza's proxy (`HTTPS_PROXY`), and the CA is in
  every session image's system trust store.
- Grants are `GH_TOKEN` (a fine-grained PAT per repository) and
  `CLAUDE_CODE_OAUTH_TOKEN` (from `claude setup-token`).

The deployment steps are in [runbook.md](runbook.md).
