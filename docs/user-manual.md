# credenza — User Manual

credenza keeps your real [secrets](#secret) in an encrypted [store](#store) and gives each agent [task](#task) [temporary tokens](#temporary-token) in their place. The agent's requests pass through credenza, which replaces each temporary token with the real secret on the way out. The agent never holds a real secret.

This manual is for two readers:

| Reader | What they do | Sections |
|---|---|---|
| [Operator](#operator) | installs credenza, stores the secrets, writes the policy, runs the broker | all of them |
| Developer | starts agent tasks through the [launcher](#launcher) and receives the tokens | [Before you begin](#before-you-begin), [Issue, renew and revoke tokens for a task](#issue-renew-and-revoke-tokens-for-a-task), [Troubleshoot](#troubleshoot) |

The sections follow the order of a first installation. Blocks titled **Technical Details** are optional: every task in this manual can be completed without opening one.

Three other documents go deeper, and this manual links to them instead of repeating them:

- [spec.md](spec.md): what credenza guarantees.
- [policy.md](policy.md): the full policy format.
- [runbook.md](runbook.md): a complete reference installation on a Raspberry Pi, step by step (R1 to R16).

## Before you begin

### What you need

- **A host for credenza** that runs no agent. credenza runs on Linux, macOS and FreeBSD. There is no Windows version.
- **The `credenza` program.** Build it with `sh scripts/build.sh` (see the [README](../README.md), "Test and build"), copy the file for your system to the host, and run `credenza version`: it prints the build version.
- **A [service user](#service-user)**: one account on that host that runs every `credenza` command in this manual.
- **A [state directory](#state-directory)** owned by the service user. The default is `/srv/credenza`. Create it before the first command: credenza never creates it.
- **The real secrets** you want agents to use, for example a GitHub access token. Give each one the narrowest permissions its provider allows: that is the first limit, and credenza's [policy](#policy) is the second.

credenza covers secrets that travel in the `Authorization` header of HTTPS requests: the GitHub API, git over HTTPS and LLM APIs. Other kinds of secret, such as SSH logins to servers or database passwords, are not supported; they are future work ([spec.md](spec.md), "Non-HTTP secrets").

credenza does not start agents. Your [launcher](#launcher) does, and asks credenza for the tokens of each task.

### How the commands work

Every action in this manual is one `credenza` command. These rules apply to all of them and are not repeated later:

- **`-dir <dir>`** selects the state directory. Without it, the command uses `/srv/credenza`. The examples in this manual leave it out.
- **Flags go before the names.** Type `credenza secret add -replace github-app`, not `credenza secret add github-app -replace`.
- **Prompts hide what you type.** When credenza asks `passphrase: ` or `secret value: `, nothing appears on screen. Type the value and press Enter. Press `Ctrl-C` at a prompt to cancel: credenza prints `credenza: interrupted` and changes nothing.
- **Every result is one line** starting with `credenza: `, for example `credenza: passphrase changed`. Errors use the same form.
- **Every command ends with an [exit code](#exit-code)**: `0` means it worked. The other codes are listed in [Exit codes](#exit-codes).
- **`credenza help`** prints the list of commands.

### Where to find each task

| You want to | Command | Section |
|---|---|---|
| Create the encrypted store | `credenza init` | [Create the store and add secrets](#create-the-store-and-add-secrets) |
| Add or list secrets | `credenza secret add`, `credenza secret list` | [Create the store and add secrets](#create-the-store-and-add-secrets) |
| Change the passphrase | `credenza passwd` | [Change the passphrase](#change-the-passphrase) |
| Create and export the CA | `credenza ca init`, `credenza ca-cert` | [Create the CA](#create-the-ca) |
| Check or replace the policy | `credenza policy check`, `policy-load` | [Write the policy](#write-the-policy) |
| Start and stop the broker | `credenza serve` | [Run the broker](#run-the-broker) |
| Give a task its tokens | `mint`, `renew`, `revoke` | [Issue, renew and revoke tokens for a task](#issue-renew-and-revoke-tokens-for-a-task) |
| Replace or delete a secret | `credenza secret add -replace`, `credenza secret rm` | [Rotate or remove a secret](#rotate-or-remove-a-secret) |
| See what happened | `audit.log` | [Read the audit log](#read-the-audit-log) |
| Understand an error | | [Troubleshoot](#troubleshoot) |

<details>
<summary>Technical Details</summary>

The state directory holds four things: `store.enc` (the encrypted store), `policy.json` (the policy), `audit.log` (the audit log) and `run/` (the two control sockets of a running `serve`). In the reference installation the directory is mode 0700 and sits on its own filesystem, a USB stick ([runbook.md](runbook.md), R5).

credenza is one static binary written in Go with the standard library only. `scripts/build.sh` writes `dist/credenza-<os>-<arch>` for linux/armv7, linux/arm64, linux/amd64, darwin/arm64, darwin/amd64 and freebsd/amd64, plus `dist/SHA256SUMS`.

Results and errors go to stderr. Only data goes to stdout: secret names, the CA certificate, `policy ok: ...`, the version and the minted tokens.

</details>

## Create the store and add secrets

The store is one encrypted file that holds your real secrets. It opens only with its [passphrase](#passphrase).

### Create the store

1. Log in as the service user.
2. Run `credenza init`.
3. At `new passphrase: `, type a passphrase of at least 12 characters and press Enter.
4. At `repeat passphrase: `, type it again.

credenza prints `credenza: store created at /srv/credenza/store.enc`.

Keep the passphrase somewhere safe, away from the host. credenza has no command to recover it: without the passphrase, neither the store nor any backup of it can be opened.

### Add a secret

Each secret has a name, which the policy uses later, and a value, which is the real credential. A name uses lowercase letters, digits, `.`, `_` or `-`, starts with a letter or digit, and has at most 64 characters. Example: `github-app`.

1. Run `credenza secret add github-app`.
2. If credenza asks `passphrase: `, type the store passphrase.
3. At `secret value: `, paste the real credential and press Enter.

credenza refuses an empty value, a value that starts or ends with a space, and a value containing control characters.

The result line tells you when the change takes effect. It depends on whether the [broker](#broker) is running:

| State of the broker | What credenza asks | Result line | Meaning |
|---|---|---|---|
| Not running | `passphrase: `, then `secret value: ` | `credenza: secret github-app saved; used at next serve start` | The secret is in the store. The broker uses it the next time it starts. |
| Running | `secret value: ` only | `credenza: secret github-app saved; live` | The secret is in the store and the broker uses it at once. No restart. |

To overwrite a secret that already exists, see [Rotate or remove a secret](#rotate-or-remove-a-secret).

### List the secrets

1. Run `credenza secret list`.
2. At `passphrase: `, type the store passphrase.

credenza prints the names, one per line, in alphabetical order. It never prints a value: no command shows a stored secret again.

### Change the passphrase

1. Run `credenza passwd`.
2. At `old passphrase: `, type the current passphrase.
3. At `new passphrase: ` and `repeat new passphrase: `, type the new one (at least 12 characters).

credenza prints `credenza: passphrase changed`.

If the broker is running, restart it afterwards (see [Stop and restart the broker](#stop-and-restart-the-broker)). Until then, `credenza secret add` and `credenza secret rm` fail with the line `the store no longer opens with serve's passphrase` listed in [Error lines](#error-lines).

### Back up the store

Copy `store.enc` and `policy.json` to another machine after every change to a secret, the passphrase, the policy or the CA. The exact commands, and how to restore, are in [runbook.md](runbook.md), R13.

<details>
<summary>Technical Details</summary>

- The store is encrypted with AES-256-GCM. The key is derived from the passphrase with PBKDF2-HMAC-SHA256.
- The passphrase limit is 12 bytes, not characters; the two differ only for non-ASCII characters.
- A command that changes the store holds a lock on it; a second one started meanwhile stops with `credenza: store ... is locked by another credenza process`.
- With `serve` running, `secret add` and `secret rm` send the change to `serve` through `<dir>/run/admin.sock`. `serve` writes the store with the passphrase it was unlocked with, then updates its copy in memory. A live secret value is limited to 16384 bytes.
- The commands that read a passphrase or a secret disable core dumps first.

</details>

## Create the CA

Agents send their requests to credenza instead of directly to GitHub or to the LLM provider. For their programs to accept that, they must trust a certificate that credenza owns: the [CA](#ca). You create it once and install its public certificate wherever agents run.

### Create it

1. List the domains your agents need, for example `github.com` and `anthropic.com`. A domain covers its subdomains: `github.com` covers `api.github.com`. Every host you later write in the policy must fall inside this list.
2. Run `credenza ca init -domains github.com,anthropic.com` (commas, no spaces).
3. At `passphrase: `, type the store passphrase.

credenza prints `credenza: CA created; export it with credenza ca-cert and rebuild every image`.

Options of `credenza ca init`:

| Flag | Effect |
|---|---|
| `-domains d1,d2` | Limits the CA to these domains. Recommended. |
| `-unconstrained` | Creates a CA with no domain limit. Use it only when a program rejects a limited CA: if this CA were stolen, it could impersonate any site to your agents. |
| `-name <cn>` | Sets the name shown for the certificate, `credenza CA` by default (1 to 64 characters). |
| `-force` | Replaces an existing CA. |

`ca init` needs exactly one of `-domains` or `-unconstrained`.

### Export and install the certificate

1. Run `credenza ca-cert > credenza-ca.pem`.
2. At `passphrase: `, type the store passphrase. The file now holds the CA certificate. It is public: copying it around is safe.
3. Install it where the agents run, in one of two ways:
   - in the system's list of trusted certificates of every agent image, or
   - as the CA file of a single program (for git, the setting `http.sslCAInfo`).

Do not use the variable `SSL_CERT_FILE` for this: it replaces the system's trusted certificates instead of adding to them.

### Replace the CA

Replacing the CA changes the certificate every agent must trust.

1. Run `credenza ca init -force` with `-domains` or `-unconstrained`.
2. Restart the broker (see [Stop and restart the broker](#stop-and-restart-the-broker)). The running broker keeps the old CA until then.
3. Export the new certificate and install it again everywhere, as in [Export and install the certificate](#export-and-install-the-certificate).

<details>
<summary>Technical Details</summary>

The CA is an ECDSA P-256 certificate valid for 10 years, limited to server authentication. A CA created with `-domains` carries DNS name constraints and excludes every IP address. Its private key lives inside the encrypted store. Nothing checks the common name, so a CA created under another name keeps working ([spec.md](spec.md), "Data plane").

`ca-cert` prints the certificate in PEM form on stdout.

</details>

## Write the policy

The policy is the file that says which secrets the tasks of each [project](#project) receive, under which variable name, for how long, and which requests each temporary token may make. No agent chooses its secrets: credenza issues only what the policy grants.

In short, the policy lists projects. Each project has [grants](#grant): one grant per secret, with the variable name the task receives (`env`), the name of the secret (`secret`), the [lease](#lease) (`ttl`) and the allowed requests (`allow`: host, methods and paths). The complete format, the path rules and a working example are in [policy.md](policy.md).

### Write the first policy

Do this after [adding the secrets](#add-a-secret) and [creating the CA](#create-the-ca): the broker refuses a policy that names a missing secret or a host outside the CA's domains.

1. Copy the example from [policy.md](policy.md), "Example", and adapt the project name, the secret names and the allowed requests.
2. Save it as `policy.json` in the state directory (`/srv/credenza/policy.json`), as the service user. The file must belong to the service user and must not be writable by anyone else.
3. Run `credenza policy check`.

credenza prints `policy ok: 1 project(s)` (with your number of projects). Otherwise it prints one line starting `credenza: policy: ` that names the field to fix.

`credenza policy check` checks the file's owner, permissions and format only. Secrets and hosts are checked when the broker starts and each time it reads the policy.

### Change the policy later

The broker reads the policy again at every `mint` and every `renew`, so a change needs no restart:

- a new task gets the new policy when its tokens are issued;
- an open task gets it at its next `renew` (within about a minute when the launcher renews every 60 seconds);
- a project removed from the policy loses its tokens at its next `renew`.

There are two ways to change it:

**By hand.** Edit `/srv/credenza/policy.json` as the service user and run `credenza policy check`.

**Remotely, with `policy-load`.** A person or tool holding the [policy key](#policy-key) sends a new policy to the running broker:

1. Run `ssh credenza@<host> policy-load < policy.json` with the policy key.
2. Check the exit code: `0` means the broker checked the policy and put it in force.

If the broker refuses the policy, it prints `credenza: invalid policy: <reason>` and keeps the old one. All outcomes are in [Exit codes](#exit-codes).

Setting up the policy key is in [runbook.md](runbook.md), R8. If a tool generates your policy, change that tool's configuration, not `policy.json`: the next load overwrites a hand edit.

To add a secret and use it in the policy, add the secret first, then change the policy. To retire one, see [Remove a secret](#remove-a-secret).

<details>
<summary>Technical Details</summary>

- `policy-load` is the only verb of the forced command `credenza ssh-admin`. The policy arrives on stdin, at most 256 KiB, and goes to `<dir>/run/admin.sock`.
- `serve` validates the body (strict format, secrets present in the store, hosts inside the CA's name constraints) and replaces `policy.json` atomically, owner the service user, mode 0644.
- Each load writes a `policy` event with the body's SHA-256 to the audit log.
- A renew that changes a token's rules also ends that token's requests in flight ([policy.md](policy.md), "When changes apply").

</details>

## Run the broker

The broker is credenza running: `credenza serve`. While it runs, tasks can receive tokens and agents' requests are served. It asks for the passphrase at every start, so after a reboot of the host credenza stays locked until you start it again.

### Start the broker

1. Log in as the service user, in a terminal that stays open after you log out (the reference installation uses tmux: [runbook.md](runbook.md), R11).
2. Run `credenza serve -clients 192.0.2.20/32`, with the address of the host your agents run on.
3. At `passphrase: `, type the store passphrase. You have three attempts.
4. Wait for the line starting `credenza: serving proxy on`. The broker is now running.

If a line starting `credenza: warning:` appears before it, the broker still runs; look the warning up in [Error lines](#error-lines). If the broker stops instead, its last line says why; the same table lists the causes.

Options of `credenza serve`:

| Flag | Default | Effect |
|---|---|---|
| `-clients <cidr,...>` | none, required | The addresses allowed to send agents' requests, as comma-separated ranges with no spaces, for example `192.0.2.20/32` (one host) or `192.168.1.0/24`. |
| `-listen <addr>` | `:8888` | The address and port where the broker receives agents' requests. |
| `-max-session <dur>` | `24h` | The longest a task can keep its tokens alive by renewing, from `1m` to `720h`. |

### Connect the agents

Three things connect an agent to the running broker:

1. **The certificate**: installed as in [Export and install the certificate](#export-and-install-the-certificate).
2. **The proxy setting**: in the agents' environment, set `HTTPS_PROXY` to the broker's host and port, for example `http://<host>:8888`.
3. **The session key**: the launcher needs the [session key](#session-key) to ask for tokens. Setting it up is in [runbook.md](runbook.md), R10.

To confirm the whole path with a real task, follow the smoke test in [runbook.md](runbook.md), R12.

### Stop and restart the broker

1. In the broker's terminal, press `Ctrl-C` once. The broker stops cleanly.
2. To start it again, repeat [Start the broker](#start-the-broker).

A restart cancels every temporary token. Open tasks stop at their next `renew` and must be started again, so restart when no task is open.

A restart is required after `credenza passwd`, after `credenza ca init -force` and after replacing the `credenza` program ([runbook.md](runbook.md), R14). It is not required for secrets or for the policy.

<details>
<summary>Technical Details</summary>

- `serve` listens on the proxy address and on two Unix sockets, both mode 0600: `<dir>/run/broker.sock` accepts only `mint`, `renew` and `revoke`; `<dir>/run/admin.sock` accepts only `secret-set`, `secret-rm` and `policy-load`. A verb on the wrong socket is refused. There is no HTTP control API.
- The serving line names all three, for example `credenza: serving proxy on [::]:8888, control on /srv/credenza/run/broker.sock, admin on /srv/credenza/run/admin.sock`.
- The proxy answers `CONNECT` only, from the `-clients` addresses, and intercepts the TLS tunnel with a certificate signed by the credenza CA. It replaces the temporary token in `Authorization` with the real secret when host, method, path and lease allow it; otherwise it refuses and never forwards.
- Limits: 256 open connections in total and 32 from one address.
- `serve` keeps the passphrase in memory to save secret changes, and disables core dumps.
- A second `Ctrl-C` during shutdown stops the process at once; the next `serve` removes the leftover sockets.
- Once a minute `serve` checks the free space on the audit log's filesystem ([runbook.md](runbook.md), R11).

</details>

## Issue, renew and revoke tokens for a task

### What the developer sees

You start an agent task with your launcher, for a project such as `example/app`. The launcher asks credenza for the task's tokens and places them in the task's environment, under the variable names the policy gives, for example `GH_TOKEN` and `CLAUDE_CODE_OAUTH_TOKEN`. You do not run any `credenza` command yourself.

What to expect inside the task:

- The values of those variables are temporary tokens, not real credentials. They work only through credenza, only for the hosts, methods and paths the policy allows for your project.
- A request outside those limits is answered `credenza: denied (<reason>)`. See [Inside an agent task](#inside-an-agent-task).
- The tokens stop working when the task ends, when the launcher stops renewing them, or when the task reaches the broker's time limit (24 hours by default). To continue, start a new task.

### The three commands

The launcher sends three commands to the broker with the session key, in the form `ssh credenza@<host> <command>`:

| Command | When | Result |
|---|---|---|
| `mint <task-id> <project> [<env>...]` | once, when the task starts | prints one line per token, `NAME=value`, sorted by name |
| `renew <task-id>` | regularly while the task runs (every 60 seconds in the reference launcher) | prints nothing; extends the task's tokens by one lease |
| `revoke <task-id>` | when the task ends | cancels the task's tokens at once |

- A [task id](#task-id) uses letters, digits, `.`, `_` or `-`, at most 64 characters. A project is written `owner/repo`.
- `mint` with only the task id and the project issues every grant of the project. Adding up to three variable names issues only those: `mint job-7 example/app GH_TOKEN` issues the GitHub token alone. A later `renew` extends only what the `mint` issued.
- One task id holds tokens of one project.

Example, with the policy from [policy.md](policy.md):

```
$ ssh credenza@<host> mint task-1 example/app
CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-...
GH_TOKEN=fbt_...
```

Each command ends with an exit code that the launcher must act on. They are listed in [Exit codes](#exit-codes).

### The states of a task's tokens

| State | Indicator | Meaning | Action |
|---|---|---|---|
| Live | `mint` or `renew` exits `0` | The tokens work within the policy's limits. | Keep renewing while the task runs. |
| Expired | `renew` exits `5` with `credenza: no live tokens` | Nobody renewed within the lease, or the broker was restarted. | Stop the task; start a new one. |
| Session limit reached | `renew` exits `5` with `credenza: max session reached; tokens revoked` | The task reached `-max-session`. | Stop the task; continue the work in a new one. |
| Denied by the policy | `mint` or `renew` exits `4` | The policy does not grant the project, or no longer does. On `renew`, the tokens are cancelled. | Stop the task; ask the operator to check the policy. |
| Revoked | `revoke` exits `0` | The tokens are cancelled. | None. |

A token lives for one lease (the grant's `ttl`) after its `mint` or its last `renew`, and never longer than `-max-session` after its `mint`. If the launcher stops unexpectedly, nobody renews and the tokens run out on their own after one lease.

A request already in progress, such as a long download or a streamed reply, is cut when its token is revoked, when a `renew` changes what the token may do, or within 5 seconds after its lease runs out.

The broker holds at most 1024 live tokens. Revoking each task when it ends keeps the count low.

<details>
<summary>Technical Details</summary>

- `mint`, `renew` and `revoke` are the only verbs of the forced command `credenza ssh-command`, which passes them to `<dir>/run/broker.sock`. A leading `credenza` (or the legacy `broker`) before the verb is accepted.
- A temporary token is a prefix (`fbt_` by default, or the grant's `token_prefix`) followed by 43 base64url characters (32 random bytes).
- Tokens live only in the memory of `serve`.
- `renew` re-reads the policy and sets each token's expiry to `min(now + ttl, mint + max-session)`; a token whose grant is gone is dropped ([spec.md](spec.md), "Surrogate tokens and leases").
- The reference integration, with its `launcher` user, is described in [spec.md](spec.md), "Integration".

</details>

## Rotate or remove a secret

### Rotate a secret

Rotating replaces the value of a secret, for example after its provider issued a new credential.

1. Run `credenza secret add -replace github-app`.
2. Answer the prompts as in [Add a secret](#add-a-secret).

With the broker running, the result line ends in `saved; live`: open tasks use the new value on their next request. Their temporary tokens do not change and nothing needs a restart.

Without `-replace`, credenza refuses to overwrite: `credenza: secret github-app exists; use -replace to overwrite it`.

### Remove a secret

Remove a secret only after the policy stops naming it. Otherwise the tasks that depend on it are denied, and the broker refuses to start.

1. Change the policy so that no grant names the secret (see [Change the policy later](#change-the-policy-later)).
2. Run `credenza secret rm github-app`.

The result line follows the same pattern as for adding:

| State of the broker | What credenza asks | Result line |
|---|---|---|
| Not running | `passphrase: ` | `credenza: secret github-app removed; used at next serve start` |
| Running | nothing | `credenza: secret github-app removed; live` |

After rotating or removing a secret, [back up the store](#back-up-the-store).

## Read the audit log

The audit log is the record of everything credenza decided: every token issued, renewed and revoked, every request an agent made through the broker, and every change to a secret or to the policy. It never contains a secret value or a token.

The log is the file `audit.log` in the state directory (`/srv/credenza/audit.log`). Each line is one event. Only the service user can read it.

### See the latest events

1. Log in as the service user.
2. Run `tail -n 40 /srv/credenza/audit.log` for the last 40 events.
3. To see only refusals, run `grep '"decision":"deny"' /srv/credenza/audit.log | tail -n 20`.

### Read one line

Each line names the event and its decision, plus the fields that apply:

| Field | Content |
|---|---|
| `time` | when it happened (UTC) |
| `event` | what happened; see the next table |
| `decision` | `allow` or `deny` |
| `reason` | a short code that explains the decision |
| `task`, `project` | the task and project concerned |
| `secret` | the name of the secret, never its value |
| `host`, `method`, `path` | the request an agent made (the path without its query) |
| `client` | the address the request came from |

| Event | Written when | `"decision":"allow"` | `"decision":"deny"` |
|---|---|---|---|
| `mint` | a task asks for tokens | tokens issued | reason `project`: the policy does not grant the project; reason `env`: a requested variable is not a grant of the project |
| `renew` | a task's tokens are renewed | renewed; the reason shows how many tokens are live (`live=2`) | reason `gone`: no live tokens; `max-session`: session limit reached; `project`: the policy no longer grants the project |
| `revoke` | a task's tokens are cancelled | cancelled | |
| `proxy` | an agent makes a request | the request was sent with the real secret | the request was refused; the reasons are listed in [policy.md](policy.md), "Widening a rule from audit denials" |
| `secret` | a secret changes while the broker runs | reason `add`, `replace` or `rm` | |
| `policy` | a policy is loaded with `policy-load` | the policy is in force | the policy was refused or could not be written |

### Act on what you read

- **A request you want to allow is denied with reason `scope`.** Add its method and path to the project's rule in the policy, as narrowly as the request needs. The procedure is in [policy.md](policy.md), "Widening a rule from audit denials".
- **Denials at every start of Claude Code.** Several are expected and stay denied on purpose: [policy.md](policy.md), "Expected denials at startup".
- **A `no-token` denial before each git operation.** This is normal: git first asks without credentials, then retries with them.

### Keep the log healthy

When credenza cannot write an allowed event to the log, it refuses the request instead of serving it unrecorded. A full disk therefore stops all work. Check the free space before each start and rotate the log when less than 20% is free: [runbook.md](runbook.md), R15. To make the file append-only, so that it can only grow, see [runbook.md](runbook.md), R9.

<details>
<summary>Technical Details</summary>

- The log is JSON lines, one object per line; `time` is RFC 3339 in UTC.
- The file must be mode 0600; `serve` refuses to start otherwise.
- `host`, `method` and `path` are cut to 253, 16 and 512 bytes.
- Denied requests from one address above one per second on average (bursts of 200) are no longer written; the first skipped one is recorded with reason `rate-limited`, and the broker's terminal shows the count of skipped ones ([runbook.md](runbook.md), R11).
- Refusals that happen before any token is read, such as reason `host`, carry no `task` or `project`.

</details>

## Troubleshoot

Find the exit code or the line credenza printed in the tables below. Parts written `<like this>` vary.

### Exit codes

| Indicator | Commands | Meaning | Action |
|---|---|---|---|
| `0` | all | The command worked. | None. |
| `1` | all | The command failed; the line starting `credenza: ` says why. | Find the line in [Error lines](#error-lines). |
| `2` | all | The command was typed wrongly; the line shows the correct form after `usage:`. | Correct the command. Check that flags come before names. |
| `3` | `mint`, `renew`, `revoke`, `policy-load` | `credenza: broker is locked or not running`. | [Start the broker](#start-the-broker). |
| `4` | `mint`, `renew` | `credenza: policy denies the project "<project>"`: the policy has no grant for this project, or for a variable named in the `mint`. A `renew` that ends this way also cancels the task's tokens. | Stop the task. Add the project or the grant to the policy if it should be allowed. |
| `5` | `renew` | The task has no live tokens (`credenza: no live tokens`) or reached the session limit (`credenza: max session reached; tokens revoked`). | Stop the task and start a new one. |

`policy-load` uses exit `1` for three different outcomes:

| Indicator | Meaning | Action |
|---|---|---|
| `credenza: invalid policy: <reason>` | The policy was refused. The old policy stays in force. | Fix what the reason names and load again. |
| `credenza: write policy: <reason>` | The policy was valid but could not be saved. The old policy stays in force. | Check the state directory's disk space and permissions, then load again. |
| `credenza: write audit log: <reason>` | The new policy is in force, but the event could not be recorded. | Fix the audit log ([Keep the log healthy](#keep-the-log-healthy)) and load the policy again. |

### Error lines

**Any command**

| Indicator | Meaning | Action |
|---|---|---|
| `credenza: flags go before the arguments; usage: ...` | A flag was typed after a name. | Move the flag before the name. |
| `credenza: unknown flag or bad flag value; usage: ...` | A flag does not exist or its value is wrong. | Compare with the form shown after `usage:`. |
| `credenza: want <n> argument(s), got <m>; usage: ...` | A name is missing or there is one too many. | Compare with the form shown after `usage:`. |
| `credenza: unknown command; usage: ...` | The first word is not a credenza command. | Run `credenza help`. |
| `credenza: interrupted` | You pressed `Ctrl-C`. Nothing was changed. | Run the command again. |
| `credenza: tty: standard input is not a terminal` | credenza needs to ask for a passphrase or secret and cannot. | Run the command in an interactive terminal. |

**Store, passphrase and secrets**

| Indicator | Meaning | Action |
|---|---|---|
| `credenza: state directory <dir> not found (is its filesystem mounted?)` | `init` did not find the state directory. | Create or mount the directory, or pass the right `-dir`. |
| `credenza: store already exists at <path>` | `init` found a store and left it untouched. | None; the store is already created. |
| `credenza: no store at <path>; run credenza init` | There is no store in this state directory. | Check `-dir`, or [create the store](#create-the-store). |
| `credenza: passphrase must be at least 12 bytes` | The new passphrase is too short. | Choose a longer passphrase. |
| `credenza: passphrases do not match` | The two entries differ. Nothing was changed. | Run the command again. |
| `credenza: wrong passphrase or corrupted store` | The passphrase did not open the store. | Run the command again with the right passphrase. If it is certainly right, restore the store from a backup ([runbook.md](runbook.md), R13). |
| `credenza: store <path> is locked by another credenza process` | Another command is changing the store right now. | Wait for it to finish and run the command again. |
| `credenza: invalid secret name (want lowercase letters, digits, '.', '_' or '-', at most 64); usage: ...` | The name breaks the naming rule. | Choose a valid name ([Add a secret](#add-a-secret)). |
| `credenza: secret <name> exists; use -replace to overwrite it` | A secret with this name is already stored. | [Rotate the secret](#rotate-a-secret) with `-replace`, or choose another name. |
| `credenza: secret <name> not found` | `secret rm` found no secret with this name. | Check the name with `credenza secret list`. |
| `credenza: secret value is empty`, `... contains a control character`, `... starts or ends with a space`, `... is not valid UTF-8`, `... is longer than 16384 bytes` | The value was refused. | Paste the value again, without surrounding spaces or line breaks. |
| `credenza: the store no longer opens with serve's passphrase (changed with credenza passwd?); restart serve` | The passphrase changed while the broker was running. | [Restart the broker](#stop-and-restart-the-broker). |

**CA**

| Indicator | Meaning | Action |
|---|---|---|
| `credenza: ca init needs exactly one of -domains or -unconstrained; usage: ...` | Neither or both were given. | Give one of them. |
| `credenza: invalid CA domain "<d>" (want a lowercase DNS name with a dot); usage: ...` | An entry of `-domains` is not a domain name. | Write domains such as `github.com`, separated by commas, with no spaces. |
| `credenza: duplicate CA domain "<d>"; usage: ...` | A domain appears twice. | Remove the repetition. |
| `credenza: CA already exists; use -force to replace it` | A CA is already stored. | None, or [replace the CA](#replace-the-ca). |
| `credenza: no CA in store; run credenza ca init` | `ca-cert` or `serve` found no CA. | [Create the CA](#create-the-ca). |

**Policy**

| Indicator | Meaning | Action |
|---|---|---|
| `credenza: policy: <path>: owned by uid <n>, want uid <m>` | The file does not belong to the user running credenza. | Save the file as the service user. |
| `credenza: policy: <path>: group or world writable (mode <mode>)` | Other accounts can change the file. | Remove write permission for everyone but the service user. |
| `credenza: policy: <field>: <rule>` | A field breaks the format. | Fix the field; the rules are in [policy.md](policy.md), "Format". |
| `credenza: policy: secret "<name>" not in store` | A grant names a secret that is not stored. | [Add the secret](#add-a-secret), or fix the name in the policy. |
| `credenza: policy: host "<host>" not permitted by the CA: ...` | A rule names a host outside the CA's domains. | Fix the host, or [replace the CA](#replace-the-ca) with one that covers it. |

**Starting and running the broker**

| Indicator | Meaning | Action |
|---|---|---|
| `credenza: -clients is required; usage: ...` | `serve` was started without `-clients`. | Add `-clients` with the agents' address. |
| `credenza: invalid -clients entry "<s>" (want a CIDR such as 192.168.1.0/24); usage: ...` | An entry is not an address range. | Write each entry as address, slash, length; commas between entries, no spaces. |
| `credenza: invalid -max-session (want a duration from 1m to 720h, such as 24h); usage: ...` | The value is not a duration in range. | Use a value such as `24h`. |
| `credenza: invalid -listen address (want host:port or :port); usage: ...` | The value is not an address and port. | Use a value such as `:8888`. |
| `credenza: store not found at <path> (is its filesystem mounted?)` | The store is missing. Nothing was created. | Mount the state directory's disk, or pass the right `-dir`. |
| `credenza: audit log <path> has mode <mode>, want no group or other access` | Other accounts can read the audit log. | Make the file readable and writable by the service user only ([runbook.md](runbook.md), R9). |
| `credenza: another credenza serve is running on <path>` | A broker is already running on this state directory. | Use the running one, or stop it first. |
| `credenza: warning: audit log <path> is not append-only; run sudo chattr +a on it (runbook R9)` | The broker runs, but the log is not protected against changes. | Stop the broker and follow [runbook.md](runbook.md), R9. |
| `credenza: warning: <n>% free on the filesystem of <path>, below 20%; rotate the audit log (runbook R15)` | The disk holding the audit log is nearly full. | Rotate the log soon ([runbook.md](runbook.md), R15). |
| `credenza: proxy: <n> unaudited denials (...) since <time>` | Refused connections or requests were counted but not written to the audit log. | A growing count points at a program stuck in a loop; see [runbook.md](runbook.md), R11. |

**Tokens**

| Indicator | Meaning | Action |
|---|---|---|
| `usage: mint <task-id> <project> [<env>...] \| renew <task-id> \| revoke <task-id>` | The session key was used for anything but these three commands, or with an invalid task id or project. | Send one of the three commands in this form. |
| `usage: policy-load < policy.json` | The policy key was used for anything but `policy-load`, or the policy is larger than 256 KiB. | Send `policy-load` with the policy file as input. |
| `credenza: token limit reached (1024 live tokens); revoke finished tasks` | The broker holds its maximum of live tokens. | Revoke the tasks that have ended, or wait for their leases to run out. |
| `credenza: task "<task>" has live tokens of another project; revoke it first` | The task id is in use for another project. | Use a new task id, or revoke the task first. |

### Inside an agent task

These are the answers an agent's program receives from the broker instead of the provider's answer:

| Indicator | Meaning | Action |
|---|---|---|
| `403` with `credenza: denied (<reason>)` | The request was refused. The reason is the same code the audit log records. | Give the operator the reason, host, method and path. The operator looks the reason up in [policy.md](policy.md), "Widening a rule from audit denials". |
| `401` | The request carried no credential. | Normal as git's first attempt. Otherwise check that the program uses the task's variables. |
| `503` with `credenza: audit log unavailable` | The broker cannot write its audit log and refuses all requests. | The operator frees space or repairs the log ([Keep the log healthy](#keep-the-log-healthy)). |
| `502` with `credenza: upstream error` | The broker could not reach the provider, or the provider's connection failed. | Try again; if it persists, the operator checks the broker's terminal and the host's network. |
| A certificate error, with no answer from credenza | The program does not trust the credenza CA. | Install the certificate ([Export and install the certificate](#export-and-install-the-certificate)). |
| `Forbidden` on every request right after the task stopped being renewed | The task's tokens were revoked or ran out. | Start a new task. |

## FAQ

**Can an agent ever see a real secret?**
No. credenza never returns a real secret to anyone, the operator included: it only places it in the outgoing request.

**I forgot the passphrase. Can it be recovered?**
No. credenza has no recovery command, and the store and its backups open only with the passphrase. Create a new store and add the secrets again.

**Does credenza start by itself after a reboot?**
No. Someone must [start the broker](#start-the-broker) and type the passphrase. Until then every `mint`, `renew` and `revoke` exits `3`.

**What needs a restart of the broker, and what does not?**
Secrets and the policy change without a restart. A new passphrase, a new CA and a new version of the program need one; see [Stop and restart the broker](#stop-and-restart-the-broker).

**My task stopped after a day. Why?**
A task can renew its tokens only up to `-max-session`, 24 hours by default. Start a new task to continue, or ask the operator to start the broker with a longer `-max-session` (at most `720h`).

**A temporary token leaked. What can be done with it?**
Only what the policy allows that token: its hosts, methods and paths, for the rest of its lease, and only from an address listed in `-clients`. Revoke the task to cancel it at once.

**Can credenza hold an SSH key or a database password?**
Not today. credenza handles credentials sent in the `Authorization` header of HTTPS requests. Other protocols are future work ([spec.md](spec.md), "Non-HTTP secrets"). Use git over HTTPS.

**Can credenza stop an agent from merging its own pull request?**
No. credenza checks the host, method and path of a request, never its content, so a token allowed to use GitHub's GraphQL address can merge. Protect the branches on GitHub: [runbook.md](runbook.md), R16.

**Does credenza run on Windows?**
No. It runs on Linux, macOS and FreeBSD.

**Why does the audit log show denials every time Claude Code starts?**
Some of its startup requests are denied on purpose. See [Act on what you read](#act-on-what-you-read).

**How do I report a security problem?**
See [SECURITY.md](../SECURITY.md).

## Glossary

### Agent

A program driven by an LLM that works on a task, for example a coding assistant. credenza treats agents and the hosts they run on as untrusted.

### Audit log

The file where credenza records every decision. See [Read the audit log](#read-the-audit-log).

### Broker

credenza while `credenza serve` is running. "The broker is locked" means it is not running because nobody has typed the passphrase since the last stop or reboot.

### CA

Certificate authority. The certificate credenza owns, which agents' programs must trust so that their requests can pass through credenza. See [Create the CA](#create-the-ca).

### Exit code

The number a command returns when it ends. `0` means success. Scripts and launchers read it to decide what to do next. See [Exit codes](#exit-codes).

### Grant

One entry of a project in the policy: one secret, the variable name the task receives, the lease, and the allowed requests.

### Launcher

The program on your side that starts agent tasks. It asks credenza for each task's tokens (`mint`), keeps them alive (`renew`) and cancels them (`revoke`). credenza does not include one.

### Lease

How long a temporary token lives after its `mint` or its last `renew`. The policy sets it per grant, in the field `ttl`, for example `5m`.

### Operator

The person who installs credenza, stores the secrets, writes the policy and starts the broker.

### Passphrase

The password that opens the store. credenza asks for it with `passphrase: `.

### Policy

The file `policy.json`, which says what each project's tasks receive and may do. See [Write the policy](#write-the-policy).

### Policy key

An SSH key that can do one thing only: send a new policy with `policy-load`. It cannot read secrets or issue tokens.

### Project

The unit the policy grants secrets to, written `owner/repo`, for example `example/app`.

### Proxy

The part of the broker that agents' requests pass through, where each temporary token is replaced by the real secret.

### Secret

A real credential, such as an access token for GitHub or for an LLM provider, kept in the store under a name.

### Service user

The account on the credenza host that owns the state directory and runs every `credenza` command.

### Session key

An SSH key that can do three things only: `mint`, `renew` and `revoke`. The launcher holds it. It cannot change secrets or the policy.

### State directory

The directory that holds the store, the policy and the audit log: `/srv/credenza`, or the one given with `-dir`.

### Store

The encrypted file `store.enc`, which holds the real secrets and the CA.

### Task

One run of an agent on a project. Its tokens exist only for that run.

### Task id

The name the launcher gives a task, used in `mint`, `renew` and `revoke`.

### Temporary token

The stand-in for a real secret that a task receives. It works only through credenza, within the policy's limits, and only while its lease lasts. [spec.md](spec.md) calls it a surrogate token.
