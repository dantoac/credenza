# Policy reference

The policy says which secrets a project's tasks get on `mint`, as which
environment variable, for how long, and which host, method and path each
temporary token may reach through the proxy.

## Location and ownership

- File: `/srv/credenza/policy.json` (`<dir>/policy.json` with `-dir <dir>`).
- Owner: the user running `credenza serve` (`credenza` in the reference
  deployment), mode 0644.
- `credenza` refuses the file when it is not a regular file, is not owned by
  the user running `credenza`, or is group or world writable:
  `credenza: policy: /srv/credenza/policy.json: group or world writable (mode 0664)`.

Write it by hand as the service user (`sudo -iu credenza`), so the owner
is right, or load it over the admin channel: `credenza ssh-admin` takes the
policy on stdin, `serve` checks it and replaces `policy.json` itself, as
its own user, mode 0644 (see [spec.md](spec.md), "Control plane").

The policy can also be generated from your own configuration and loaded
with `ssh broker-admin policy-load < policy.json` (runbook R8). In that
case edit your configuration, not `policy.json`: the next load overwrites
any hand edit. "The launcher" below is whatever starts agent sessions and
calls `mint`, `renew` and `revoke` for them (runbook R10).

## Format

The decoding is strict: an unknown member, two member names that differ
only in case, a duplicate member or trailing data is an error.

### Policy

| Field | Type | Rule |
|---|---|---|
| `version` | number | must be `1` |
| `projects` | object | key: `owner/repo` (`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`); value: a list of grants |

A project with an empty grant list, or a project missing from the file, is
denied on `mint` (exit 4).

### Grant

| Field | Type | Rule |
|---|---|---|
| `env` | string | `^[A-Z_][A-Z0-9_]{0,63}$`, unique within the project; the variable name `mint` prints |
| `secret` | string | name of a secret in the store, `^[a-z0-9][a-z0-9._-]{0,63}$` |
| `ttl` | string | Go duration (`5m`, `30m`, `24h`), `0 < ttl <= 24h`; the lease, see "Choosing `ttl`" |
| `token_prefix` | string | optional, `^[A-Za-z0-9_-]{0,32}$`; absent or empty means `fbt_` |
| `allow` | list | at least one rule |

A temporary token is the prefix followed by 43 base64url characters
(32 random bytes).

### Rule

| Field | Type | Rule |
|---|---|---|
| `host` | string | lowercase DNS name with at least one dot, no port, no trailing dot, not an IP address, at most 253 bytes |
| `methods` | list | at least one of `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE` |
| `paths` | list | at least one path; see below |

A policy path starts with `/` and must not contain `?`, `#`, `%`, `\`, `;`,
a control character, `//`, or a `.` or `..` segment.

## Path matching

- A rule path ending in `/` is a prefix: `/repos/example/app/` matches
  `/repos/example/app/pulls`, but not `/repos/example/app` (list that one
  separately) and not `/repos/example/app-evil/pulls`.
- Any other rule path matches only the exact request path.
- The query string is never part of the match.
- A request path containing `..` or `.` segments, `//`, `%2F`, `%5C`, `\`,
  `;`, a decoded `%` or a control character is always denied (reason
  `path`), never normalized. The path that was checked is the path that is
  forwarded.

A request is allowed when its token is live and one rule of the token's
grant has the exact host, the exact method and a matching path.

## When changes apply

- Each `mint` and each `renew` reads the file again, so a new policy needs
  no restart. A new session gets it at its `mint`.
- Live tokens get the new rules at their next `renew`: each token takes
  the rules of its grant (same `env`) as the file has them then, and a
  token whose grant is gone is dropped. The launcher renews every 60
  seconds, so a tightened rule (a method, path or host removed) reaches
  every open session within about a minute.
- A project removed from the policy is revoked at its next `renew`, which
  exits 4; the launcher then stops the session.
- A renew that changes a token's rules or secret also ends that token's
  requests in flight, so no stream keeps the old scope.
- `revoke <task>` ends the task's requests in flight at once: a streamed
  response is cut, not left to finish.
- `policy-load` refuses a policy `serve` could not enforce (format,
  missing secret, host outside the CA) and keeps the old file. A `serve`
  restart drops every token; `serve` checks the policy at start and
  refuses to start on any error.

## Choosing `ttl`

`ttl` is the lease: how long a token lives after its `mint` or its last
`renew`. Each `renew` sets the expiry to `min(now + ttl, mint +
max-session)` (`serve -max-session`, 24h by default). The reference launcher
renews every 60 seconds while the session's container runs and revokes it
when the container ends; if the launcher dies, nobody renews and the
tokens lapse after one `ttl`. `5m` is a good default: long enough to ride out a few missed
renews, short enough that a lost launcher leaves no live token for long.
A session longer than `-max-session` ends; continue it in a new session.

A request in flight, such as a streamed Claude Code reply or a long
`git clone`, is not cut at the expiry it had when it started: it ends when
its token is revoked, dropped or changed by a renew, or within 5 seconds
after a lease that nobody renewed runs out.

The broker holds at most 1024 live tokens. A `mint` beyond that exits 1
with `credenza: token limit reached (1024 live tokens); revoke finished tasks`
and writes nothing to the audit log. Expired tokens do not count. Every
`mint` adds one token per grant until `revoke` or the end of its lease;
the launcher revokes each session when its container ends.

## Hosts and the CA

Every policy host must be inside the CA's name constraints
(`credenza ca init -domains github.com,anthropic.com`). A constrained CA
also excludes every IPv4 and IPv6 address, because DNS constraints alone
say nothing about IP names, and every CA is limited to server
authentication: a stolen CA key cannot sign a certificate for an IP
address or for client or code signing that a client accepts. Otherwise `serve`
refuses to start and `mint` exits 1, both with:

```
credenza: policy: host "<host>" not permitted by the CA: ...
```

Every grant's `secret` must also exist in the store when `serve` starts
(`credenza: policy: secret "<name>" not in store`) and when a policy is
loaded (`credenza: invalid policy: secret "<name>" not in store`, exit 1,
old file kept). `policy-load` refuses a host outside the CA the same way
(`credenza: invalid policy: host "<host>" not permitted by the CA: ...`).

Add the secret before applying a policy that names it: `credenza secret add
<name>` on the credenza host while `serve` runs makes it live at once, with no
restart (runbook R7); then load the policy (runbook R8). To retire a secret, apply a
policy without it first, then `credenza secret rm` it.

## Checking the file

```sh
credenza policy check            # -dir /srv/credenza is the default
```

Prints `policy ok: <n> project(s)` and exits 0, or one `credenza: policy: ...`
line and exit 1. `policy check` checks the file's owner, mode and format
only; the CA and store checks above run in `serve`, `policy-load`, `mint`
and `renew`.

## Widening a rule from audit denials

```sh
sudo grep '"decision":"deny"' /srv/credenza/audit.log | tail -n 20      # as admin; or without sudo as credenza
```

Each line has `host`, `method`, `path` (no query) and `reason`. The proxy
answers `403 credenza: denied (<reason>)`, except where the table says
otherwise:

| Reason | Meaning |
|---|---|
| `port` | `CONNECT` to a port other than 443, or to a host that is not a valid policy host (an IP address, a single-label name) |
| `host` | no live token allows the `CONNECT` host |
| `tls` | after `200 Connection Established`, the client's TLS handshake failed, timed out or named another host (SNI); the connection is closed with no HTTP error. A client that does not trust the credenza CA ends here |
| `host-mismatch` | the request's `Host` differs from the `CONNECT` host |
| `upgrade` | protocol upgrade (WebSocket and similar) |
| `no-token` | no `Authorization` header; answered 401, not 403 |
| `token` | unknown, expired, revoked or malformed token, or more than one `Authorization` header |
| `path` | request path refused by the rules under "Path matching" |
| `scope` | the token's rules do not allow this host, method and path |
| `secret` | the grant's secret is missing or empty in the running store |
| `rate-limited` | the client sent more than one denied request a second on average (bursts of 200); the request was denied for one of the reasons above, and this line marks where the broker stopped writing that client's denials until its rate drops. The skipped ones are counted on the broker's stderr (runbook R11). Every agent on one host shares that host's rate |

A `no-token` line before each git operation is normal: git first sends no
credentials, gets 401 and retries with them.

The 20th denied request on one tunnel is answered with `Connection:
close` and ends the tunnel; the client opens a new one. Allowed requests
are always written, whatever the rate.

Skip the requests listed under "Expected denials at startup": they stay
denied on purpose.

To allow a `scope` denial, add its method and path to the matching rule
of the policy, as narrowly as the request needs, and load it (runbook R8). New sessions get it at `mint` and open sessions at their
next `renew` (see "When changes apply").

Other events have their own reasons: `renew` denies with `gone` (no live
tokens), `max-session` or `project` (the policy no longer grants the
project), and a `policy` event (one per `policy-load`) has `sha256=<hex>`
of the loaded body on `allow`, and `invalid sha256=<hex>` (refused body)
or `failed sha256=<hex>` (the file could not be written; the old one is
kept) on `deny`.

## Example

Identical to `internal/policy/testdata/valid.json`, which the tests use:

```json
{
  "version": 1,
  "projects": {
    "example/app": [
      {
        "env": "GH_TOKEN",
        "secret": "github-app",
        "ttl": "5m",
        "allow": [
          {"host": "api.github.com", "methods": ["GET"],
           "paths": ["/repos/example/app/", "/repos/example/app"]},
          {"host": "api.github.com", "methods": ["POST"],
           "paths": ["/graphql"]},
          {"host": "github.com", "methods": ["GET", "POST"],
           "paths": ["/example/app.git/info/refs", "/example/app.git/git-upload-pack", "/example/app.git/git-receive-pack",
                     "/example/app/info/refs", "/example/app/git-upload-pack", "/example/app/git-receive-pack"]}
        ]
      },
      {
        "env": "CLAUDE_CODE_OAUTH_TOKEN",
        "secret": "claude-oauth",
        "ttl": "5m",
        "token_prefix": "sk-ant-oat01-",
        "allow": [
          {"host": "api.anthropic.com", "methods": ["GET", "HEAD", "POST"],
           "paths": ["/v1/messages", "/v1/messages/count_tokens", "/api/hello", "/api/oauth/", "/api/event_logging/"]}
        ]
      }
    ]
  }
}
```

`mint <task> example/app` prints two lines, sorted by name:

```
CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-...
GH_TOKEN=fbt_...
```

### Why these hosts, methods and paths

The example grants only what the deliverable needs, a draft PR:
`gh pr create --draft`, git smart HTTP and the model API.

- `gh pr create --draft --title T --body B` on a repo the token can push
  to sends every API request as `POST https://api.github.com/graphql` and
  pushes the branch with `git push`. The only REST write on that path is
  `POST .../forks`, used only when a fork is needed. `gh pr close` is
  GraphQL too. `gh api <path>` is `GET` without fields. So REST gets `GET`
  only, and `POST` is limited to `/graphql`.
- No `PUT`, `PATCH` or `DELETE` anywhere:
  `PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge` (and
  `.../merge-async`) merges a PR, `DELETE /repos/{owner}/{repo}` deletes the
  repo, and `POST /repos/{owner}/{repo}/merges` merges a branch without a
  PR. `gh pr close --delete-branch` therefore fails on its REST
  `DELETE .../git/refs/heads/<branch>`; delete branches with
  `git push origin --delete <branch>` instead.
- git smart HTTP: the exact paths `info/refs`, `git-upload-pack` and
  `git-receive-pack`, with and without `.git`. The query
  (`?service=...`) is never part of the match.
- Claude Code: `/v1/messages` (sent as `/v1/messages?beta=true`), the
  optional `/v1/messages/count_tokens`, `HEAD /api/hello`, and the
  `/api/oauth/` and `/api/event_logging/` prefixes seen at startup. The
  WebFetch domain safety check also calls `api.anthropic.com`, on a path no
  source documents: it gets 403 `scope` here. Either set
  `skipWebFetchPreflight: true` in the Claude Code settings of the image,
  or add the path from the audit denials.
- `token_prefix` `sk-ant-oat01-` keeps the temporary token shaped like the
  OAuth token, because no source says whether Claude Code checks the
  prefix.

### Expected denials at startup

With the example policy, every Claude Code start leaves these denials in
the audit log. Claude Code starts and answers with them denied (runbook
R12), so they stay denied unless the check below shows a lost feature. Do
not widen a rule for them.

| Request | Reason | Why it stays denied |
|---|---|---|
| `GET api.anthropic.com /api/claude_code/settings` | `scope` | No source documents the path. The name suggests the server-managed settings fetch (1), which can push server-side hooks, environment variables and permission rules (2) into unattended agents. That fetch also repeats hourly (1), so a long session may leave more of these lines. Claude Code continues without it unless a managed source sets `forceRemoteSettingsRefresh` (3). |
| `GET api.anthropic.com /api/claude_code/policy_limits` | `scope` | No source documents the path. |
| `GET api.anthropic.com /api/claude_cli/bootstrap` | `scope` | No source documents the path. |
| `GET api.anthropic.com /api/model_selector/cc` | `scope` | No source documents the path. |
| `POST api.anthropic.com /api/eval/sdk-...` (paths starting with `/api/eval/sdk-`) | `scope` | No source documents the path. The name suggests feature-flag evaluation (4). |
| `CONNECT http-intake.logs.us5.datadoghq.com` | `host` | Optional operational telemetry (5, 6). Allowing it needs a new CA with `datadoghq.com` in `-domains` ("Hosts and the CA"), which optional telemetry does not justify. |
| `GET github.com /anthropics/claude-plugins-official.git/info/refs` | `scope`, after a `no-token` probe | Seen at every interactive start in the 1.1.0 deploy smoke (2026-11-04: 2 `no-token` and 2 `scope` lines). The path is the official plugin marketplace repository; `git` first asks without credentials (`no-token`), then with the session's GitHub token, which the project grant does not cover (`scope`). Claude Code keeps working. Either turn the marketplace fetch off in the agent's settings or allow the path. |

None of the five `api.anthropic.com` paths appears in the network-config,
data-usage or server-managed-settings pages of the Claude Code docs, nor
in the research notes (section "Sources" at the end of this page). The
purposes above are guesses from the names. Allow one of them only if a
test shows a lost feature: add the one path to the policy, `mint` a test
task, start `claude --debug`, and compare the behavior (model list,
feature flags) with and without it; then remove the path and `revoke` the
test task.

Not known yet: which process sends the Datadog `CONNECT` and
`POST /api/eval/sdk-...`. The reference launchers set
`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`, which the docs say disables
both Datadog hosts (6) and feature-flag evaluation (4), yet both requests
still reach the broker. Either the variable does not reach
the process that sends them, or these requests are not what the docs
describe. It matters because a process that misses the variable may send
other non-essential traffic too, and because a `host` denial is written
before any token is looked up, so its audit line has no `task` or
`project` to name the sender. If a later check stops either request,
remove it from the table.

Sources:

1. https://code.claude.com/docs/en/server-managed-settings: "Claude Code
   fetches settings from Anthropic's servers at startup and polls for
   updates hourly during active sessions." The page names the host
   `api.anthropic.com`, not the path.
2. Same page: "All settings available in `settings.json` are supported
   except those restricted to OS-level policy delivery; see Current
   limitations for that short list. This includes hooks, environment
   variables, and managed-only settings like
   `allowManagedPermissionRulesOnly`."
3. Same page: "If the fetch fails, Claude Code continues without
   server-managed settings and warns in interactive sessions that no
   remote policy applies; endpoint-managed settings still apply. If a
   managed source sets `forceRemoteSettingsRefresh`, Claude Code exits
   instead"
4. https://code.claude.com/docs/en/data-usage: "Setting
   `DISABLE_TELEMETRY` or `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` also
   disables feature-flag evaluation, which can make Remote Control
   unavailable; `DISABLE_ERROR_REPORTING` doesn't."
5. https://code.claude.com/docs/en/network-config, the row for
   `http-intake.logs.us5.datadoghq.com`: "Operational telemetry events,
   sent only when the CLI uses the Anthropic API directly, never for
   Amazon Bedrock, Google Cloud's Agent Platform, or Microsoft Foundry.
   Optional: disable with `DISABLE_TELEMETRY` or `DO_NOT_TRACK`"
6. Same page: "The two Datadog intake hosts carry only optional
   operational telemetry, and setting
   `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` disables both."

### Limit: GraphQL

`POST /graphql` carries reads and writes alike, including
`mergePullRequest`, `enablePullRequestAutoMerge`, `mergeBranch`,
`createCommitOnBranch` and `updateRefs`. The broker matches method and
path, never the body, so a token that may `POST /graphql` can merge. Protect
the default branch on GitHub instead (runbook R16).

