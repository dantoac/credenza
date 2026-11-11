# Deploy runbook

The reference deployment: credenza on a Raspberry Pi 2 Model B serving a
small set of LLM agent hosts on a home network. The host names, users,
addresses (from the documentation range 192.0.2.0/24) and the
`launcher`/`policyadmin` callers below are examples; adapt them to your
network. For what credenza does, see [spec.md](spec.md).

The launcher is whatever starts agent sessions on your side: it mints a
task's tokens, renews them every 60 seconds while the session runs and
revokes them when it ends ([spec.md](spec.md), "Integration").

For the user to run by hand. Every step lists exact commands and a check.
Steps R1 to R12 and R16 run once, before the first agent task, with R13
(backup) right after R8 and R16 after R12 (R12 deletes its test branches,
which R16 forbids). R16 is the only guard against a merge through GraphQL
and against a token deleting or rewriting branches; do not skip it. R11 runs again after every reboot. R13 to R15 are
maintenance.

`/srv/credenza` is mode 0700, owned by `credenza`, so the admin account reads
anything in it only through `sudo`.

Hosts:

| Host | Role | Address |
|---|---|---|
| Mac | builds the binary, keeps backups, admin SSH | reserved in R2 |
| Pi 2 Model B rev 1.1 | runs `credenza` | reserved in R2 |
| controller | mints, renews and revokes tokens as `launcher` (R10); loads the policy as `policyadmin` (R8); not a proxy client | 192.0.2.10 (to reserve in R2) |
| agent-host | the only proxy client: the agent session containers reach credenza through it | 192.0.2.20 (to reserve in R2) |

Set these once per shell, on every host where a step uses them:

```sh
PI=<address reserved for the Pi in R2>
ADMIN=<admin user created in R1>
MAC_IP=<address reserved for the Mac in R2>
```

Conventions of the `credenza` command:

- `-dir` defaults to `/srv/credenza`; every subcommand accepts it.
- Flags go before positional arguments: `credenza secret add -replace github-app`,
  not `credenza secret add github-app -replace`.
- Errors are one line starting `credenza: ` on stderr. Admin commands exit 0
  ok, 1 error, 2 usage. `mint`, `renew` and `revoke` exit 0 ok, 1 error,
  2 usage, 3 broker locked or not running, 4 policy denies the project
  (`renew` then revokes the task); `renew` exits 5 when the task has no
  live tokens or reached `-max-session`. `policy-load` exits 0 ok,
  1 invalid or failed, 2 usage, 3 broker locked or not running.
- `serve` reads the store once, at start. While it runs, `secret add` and
  `secret rm` go to the admin socket and take effect at once (R7), and
  `policy-load` replaces the policy at once (R8). `passwd` and
  `ca init -force` work while it runs, but take effect only after a
  `serve` restart (R14 steps 2 and 4); after `passwd`, live secret writes
  fail until that restart.
- A `serve` restart drops every token. Each open session's next `renew`
  then exits 5 and the launcher stops it; start it again.

## R1 Flash the SD card (Mac)

In Raspberry Pi Imager choose device "Raspberry Pi 2 Model B" and OS
"Raspberry Pi OS Lite (32-bit)" (Debian trixie, armhf). In the
customisation set:

- hostname `credenza`;
- the admin user (`$ADMIN`);
- SSH with public-key authentication only, with the Mac's key.

The SD card stays the boot device: the Pi 2 rev 1.1 cannot boot from USB.

Check: `ssh $ADMIN@credenza.local true` from the Mac (or the Pi's
address from the DHCP leases) exits 0 without a password prompt.

## R2 Network (DHCP server and router)

Reserve fixed leases for:

- the Pi (its MAC: `ssh $ADMIN@credenza.local ip link`);
- the Mac (its address: `ipconfig getifaddr en0`, or the interface that
  `route -n get default` names; R3's firewall admits SSH only from it and
  controller). If the Mac uses a private Wi-Fi address that changes, the
  reservation stops matching and R3 locks it out: keep one address for
  this network;
- the controller (192.0.2.10 in the examples);
- the agent host (192.0.2.20 in the examples).

Firewall rules, which take effect only if the Pi is moved to its own
interface or VLAN, because a router cannot filter traffic between hosts on
the same subnet:

- allow TCP 8888 to the Pi from agent-host;
- allow TCP 22 to the Pi from controller and the Mac;
- block everything else to the Pi.

Until then, the Pi's own firewall (R3), the broker's `-clients` list (R11)
and the tokens are the gates.

If a reserved address differs from the ones above, use it in R3 (firewall),
R8 and R10 (`from=`) and R11 (`-clients`).

Check: after a reboot of each host, `ip -4 addr` on it shows the reserved
address.

## R3 Base system (Pi, as admin)

```sh
ssh $ADMIN@$PI
sudo apt update && sudo apt full-upgrade -y && sudo apt install -y tmux nftables
printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\n' | sudo tee /etc/ssh/sshd_config.d/10-credenza.conf
sudo sshd -T | grep -E '^(passwordauthentication|kbdinteractiveauthentication) '
sudo install -d -m 0755 /etc/rpi/swap.conf.d
printf '[Main]\nMechanism=none\n' | sudo tee /etc/rpi/swap.conf.d/90-disable-swap.conf
sudo reboot
```

Check:

- Both `sshd -T` lines end in `no`. Both options default to yes, and the
  first value sshd reads wins, hence a file early in `sshd_config.d`.
- After the reboot, `ssh -o PubkeyAuthentication=no $ADMIN@$PI` from the
  Mac is refused.
- After the reboot, `swapon --show` prints nothing and `ls /var/swap`
  reports no such file.

Why swap is off: the image swaps through `rpi-swap` (no `dphys-swapfile`).
Its default mechanism `auto` means `zram+file`, which writes idle zram
pages to `/var/swap` on the SD card, so secrets in the broker's memory
could reach the card. `Mechanism=none` is the documented way to turn it
off; it removes `/var/swap` and needs a reboot. Do not purge `rpi-swap`:
`systemd-zram-generator` would then turn zram0 back on. Run
`swapon --show` again after every `apt full-upgrade`.

### R3 firewall (Mac, after the reboot above)

A host on the LAN can open connections to the Pi faster than `credenza`
can refuse them, and the Pi has no swap: an out-of-memory kill leaves the
broker locked until someone types the passphrase again. The firewall drops
everything except SSH from controller and the Mac, the proxy port from the
`-clients` host of R11 (agent-host only), loopback, replies to the Pi's own connections,
DHCP replies and IPv6 neighbour discovery. In a shell on the Mac with
`MAC_IP` set:

```sh
ssh $ADMIN@$PI "cat > nftables.conf" <<EOF
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
	chain input {
		type filter hook input priority 0; policy drop;
		iif lo accept
		ct state invalid drop
		ct state established,related accept
		icmpv6 type { nd-neighbor-solicit, nd-router-advert, nd-neighbor-advert } accept
		udp sport 67 udp dport 68 accept
		ip saddr { 192.0.2.10, $MAC_IP } tcp dport 22 accept
		ip saddr 192.0.2.20 tcp dport 8888 accept
	}
}
EOF
ssh -t $ADMIN@$PI 'cat nftables.conf && sudo nft -c -f nftables.conf && sudo systemctl disable nftables.service && sudo install -o root -g root -m 0644 nftables.conf /etc/nftables.conf && rm nftables.conf && sudo nft -f /etc/nftables.conf'
ssh -o ControlMaster=no -o ControlPath=none $ADMIN@$PI true && ssh -t $ADMIN@$PI 'sudo systemctl enable nftables.service && sudo reboot'
```

- `cat` must show the Mac's address in place of `$MAC_IP`; the unquoted
  `EOF` makes the Mac's shell substitute it.
- `nft -c` checks the file without applying it. `systemctl disable` makes
  sure no boot loads the new file before it is tested. `nft -f` then
  loads it for the running system only; the session in progress survives
  as an established connection.
- The third `ssh` opens a new TCP connection: `ControlMaster=no` and
  `ControlPath=none` stop it from reusing a multiplexed one from
  `~/.ssh/config`, which would pass even with a wrong `MAC_IP`. If it
  fails, the rules lock the Mac out: power-cycle the Pi (the rules are not
  loaded at boot yet), fix `MAC_IP` and run the block again. Only after it
  succeeds does `systemctl enable` make the rules load at every boot.
- The two address lists must match R8 and R10 (`from=`) and R11 (`-clients`);
  `8888` must match R11's `-listen` port. Change all of them together.

Check, after the reboot:

- From the Mac: `ssh -t $ADMIN@$PI sudo nft list ruleset` shows the table
  with `policy drop`.
- From agent-host (a proxy client, not an SSH host), port 22 is closed:
  `timeout 5 bash -c "</dev/tcp/$PI/22" && echo open || echo closed`
  prints `closed`. Once R11 runs, the same line with `8888` prints `open`.
- From the Mac and from controller (SSH hosts, not proxy clients), once R11
  runs: `nc -z -w 5 $PI 8888 && echo open || echo closed` prints `closed`.

## R4 Service user (Pi, as admin)

```sh
sudo adduser --disabled-password --comment "credenza" credenza
echo 'set-option -g remain-on-exit on' | sudo -u credenza tee /home/credenza/.tmux.conf
```

Not `--disabled-login` or `--system`: both set the shell to
`/usr/sbin/nologin`, and sshd runs the forced command of R10 through the
login shell.

`remain-on-exit` keeps the broker's tmux pane open after `serve` exits, so
its last error line stays readable. tmux reads the file only when its
server starts.

Check: `getent passwd credenza` ends in `/bin/bash`;
`sudo -u credenza cat /home/credenza/.tmux.conf` shows the line.

## R5 USB stick (Pi, as admin; destroys the stick's contents)

```sh
lsblk -f                                   # identify the stick, for example sda1
sudo mkfs.ext4 -L credenzadata /dev/sda1     # replace sda1 with what lsblk showed
sudo install -d -o root -g root -m 0755 /srv/credenza
echo 'LABEL=credenzadata /srv/credenza ext4 defaults,noatime,nosuid,nodev,noexec,nofail,x-systemd.device-timeout=10s 0 2' | sudo tee -a /etc/fstab
sudo systemctl daemon-reload
sudo mount /srv/credenza && mountpoint /srv/credenza
sudo chown credenza:credenza /srv/credenza && sudo chmod 0700 /srv/credenza
```

Check:

- `mountpoint /srv/credenza` prints `/srv/credenza is a mountpoint`.
- `findmnt -no OPTIONS /srv/credenza` lists `nosuid`, `nodev` and `noexec`:
  the stick holds data only (no setuid, no device nodes, no executables).
- `ls -ld /srv/credenza` shows `drwx------ credenza credenza`.

`nofail` lets the Pi boot without the stick. The SD-card directory under
the mount point stays root-owned, so without the stick `credenza` cannot
write there, and both `credenza init` and `credenza serve` stop before creating
anything.

## R6 Binary (Mac, then Pi)

On the Mac:

```sh
cd ~/code/credenza && sh scripts/build.sh && grep ' credenza-linux-armv7$' dist/SHA256SUMS
scp dist/credenza-linux-armv7 $ADMIN@$PI:credenza-linux-armv7
```

On the Pi, as admin, with the line `grep` printed above pasted into `SUM`:

```sh
SUM='<64 hex digits>  credenza-linux-armv7'      # paste the whole line
printf '%s\n' "$SUM" | sha256sum -c && sudo install -o root -g root -m 0755 credenza-linux-armv7 /usr/local/bin/credenza && rm credenza-linux-armv7 && credenza version
```

`build.sh` refuses a Go older than go1.27.3 (crypto/x509 security fixes)
and writes six binaries plus `dist/SHA256SUMS`.

The binary waits in the admin's home, not in the world-writable `/tmp`,
and `install` runs only when `sha256sum -c` prints
`credenza-linux-armv7: OK`; on `FAILED` nothing is installed: copy it again.

Check: `sha256sum -c` prints `credenza-linux-armv7: OK`; `credenza version`
prints the build version (`git describe --tags --always --dirty` at build
time: the tag, or the commit hash when there is no tag; `-dirty` means
uncommitted changes).

## R7 Store, secrets and CA (Pi)

```sh
sudo -iu credenza
credenza init
credenza ca init -domains github.com,anthropic.com
credenza secret add github-app      # fine-grained PAT for example/app: Contents RW, Pull requests RW, no Workflows
credenza secret add claude-oauth    # output of `claude setup-token`
credenza secret list
exit
sudo -u credenza credenza ca-cert > ~/credenza-ca.pem     # back as admin; asks for the passphrase
```

- `init` asks `new passphrase: ` and `repeat passphrase: ` (at least 12
  bytes) and prints `credenza: store created at /srv/credenza/store.enc`.
  Without the stick it stops with `credenza: state directory /srv/credenza not
  found (is its filesystem mounted?)` or a permission error.
- `ca init` needs exactly one of `-domains` or `-unconstrained`. Every
  policy host must fall inside the domains. `-name <cn>` sets the
  certificate's common name, `credenza CA` by default: the label trust
  stores and `openssl x509 -subject` show (1 to 64 characters, no control
  characters, no leading or trailing space). It prints
  `credenza: CA created; export it with credenza ca-cert and rebuild every image`.
- `secret add` asks `passphrase: `, then `secret value: `; nothing is
  echoed. It refuses an empty value, a control character and leading or
  trailing spaces. Use `secret add -replace <name>` to overwrite.
- `secret list` prints the names only.
- Later, with `serve` running, `secret add [-replace] <name>` and
  `secret rm <name>` go to `serve`'s admin socket: no passphrase prompt
  (only `secret value: ` for `add`) and no restart. `serve` saves the
  store with the passphrase it was unlocked with and uses the new value
  for the next request, also for tokens already minted. They print
  `credenza: secret <name> saved; live` or `credenza: secret <name> removed; live`.
  Without `serve`, they ask for the passphrase, write the store and print
  `... used at next serve start`. Add a secret before applying a policy
  that names it (R8); remove one only after a policy without it is
  applied. Back up after each change (R13).

Then on the Mac:

```sh
scp $ADMIN@$PI:credenza-ca.pem ~/code/credenza/dist/credenza-ca.pem
openssl x509 -in ~/code/credenza/dist/credenza-ca.pem -noout -subject
```

The certificate is public. Install it in the system trust store of every
agent session image (never through `SSL_CERT_FILE`), or pass it as the CA
file of a single command (for git, `http.sslCAInfo`).

Check: `secret list` prints `claude-oauth` and `github-app`; `openssl`
shows `CN=credenza CA` (`openssl` prints `subject=CN=credenza CA`
or `subject= /CN=credenza CA` depending on its version).

## R8 Policy (Mac, then Pi; then controller as `policyadmin`)

`serve` refuses to start without a valid policy, so the first one is
installed by hand. Write it on the Mac as
`~/code/credenza/dist/policy.json`, starting from the example in
`docs/policy.md` (it covers `example/app`; `ttl` is the lease, `5m`, as
that file explains), then:

```sh
scp ~/code/credenza/dist/policy.json $ADMIN@$PI:policy.json
ssh -t $ADMIN@$PI 'sudo install -o credenza -g credenza -m 0644 policy.json /srv/credenza/policy.json && rm policy.json && sudo -u credenza credenza policy check'
```

`credenza` refuses a policy file not owned by the user running it, or group
or world writable; `install -o credenza -m 0644` sets both.

Check: `policy ok: 1 project(s)`.

Then run R13 (backup).

After R10 and R11, later policies are loaded remotely, by the user
`policyadmin` on the controller, over a second SSH key that can only load a
policy. `launcher` does not hold that key. On controller, as `policyadmin`, with `PI` set:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/id_broker_admin -N '' -C policyadmin@controller
cat ~/.ssh/id_broker_admin.pub
printf 'Host broker-admin\n\tHostName %s\n\tUser credenza\n\tIdentityFile ~/.ssh/id_broker_admin\n\tIdentitiesOnly yes\n' "$PI" >> ~/.ssh/config
```

On the Pi, as admin, append the line printed above to the file R10
writes (R10's `tee` replaces the file: after rerunning R10, append this
line again):

```sh
KEY='ssh-ed25519 AAAA... policyadmin@controller'      # paste the whole line
echo "restrict,from=\"192.0.2.10/32\",command=\"/usr/local/bin/credenza ssh-admin -dir /srv/credenza\" $KEY" | sudo tee -a /home/credenza/.ssh/authorized_keys
```

- `restrict` is required, as in R10: a forced command alone does not stop
  `ssh -L` from forwarding to a Unix socket.
- `credenza ssh-admin` accepts only `policy-load` (a leading `credenza`, or the legacy `broker`, is
  also accepted) with the policy on stdin, at most 256 KiB, and passes it
  to `/srv/credenza/run/admin.sock`. It never reaches `mint`, `renew`,
  `revoke` or the secret verbs, and R10's key never reaches `policy-load`.
- `serve` parses the body with the same strict rules as `policy check`,
  requires every grant's secret in the store and every host inside the
  CA's domains, then replaces `policy.json` atomically (temp file, fsync,
  rename; owner `credenza`, mode 0644). A refused policy prints one line,
  `credenza: invalid policy: <reason>`, exit 1, and keeps the old file; a
  failed write prints `credenza: write policy: ...`, exit 1, and keeps it
  too. The audit log gets a `policy` event with the body's sha256. If
  only that audit write fails (`credenza: write audit log: ...`, exit 1),
  the new policy is already in force: fix the log (R11, R15) and load the
  policy again.
- No restart is needed: the next `mint` and each session's next `renew`
  use the new policy (`docs/policy.md`, "When changes apply").

Check, as `policyadmin` on controller, with `serve` running (R11):

```sh
ssh broker-admin policy-load < /dev/null; echo "exit $?"
ssh broker-admin mint x y < /dev/null; echo "exit $?"
```

The first prints `credenza: invalid policy: ...` and `exit 1`; the second
prints `usage: policy-load < policy.json` and `exit 2`. Then run
`ssh broker-admin policy-load < policy.json` with a valid policy and check
that it exits 0. After a policy change, run
R13 again.

## R9 Audit log append-only (Pi, as admin)

```sh
sudo -u credenza sh -c 'umask 077 && touch /srv/credenza/audit.log'
sudo ls -l /srv/credenza/audit.log
sudo chattr +a /srv/credenza/audit.log && sudo lsattr /srv/credenza/audit.log
```

Check: `ls -l` shows `-rw-------` and owner `credenza`; `lsattr` shows `a`.

- Mode 0600 is required: `serve` refuses an audit log with any group or
  other permission bit
  (`credenza: audit log /srv/credenza/audit.log has mode 0644, want no group or other access`).
- Set `a` before the first `serve`: the flag does not affect descriptors
  already open.
- With `a` set, nobody (root included) can truncate, rename or delete the
  file until root clears the flag, so it only grows; R15 is the only way to
  reclaim the space.
- `serve` reads the flag at start and, when it is missing, prints
  `credenza: warning: audit log /srv/credenza/audit.log is not append-only; run sudo chattr +a on it (runbook R9)`
  before its serving line. It still starts; stop it and run this step.

## R10 Mint key (controller as launcher, then Pi as admin)

On controller, as `launcher`:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/id_broker -N '' -C launcher-mint@controller
cat ~/.ssh/id_broker.pub
```

On the Pi, as admin, with the line printed above in `KEY`:

```sh
KEY='ssh-ed25519 AAAA... launcher-mint@controller'      # paste the whole line
sudo install -d -o credenza -g credenza -m 0700 /home/credenza/.ssh
echo "restrict,from=\"192.0.2.10/32\",command=\"/usr/local/bin/credenza ssh-command -dir /srv/credenza\" $KEY" | sudo tee /home/credenza/.ssh/authorized_keys
sudo chown credenza:credenza /home/credenza/.ssh/authorized_keys && sudo chmod 0600 /home/credenza/.ssh/authorized_keys
```

- `restrict` disables port, agent and X11 forwarding and the pty.
- `from=` accepts the key only from controller's reserved address (CIDR
  allowed). Use the reserved address from R2 if it differs.
- `command=` runs `credenza ssh-command` whatever the client asked; the
  client's command reaches it as `SSH_ORIGINAL_COMMAND`. It accepts only
  `mint <task-id> <project> [<env>...]`, `renew <task-id>` and
  `revoke <task-id>` (a leading `credenza`, or the legacy `broker`, is also accepted), on `/srv/credenza/run/broker.sock`,
  and refuses the admin verbs (`secret-set`, `secret-rm`, `policy-load`)
  with exit 2 before connecting.
- `restrict` is required, not only tidy: a forced command alone does not
  stop `ssh -L` from forwarding to `/srv/credenza/run/admin.sock`.
- The launcher calls `mint` once per session, `renew` every 60 seconds
  while the session's container runs, and `revoke` when it ends. A job
  that needs only one secret, such as a git cache refresh, calls
  `mint <task-id> <project> GH_TOKEN`: env names narrow the mint to those
  grants (at most 3, each one a grant of the project, else exit 4 and an
  audit `deny` with reason `env`), so that mint never issues
  `claude-oauth`. A narrowed mint never widens: `renew` only extends the
  tokens the mint issued.

Admin work and `scp` always use the admin account, never this key.

Check, from controller as `launcher`, before R11:

```sh
ssh -i ~/.ssh/id_broker credenza@$PI revoke r10-check; echo "exit $?"
```

Prints `credenza: broker is locked or not running` and `exit 3`.

## R11 Start after every reboot (Pi)

The `mountpoint` line applies only when the store is on a USB stick. With
the store on the SD card, skip it: it would always abort.

```sh
ssh $ADMIN@$PI
mountpoint -q /srv/credenza || { echo 'USB stick not mounted: do not start'; exit 1; }
df -h /srv/credenza && sudo du -h /srv/credenza/audit.log
sudo lsattr /srv/credenza/audit.log
sudo -iu credenza
tmux new-session -A -s credenza '/usr/local/bin/credenza serve -dir /srv/credenza -listen :8888 -clients 192.0.2.20/32'
```

1. `df -h` must show at least 20% of the stick free; otherwise run R15
   first. A full stick makes every `allow` audit write fail, so the proxy
   answers 503 (`credenza: audit log unavailable`) to every request it would
   otherwise allow, and `mint` exits 1 (fail closed). While it runs,
   `serve` checks once a minute and prints
   `credenza: warning: <n>% free on the filesystem of /srv/credenza/audit.log, below 20%; rotate the audit log (runbook R15)`
   when the space drops below 20%, then once an hour while it stays low.
2. `lsattr` must show `a`; otherwise run R9 first. `serve` also checks it
   and warns (R9).
3. `-clients` is a comma-separated CIDR list with no spaces. An empty list
   is refused. Only the agent host is a client: its sessions reach the
   broker through it. The controller only uses SSH (R8, R10). Use the reserved address from R2
   if it differs. `-max-session` (default `24h`, from `1m` to `720h`)
   bounds how long `renew` can keep a session's tokens alive after its
   `mint`; the session then ends and continues in a new one.
4. Type the passphrase at `passphrase: ` (three attempts).
5. Wait for one line starting `credenza: serving proxy on`, with no
   `credenza: warning:` line before it, for example
   `credenza: serving proxy on [::]:8888, control on /srv/credenza/run/broker.sock, admin on /srv/credenza/run/admin.sock`
   (`0.0.0.0:8888` when IPv6 is off).
6. Detach with `Ctrl-b d`. `-A` reattaches when the session already
   exists.

The broker's later lines (unaudited denial counts, free-space warnings,
upstream errors) go to the same pane, without timestamps; read them with
tmux scrollback (`Ctrl-b [`). The count line reads
`credenza: proxy: <n> unaudited denials (client <a>, not-connect <b>, conn-limit <c>, rate-limited <d>) since <time>`,
at most once a minute:

- `client`: a connection from outside `-clients`, closed at accept with
  no answer (the R3 firewall normally drops these first);
- `not-connect`: a plain HTTP request instead of `CONNECT`;
- `conn-limit`: a connection over 256 open in total or 32 open from one
  address, closed at accept;
- `rate-limited`: a denied request from a listed client over one audited
  deny a second on average (bursts of 200), answered as usual but not
  written to the audit log, so a looping client adds at most about 60 MB
  a day. The first deny of such an episode is written, with reason
  `rate-limited` in place of its own.

Both limits are per address, and every agent on controller shares
controller's address: its 32 connections and its deny rate are for all of
them together. A growing `rate-limited` or `conn-limit` count points at a
client stuck in a loop, or at more agents than 32 connections serve; the
audit log's `deny` lines from it just before its `rate-limited` line name
the reason.

A streamed response is cut when its token is revoked, dropped or changed
by a `renew`, or within 5 seconds after a lease that nobody renewed runs
out. A cut at the end of a lease shows
`httputil: ReverseProxy read error during body copy: context canceled`
in the pane (the task is not named; the audit log's `allow` line is). A
cut by `revoke` writes no line.

If `serve` exits, the pane stays open, marked dead, with the error line
visible (`remain-on-exit`, R4). Common lines:

| Line | Cause |
|---|---|
| `credenza: store not found at /srv/credenza/store.enc (is its filesystem mounted?)` | stick missing; nothing was created |
| `credenza: wrong passphrase or corrupted store` | three wrong passphrases |
| `credenza: policy: ...` | policy error, a secret missing from the store, or a host outside the CA's domains |
| `credenza: audit log ...` | `audit.log` mode or type wrong (R9) |
| `credenza: another credenza serve is running on /srv/credenza/run/broker.sock` | a `serve` already runs (same for `admin.sock`) |

Fix the cause, then press `Ctrl-b :` and type `respawn-pane` to start
`serve` again with the same command.

Stopping: the first `Ctrl-c` in the pane stops cleanly (socket removed,
audit log closed, exit 0). A second `Ctrl-c` during that shutdown kills the
process at once; the next `serve` removes the stale sockets. A restart
drops every token: each open session's next `renew` exits 5, the launcher
stops the session, and it continues in a new one.

Check after logging out and back in:
`sudo -iu credenza tmux has-session -t credenza && echo running`. logind keeps
user processes after logout by default; if the session still dies,
`sudo loginctl enable-linger credenza`.

## R12 Smoke test (controller as launcher, then a session on agent-host)

Run it before R16's rulesets: with them in place, the two branch deletions
below are refused and the branches stay until removed as R16 describes.
Only the agent host is a proxy client (R11), so the proxy checks run inside
an agent session started by your launcher.

Session verbs, on controller as `launcher`:

```sh
ssh -i ~/.ssh/id_broker credenza@$PI mint smoke-1 example/app; echo "exit $?"
ssh -i ~/.ssh/id_broker credenza@$PI renew smoke-1; echo "exit $?"
ssh -i ~/.ssh/id_broker credenza@$PI revoke smoke-1; echo "exit $?"
ssh -i ~/.ssh/id_broker credenza@$PI renew smoke-1; echo "exit $?"
ssh -i ~/.ssh/id_broker credenza@$PI uptime; echo "exit $?"
ssh -i ~/.ssh/id_broker credenza@$PI policy-load < /dev/null; echo "exit $?"
```

Check:

- `mint` exits 0 and prints two lines, `CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-...`
  and `GH_TOKEN=fbt_...`.
- The first `renew` prints nothing and exits 0; `revoke` exits 0; the
  second `renew` prints `credenza: no live tokens` and exits 5.
- `uptime` and `policy-load` print
  `usage: mint <task-id> <project> [<env>...] | renew <task-id> | revoke <task-id>`
  and exit 2: the session key reaches no other verb.

Then start a session for `example/app` with your launcher, note its task
id as `S`, and attach to it on the agent host. In the session's Claude Code, prefix each
line with `!` to run it as a shell command:

```sh
gh api repos/example/app --jq .full_name
git ls-remote https://github.com/example/app.git HEAD
W=$(mktemp -d) && B=smoke-$(date +%Y%m%d%H%M%S)
git clone https://github.com/example/app.git $W/app && cd $W/app
git switch -c $B && git commit --allow-empty -m 'chore: credenza smoke test' && git push -u origin $B
gh pr create --draft --head $B --title 'credenza smoke test' --body 'credenza smoke test; close without merging'
gh pr close $B && git push origin --delete $B
git switch -c $B-wf && mkdir -p .github/workflows
printf 'name: smoke\non: workflow_dispatch\njobs: {}\n' > .github/workflows/credenza-smoke.yml
git add .github/workflows/credenza-smoke.yml && git commit -m 'ci: credenza workflow push check'
git push origin $B-wf; echo "exit $?"
cd - && rm -rf $W
```

Check, the session deliverable path (a draft PR) through the broker:

- Claude Code answers in the session: the `CLAUDE_CODE_OAUTH_TOKEN`
  surrogate works. Its start also leaves the `scope` and `host` denials
  listed in `docs/policy.md`, "Expected denials at startup". They are
  expected: do not widen the policy for them.
- `gh api` prints `example/app`.
- `git ls-remote` prints one hash and `HEAD`.
- The clone, the empty-commit push, `gh pr create --draft` (prints the PR
  URL), `gh pr close` and the branch delete all succeed. `gh pr create` is
  GraphQL plus `git push`; the branch is deleted with git, not with
  `gh pr close --delete-branch`, whose REST `DELETE` the example policy
  denies.

Workflow check:

- The push of `$B-wf` must fail with a non-zero exit and a message like
  ``refusing to allow a Personal Access Token to create or update workflow `.github/workflows/credenza-smoke.yml` ...``.
  This wording comes from community sources only; the GitHub docs tie
  editing workflow files to the separate Workflows permission but do not
  describe `git push`.
- If the push succeeds, the PAT can change CI: delete the branch at once
  (`git push origin --delete $B-wf` from the session), regenerate the PAT
  without the Workflows permission, store it with
  `credenza secret add -replace github-app` on the Pi (live, R7).

Revoke and lease check, with the session still open: on controller as
`launcher`, `ssh -i ~/.ssh/id_broker credenza@$PI revoke $S; echo "exit $?"`,
then in the session `! gh api repos/example/app --jq .full_name; echo "exit $?"`.

- `revoke` exits 0.
- `gh api` then fails with `Forbidden` and a non-zero exit. The revoked
  surrogate is refused at `CONNECT api.github.com`, before any request is
  read, so the audit line has reason `host` (no `task`), not `token`
  (seen 2026-10-31 and 2026-11-04). A request whose `CONNECT` is already
  open, such as a `POST /v1/messages` right after the revoke, is denied
  with reason `token`.
- Within about a minute the launcher's next `renew` exits 5, it stops the
  container and the session ends.
- On the Pi, `sudo tail -n 40 /srv/credenza/audit.log` shows `mint`,
  `renew`, `proxy` and `revoke` lines with secret names and no values, and
  the `deny` line of the `gh api` above (reason `host`), besides any expected startup
  denials of `claude`. `no-token` deny lines before git requests are
  normal (git first asks without credentials and gets 401).

The `git` and `claude` lines also confirm that GnuTLS (git) and Claude Code
accept the name-constrained CA. If one rejects it, run
`credenza ca init -force -unconstrained`, restart `serve`, export the new
certificate with `credenza ca-cert`, reinstall it and rebuild the images. An
unconstrained CA lets a stolen CA key impersonate any site to every agent
host, so prefer fixing the client.

## R13 Backup of the encrypted store (Mac)

After R8, and after every `secret add`, `secret rm`, `passwd`, policy change or
`ca init`:

```sh
ssh -t $ADMIN@$PI 'sudo install -o '"$ADMIN"' -m 0600 /srv/credenza/store.enc ~/store.enc && sudo install -o '"$ADMIN"' -m 0600 /srv/credenza/policy.json ~/policy.json'
mkdir -p ~/backups/credenza && cd ~/backups/credenza && TS=$(date +%Y%m%d-%H%M%S)
scp $ADMIN@$PI:store.enc store-$TS.enc && scp $ADMIN@$PI:policy.json policy-$TS.json
ssh $ADMIN@$PI 'sha256sum store.enc && rm store.enc policy.json'
shasum -a 256 store-$TS.enc
```

Check: the two hashes match. The store is encrypted with the passphrase;
without the passphrase the backup is useless, so keep the passphrase
somewhere else.

Restore (Pi, as admin, with `serve` stopped and the stick mounted, after
copying the backups to `~/store.enc` and `~/policy.json` with `scp`):

```sh
sudo install -o credenza -g credenza -m 0600 ~/store.enc /srv/credenza/store.enc && rm ~/store.enc
sudo install -o credenza -g credenza -m 0644 ~/policy.json /srv/credenza/policy.json && rm ~/policy.json
```

On a new stick, run R5 and R9 first.

Then start as in R11.

## R14 Upgrade the binary

1. On the Mac, build and copy as in R6, up to and including the `scp`.
2. On the Pi, as admin, attach with `sudo -iu credenza tmux attach -t credenza`,
   press `Ctrl-c` once (the pane stays, marked dead), then detach with
   `Ctrl-b d`.
3. Still as admin, with the new `SHA256SUMS` line in `SUM` as in R6:
   `printf '%s\n' "$SUM" | sha256sum -c && sudo install -o root -g root -m 0755 credenza-linux-armv7 /usr/local/bin/credenza && rm credenza-linux-armv7 && credenza version`.
4. Attach again with `sudo -iu credenza tmux attach -t credenza`, press
   `Ctrl-b :`, type `respawn-pane`, type the passphrase as in R11, and
   detach with `Ctrl-b d`. Only when `-clients` (or another `serve` flag)
   stays the same: `respawn-pane` reruns the pane's old command. To change
   a flag, kill the session instead
   (`sudo -iu credenza tmux kill-session -t credenza`) and start it as in R11
   with the new command (`new-session`).

Check: `sha256sum -c` prints `credenza-linux-armv7: OK`; `credenza version` prints the new
version; the pane shows `credenza: serving proxy on ...`. A restart
invalidates every token: open sessions stop at their next `renew` (exit 5)
and continue in new ones. Upgrade when no session is open, or close them
first.

## R15 Audit log space and rotation (Pi, as admin, in one SSH session)

When `df -h /srv/credenza` shows less than 20% free or `serve` prints the
free-space warning (R11), and at least once a month. Rotation stops the credenza: open sessions stop at their next `renew` and continue in new ones afterwards.

```sh
df -h /srv/credenza && sudo du -h /srv/credenza/audit.log
sudo -iu credenza tmux send-keys -t credenza C-c        # stop serve; the pane stays dead
sudo -iu credenza tmux list-panes -t credenza -F '#{pane_dead}'
TS=$(date +%Y%m%d-%H%M%S)
sudo chattr -a /srv/credenza/audit.log
sudo mv /srv/credenza/audit.log /srv/credenza/audit-$TS.log
sudo install -o "$USER" -m 0600 /srv/credenza/audit-$TS.log ~/audit-$TS.log
sudo sha256sum /srv/credenza/audit-$TS.log ~/audit-$TS.log
echo $TS
```

`list-panes` must print `1` (the pane is dead) before `chattr -a`; if it
prints `0`, wait a second and run it again. Never clear `a` while `serve`
runs: the log would stop being append-only for an open descriptor.

On the Mac, with `TS` set to the value printed above:

```sh
scp $ADMIN@$PI:audit-$TS.log ~/backups/credenza/ && shasum -a 256 ~/backups/credenza/audit-$TS.log
```

When the three hashes match:

```sh
ssh -t $ADMIN@$PI "rm ~/audit-$TS.log && sudo rm /srv/credenza/audit-$TS.log"
```

Then run R9 again (new empty log, mode 0600, `chattr +a`) and restart as in
R11 (`respawn-pane`).

Check: `sudo lsattr /srv/credenza/audit.log` shows `a`; `df -h /srv/credenza` shows
the space back; the first `mint` after the restart appears in the new log.

## R16 Protect the branches and tags (GitHub, once per project)

The broker cannot stop a merge through GraphQL in 1.0.0: every GraphQL
request is `POST /graphql`, including `mergePullRequest`,
`enablePullRequestAutoMerge`, `mergeBranch` and `createCommitOnBranch`, and
the broker does not read request bodies. A temporary token can therefore
merge the agent's own draft PR or write to `main` unless GitHub refuses it.

In the repository settings of `example/app`, add a branch protection rule
(or a ruleset) for the default branch with:

- "Require a pull request before merging";
- "Required number of approvals before merging" at least 1;
- "Do not allow bypassing the above settings" (by default, admins bypass
  branch protection, and the PAT acts as its owner).

Consequence: pull request authors cannot approve their own pull requests,
and the PAT's owner is the author of every agent PR. If that owner is the
user, merging an agent PR needs a second account's approval. The cleaner
setup is a separate GitHub account (a machine user with write access to the
repo) that owns the PAT in the store, so the user reviews and merges agent
PRs normally.

A temporary token can also delete or force-push any branch or tag the
PAT can write: `git push origin --delete` and `git push --force` are plain
`POST .../git-receive-pack` requests, which the policy must allow for
pushes. In Settings, Rules, Rulesets of the same repository add:

1. "New branch ruleset": name `no-delete-no-force-push`; enforcement status
   Active (the form starts at Disabled); under "Target branches", "Add
   target", "Include all branches"; rules "Restrict deletions" and "Block
   force pushes". Leave "Restrict creations" off, so agents can still push
   new branches.
2. "New tag ruleset": the same name, status and two rules, with a target
   that includes every tag.

Bypass list: leave it empty while the PAT in the store belongs to the
user. A token "has the same capabilities to access resources and perform
actions on those resources that the owner of the token has", so a bypass
for the user would also be a bypass for every agent. With a machine
account owning the PAT, the user may add their own account.

Consequence: nobody outside the bypass list force-pushes, so an agent
cannot rebase its own PR branch and push it again; it pushes new commits
or a new branch instead. Nobody outside the bypass list deletes a branch
or tag, by `git push --delete`, by the web interface, or by GitHub's
automatic deletion of head branches after a merge ("Branch protection
rules and repository rules can also prevent branches being automatically
deleted").
With an empty bypass list, set the branch ruleset to Disabled, delete the
stale branches, and set it back to Active.

Check:

- The repository's branch settings page lists the rule for the default
  branch with all three settings on.
- The rulesets page lists both rulesets as Active, one targeting all
  branches and one all tags, each with "Restrict deletions" and "Block
  force pushes", and an empty bypass list (or only the user, with a
  machine account owning the PAT).
- In a session opened as in R12, in its clone:
  `git push origin HEAD:refs/heads/r16-check` succeeds,
  and then `git push origin --delete r16-check; echo "exit $?"` prints a
  non-zero exit. Remove `r16-check` as
  described above.

## Sources

Each row quotes the source behind a step.

| Step | Claim | Source |
|---|---|---|
| R1 | Lite 32-bit is Debian trixie with no desktop | https://downloads.raspberrypi.com/os_list_imagingutility_v4.json: "A port of Debian Trixie with no desktop environment" |
| R1 | the SD card stays the boot device | https://raw.githubusercontent.com/raspberrypi/documentation/master/documentation/asciidoc/computers/raspberry-pi/bootmodes.adoc: "The SD card must be present in the Raspberry Pi for it to boot." |
| R2 | no filtering inside one subnet | https://docs.opnsense.org/manual/how-tos/vlan_and_lagg.html: "Only routed traffic can be filtered by a central firewall." |
| R3 | `auto` swap writes to a file | https://github.com/raspberrypi/rpi-swap/blob/main/man/man5/swap.conf.5: "auto: Automatically selects the most appropriate mechanism. At present, this defaults to "zram+file"" |
| R3 | `none` removes the swap file | same page: "none: No swap is configured. Any existing swap file will be removed to free up disk space." |
| R4 | `--disabled-login` sets nologin | https://manpages.debian.org/trixie/adduser/adduser.8.en.html: "--disabled-login will additionally set the shell to /usr/sbin/nologin." |
| R4, R10 | forced command runs through the login shell | https://man.openbsd.org/sshd.8: "All commands are run under the user's login shell as specified in the system password database." |
| R4, R11 | `remain-on-exit` | https://man.openbsd.org/tmux.1: "A pane with this flag set is not destroyed when the program running in it exits." |
| R5 | `LABEL=` in fstab | https://man7.org/linux/man-pages/man5/fstab.5.html: "LABEL=<label> or UUID=<uuid> may be given instead of a device name." |
| R5 | `noexec` | https://man7.org/linux/man-pages/man8/mount.8.html: "Do not permit direct execution of any binaries on the mounted filesystem." |
| R3 | nftables input chain with policy drop | https://wiki.nftables.org/wiki-nftables/index.php/Simple_ruleset_for_a_workstation: "type filter hook input priority 0; policy drop;" and "iif lo accept" and "ct state established,related accept" |
| R3 | IPv6 needs neighbour discovery | same page: "# accept neighbour discovery otherwise IPv6 connectivity breaks" and "icmpv6 type { nd-neighbor-solicit, nd-router-advert, nd-neighbor-advert } accept" |
| R3 | anonymous sets of addresses | https://www.netfilter.org/projects/nftables/manpage.html: "nft add rule filter input ip saddr { 10.0.0.0/8, 192.168.0.0/16 } tcp dport { 22, 443 } accept" |
| R3 | `nft -c` | same page: "Check commands validity without actually applying the changes." |
| R3 | `drop` policy | same page: "Supported policy values are accept (which is the default) or drop." |
| R3 | `/etc/nftables.conf` and the service | https://wiki.debian.org/nftables: "By default, rules are located in /etc/nftables.conf." and "# systemctl enable nftables.service" |
| R6 | `sha256sum -c` | https://manpages.debian.org/trixie/coreutils/sha256sum.1.en.html: "-c, --check read checksums from the FILEs and check them" |
| R6 | `shasum` needs `-a 256` | https://perldoc.perl.org/shasum: "-a, --algorithm 1 (default), 224, 256, ..." |
| R6 | go1.27.3 minimum | https://go.dev/doc/devel/release: "go1.27.3 (released 2026-10-19) includes security fixes to the crypto/x509 package." |
| R6 | `GOARM=7` | https://go.dev/doc/install/source: "GOARM=7: use VFPv3; usually Cortex-A cores" |
| R9 | `a` does not affect open descriptors | https://man7.org/linux/man-pages/man1/chattr.1.html: "Setting 'a' and 'i' attributes will not affect the ability to write to already existing file descriptors." |
| R9 | append-only files cannot be deleted | https://man7.org/linux/man-pages/man2/unlink.2.html: "EPERM The file to be unlinked is marked immutable or append-only." |
| R10 | `restrict` | https://man.openbsd.org/sshd.8: "Enable all restrictions, i.e. disable port, agent and X11 forwarding, as well as disabling PTY allocation and execution of ~/.ssh/rc." |
| R10 | `from=` with CIDR | same page: "a from stanza may match IP addresses using CIDR address/masklen notation." |
| R10 | `command=` | same page: "The command originally supplied by the client is available in the SSH_ORIGINAL_COMMAND environment variable." |
| R11 | `new-session -A` | https://man.openbsd.org/tmux.1: "The -A flag makes new-session behave like attach-session if session-name already exists;" |
| R11 | logind keeps processes | https://manpages.debian.org/trixie/systemd/logind.conf.5.en.html: KillUserProcesses "Defaults to "no"" |
| R12 | OAuth token variable | https://code.claude.com/docs/en/authentication: "`CLAUDE_CODE_OAUTH_TOKEN` environment variable. A long-lived OAuth token generated by `claude setup-token`." |
| R12 | proxy variables | https://code.claude.com/docs/en/network-config: "Claude Code uses the first one that's set in the order `https_proxy`, `HTTPS_PROXY`, `http_proxy`, `HTTP_PROXY`." |
| R12 | `gh pr create` is GraphQL | https://github.com/cli/cli/blob/9490d204a2ba95434153dedce99898ce9f281426/api/queries_pr.go#L493: "createPullRequest(input: $input) {" |
| R12 | `--delete-branch` uses REST `DELETE` | https://github.com/cli/cli/blob/9490d204a2ba95434153dedce99898ce9f281426/api/queries_pr.go#L877: "client.REST(repo.RepoHost(), "DELETE", path.String(), nil, nil)" |
| R12 | Workflows permission | https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps: "Grants the ability to add and update GitHub Actions workflow files." |
| R16 | GraphQL merges | https://docs.github.com/en/graphql/reference/pulls#mutation-mergepullrequest: "Merge a pull request." |
| R16 | admins bypass by default | https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#do-not-allow-bypassing-the-above-settings: "By default, the restrictions of a branch protection rule do not apply to people with admin permissions to the repository" |
| R16 | rulesets cover branches and tags | https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets: "Rulesets help you to control how people can interact with branches and tags in a repository." |
| R16 | branch and tag rulesets | https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository: "To create a ruleset targeting branches, click New branch ruleset. Alternatively, to create a ruleset targeting tags, click New tag ruleset." |
| R16 | the form starts at Disabled | same page: "Optionally, to change the default enforcement status, click Disabled and select an enforcement status." and "Disabled: your ruleset will not be enforced." |
| R16 | "Include all branches" | https://docs.github.com/en/copilot/how-tos/copilot-on-github/set-up-copilot/configure-code-review: "click Add target and choose one of the options" and "Include default branch or Include all branches." |
| R16 | Restrict deletions | https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets: "If selected, only users with bypass permissions can delete branches or tags whose name matches the pattern you specify." |
| R16 | Block force pushes | same page: "You can prevent users from force pushing to the targeted branches or tags." |
| R16 | Restrict creations is opt-in | same page: "If selected, only users with bypass permissions can create branches or tags whose name matches the pattern you specify." |
| R16 | a PAT acts as its owner | https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens: "A token has the same capabilities to access resources and perform actions on those resources that the owner of the token has" |
| R16 | rules stop automatic branch deletion | https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-the-automatic-deletion-of-branches: "Branch protection rules and repository rules can also prevent branches being automatically deleted." |
