# Security policy

credenza holds real credentials, so security reports are welcome and
handled first.

## Reporting a vulnerability

Do not open a public issue. Report it privately through GitHub:
**Security**, **Report a vulnerability** on
https://github.com/dantoac/credenza/security/advisories/new.

Include the version (`credenza version`), the platform, and the steps or
a test that shows the problem. You should get an answer within a week.

## Supported versions

Only the latest release gets fixes.

## Scope

In scope: anything that lets an agent or a network client obtain a real
secret, use a surrogate token outside its policy scope or lease, reach the
admin socket through the session key, write to the policy without the
admin key, or make credenza forward a request it should deny.

Out of scope: what a valid token does inside its scope (see
[docs/spec.md](docs/spec.md), "Security model"), and attacks that need
root or the service user on the credenza host.
