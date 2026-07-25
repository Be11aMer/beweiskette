# Security Policy

## Status

Beweiskette is a **reference implementation**, published so it can be read,
forked and built on. It is not a maintained product and there is no support
commitment. Fixes land when the author has time, or when someone contributes
them.

If you intend to rely on it, fork it and take ownership. That is the intended
use.

## Scope

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) first — it sets out what the
tool does and does not claim to do. Several properties people expect from a
chain-of-custody tool are explicitly *not* provided, and those are documented
limitations rather than vulnerabilities:

- A chain with truncated tail entries verifying as intact (use an anchor
  receipt — this is what they are for).
- A wholly fabricated chain verifying as intact (no signatures; use an anchor).
- Back-dated timestamps (the clock belongs to whoever makes the records).
- Loss of the chain to browser storage eviction (export regularly).

## In scope

Anything that breaks a property the tool *does* claim:

- A way to alter, reorder or remove an entry from a chain and still have it
  verify.
- Two structurally different entries producing the same `entry_hash`.
- Script execution from an imported chain, an exported report, or a filename —
  this is the highest-severity class here, since it grants IndexedDB write
  access plus the page's own hashing code.
- A disagreement between the app's verifier and the one embedded in an
  exported report.
- Any network request made by the application.
- A chain that fails verification despite never having been modified.

## Reporting

Open a [GitHub issue](https://github.com/Be11aMer/beweiskette/issues).

For something with real impact, use GitHub's [private vulnerability
reporting](https://github.com/Be11aMer/beweiskette/security/advisories/new)
rather than a public issue.

Please include what you expected, what happened, and enough to reproduce it —
a minimal chain JSON is ideal. No response time is promised.

## For forks

If you deploy this for real work:

- Serve over HTTPS. An attacker who can modify the delivered JavaScript
  controls everything, and the Web Crypto API requires a secure context.
- Keep the CSP in `public/_headers` (or the equivalent for your host) and
  verify it is actually being sent.
- Run `npm test` before deploying. The suite covers the injection vectors, the
  canonicalization collisions, and app/report verifier parity — all of which
  are the kind of thing that breaks silently.
- Anchor your chains. An unanchored chain proves far less than it appears to.
