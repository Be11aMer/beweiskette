# Beweiskette

Cryptographic chain of custody for digital evidence — entirely client-side.

> **Status: reference implementation.** Published to be read, forked and built
> on. Not a maintained product, no support commitment. If you intend to rely
> on it, fork it and take ownership — that is the intended use.

## What This Is

Beweiskette (*German: "chain of evidence"*) is a zero-dependency web
application that builds a tamper-evident record of digital files. Every file
you register is hashed, described, and linked to the previous record in a hash
chain. Alter or reorder any past record and verification fails, at the exact
entry.

**Your files never leave the browser.** All SHA-256 hashing happens
client-side using the Web Crypto API. There is no backend, no analytics, no
telemetry, and no network request after the page loads.

MIT licensed. Fork it, extend it, build on it.

## What It Proves — And What It Doesn't

This section is the important one. Most of the value in a chain-of-custody
tool comes from knowing exactly where its guarantees stop.

**It proves**, for a chain you already hold: that no record was altered, that
none was reordered, that none was removed from the middle, and that the
records all belong to the same chain. Verification recomputes every hash
rather than comparing stored values.

**It does not prove *when*.** Timestamps come from the registering machine's
clock, which the person making the records controls. A chain dated last year
is indistinguishable from one built this morning on a back-dated laptop.

**It does not prove *completeness*.** Delete the last three entries from an
exported chain and the rest still verifies as INTACT — nothing inside the file
commits to how long it was supposed to be.

**It does not prove *authenticity*.** There are no signatures, and the
construction is published. Anyone can generate a complete, internally valid
chain with any contents. "CHAIN INTACT" means *this file is internally
consistent*, not *this file is genuine*.

**It does not prove the records are *true*.** Custodian, case reference and
notes are free text, asserted by whoever typed them.

The first three gaps are closed by **anchoring**: publish a short head receipt
somewhere you do not control the timeline of, and the chain becomes bound to a
moment you cannot silently revise. See [docs/ANCHORING.md](docs/ANCHORING.md).
The full analysis is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md); read it
before relying on this for anything that matters.

## Who This Is For

- **Forensic investigators** documenting evidence handling
- **Journalists** establishing when they received source material
- **Lawyers** maintaining file integrity for case documentation
- **Security researchers** timestamping vulnerability discoveries

In each case the tool provides a defensible internal record. Pair it with a
published anchor if the timing needs to hold up against someone who disputes it.

## How It Works

1. **Register** — Drop a file in. The browser computes its SHA-256, extracts
   EXIF metadata (JPEG only), and records the custody information you provide.

2. **Chain** — Each entry commits, via SHA-256 over a canonical encoding, to
   its own contents, its position (`seq`), its chain identity (`chain_id`), and
   the previous entry's hash. The first entry links to `GENESIS`.

3. **Anchor** — Copy the head receipt and publish it. This is what converts
   "internally consistent" into "existed by a specific moment".

4. **Verify** — Import a chain and every hash is recomputed and every link
   checked. Paste a published receipt to additionally detect entries removed
   from the end.

5. **Export** — JSON (the record), CSV (a lossy summary, **not** verifiable —
   it omits metadata), or a self-contained HTML report that carries its own
   verification code and runs offline.

## Chain Format v2

Entries are hashed over a canonical JSON encoding — keys sorted by Unicode
code point, no insignificant whitespace:

```json
{
  "schema_version": 2,
  "chain_id": "3f2a1b8c-4d5e-4f60-8a1b-2c3d4e5f6071",
  "seq": 0,
  "id": "…",
  "timestamp_registered": "2026-07-24T09:31:04.117Z",
  "evidence":  { "file_hash": "…", "file_name": "…", "file_size": 204800, … },
  "metadata":  { "camera_make": "Canon", "gps_lat": "52.520008", … },
  "custody":   { "custodian": "…", "case_reference": "…", "notes": "…" },
  "prev_hash": "GENESIS"
}
```

`entry_hash` is the digest of exactly those fields and is not part of its own
preimage. The encoder **throws** rather than guess at any value it cannot
represent unambiguously — a canonicalizer that silently coerces is a collision
generator.

> **v1 chains are not readable by this version.** `schema_version`, `seq` and
> `chain_id` are covered by the digest, so v1 entries cannot be upgraded —
> recomputing their hashes under v2 rules would be indistinguishable from
> forging them. Existing v1 entries remain in the store and can be exported.

## Security Properties

| Property | Status |
|---|---|
| **Client-side only** | Files never leave the browser. No network request after load. Verifiable — there is no network code. |
| **Content integrity** | Any change to any entry breaks verification at that entry. Hashes are recomputed, not compared. |
| **Ordering integrity** | `seq` is covered by the digest; reordering and mid-chain deletion are detected directly. |
| **Chain identity** | `chain_id` prevents splicing entries from two chains into one file. |
| **Injective encoding** | The canonical encoder rejects values it cannot represent unambiguously, rather than collapsing them onto each other. |
| **Output escaping** | All values from imported chains are HTML-escaped by default via an auto-escaping template. |
| **CSV formula injection** | Fields beginning `=`, `+`, `-`, `@` are neutralized; all fields are quoted. |
| **Single verifier** | The exported report inlines the app's canonicalizer rather than a copy, so the two cannot disagree. |
| **Strict CSP** | `default-src 'none'`, no inline scripts, no inline styles, no `unsafe-eval`. See `public/_headers`. |
| **Tail truncation** | **Not** detected without a published anchor receipt. |
| **Whole-chain forgery** | **Not** detected. No signatures. Use an anchor. |
| **Wall-clock time** | **Not** established. The clock belongs to whoever makes the records. |

On constant-time comparison: `constantTimeEqual` is used consistently, but it
should not be read as a security property here. There is no secret — both
operands are already public — and JavaScript cannot guarantee constant-time
execution anyway. It is hygiene.

## Architecture

```
src/
├── main.js        App shell, tab routing, storage-durability check
├── crypto.js      Web Crypto API (SHA-256) wrappers
├── canonical.js   Canonical JSON encoder — the exact bytes that get hashed
├── chain.js       Chain construction, validation, verification
├── anchor.js      Head receipts and anchor checking
├── store.js       IndexedDB persistence (raw API)
├── exif.js        Minimal JPEG EXIF parser
├── report.js      CSV and self-contained HTML report generation
├── utils.js       Formatting, HTML escaping
└── ui/            register · chain-view · verify · export
```

`canonical.js` is deliberately self-contained: `report.js` embeds its source
verbatim so the offline report and the app cannot drift apart.

**Zero runtime dependencies.** Vanilla JavaScript, vanilla CSS. Vite is a dev
server and build tool only; the tests use Node's built-in runner. Production
output is plain static files.

## Development

```bash
git clone https://github.com/Be11aMer/beweiskette.git
cd beweiskette
npm install
npm run dev      # http://localhost:5173
npm test         # node:test — no test framework dependency
npm run build    # static output in dist/
```

Run `npm test` before deploying. The suite covers the injection vectors, the
canonicalization collisions, and app/report verifier parity — the things that
break silently.

### Deploy

```bash
npm run deploy   # Cloudflare Pages, via wrangler.jsonc
```

`public/_headers` carries the CSP and related headers. If you deploy somewhere
else, port it — and confirm the headers are actually being sent.

## Relationship to Zeitkette

Beweiskette is the evidence-chain counterpart to
[Zeitkette](https://github.com/Be11aMer/zeitkette), a CLI tool for
cryptographically verifiable work hour logging.

| | Zeitkette | Beweiskette |
|---|---|---|
| **Domain** | Work hours | Digital evidence |
| **Interface** | Python CLI | Web app |
| **Storage** | JSONL file + git | IndexedDB + JSON export |
| **Anchoring** | Git commits | Published head receipts |

The two share a canonical encoding. `test/vectors/canonical.json` is the shared
fixture: 13 vectors covering the cases where implementations actually diverge
(non-ASCII values, non-ASCII keys, astral-plane key ordering, escaping). Any
implementation claiming compatibility must reproduce every `canonical` string
and `sha256` exactly.

The Python side must use:

```python
json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
```

`ensure_ascii=False` is required and is **not** the Python default. With the
default, Python escapes non-ASCII as `\uXXXX` while JavaScript emits raw UTF-8,
and a custodian named "Müller" hashes differently in the two tools.

## Legal Note

Beweiskette creates **evidence of integrity**, not legal certainty. A
hash-chained log demonstrates that records were created in sequence and have
not been modified since. It does not establish when they were created, that
they are complete, or that their contents are true.

- This tool does not constitute legal advice.
- Evidentiary value depends on jurisdiction, context, and the specifics of any
  proceeding.
- Consult a qualified legal professional for specific situations.

## Contributing

Issues and pull requests are welcome, though see the status note at the top —
responses may be slow. Security reports: [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
