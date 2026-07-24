# Beweiskette

Cryptographic chain of custody for digital evidence — entirely client-side.

## What This Is

Beweiskette (*German: "chain of evidence"*) is a zero-dependency web
application that creates a cryptographically verifiable chain of custody
for digital files. Every piece of evidence you register is hashed,
timestamped, and linked to the previous entry in a tamper-evident chain.
Modify any historical entry and the chain breaks — detectably, instantly.

**Your files never leave the browser.** All SHA-256 hashing happens
client-side using the Web Crypto API. No data is sent to any server.
There is no backend, no analytics, no tracking.

This is an open-source reference implementation under the MIT license.
Fork it, extend it, build on it.

## Who This Is For

- **Forensic investigators** documenting evidence handling
- **Journalists** establishing when they received source material
- **Lawyers** maintaining file integrity for case documentation
- **Security researchers** timestamping vulnerability discoveries
- **Anyone** who needs to prove a file existed in a specific state at a specific time

## How It Works

1. **Register**: Drop a file into the app. The browser computes its
   SHA-256 hash, extracts EXIF metadata (for JPEG images), and records
   custody information you provide (who handled it, case reference, notes).

2. **Chain**: Each entry is linked to the previous one via a hash chain.
   Entry N's `prev_hash` = Entry N-1's `entry_hash`. The first entry
   uses `prev_hash = "GENESIS"`. Any modification to any past entry
   breaks the chain from that point forward.

3. **Verify**: Import a chain and the app recomputes every hash,
   validates every link. The result is unambiguous: CHAIN INTACT or
   CHAIN BROKEN at entry N.

4. **Export**: Download your chain as JSON, CSV, or a self-contained
   HTML report that includes embedded verification logic — open it in
   any browser and click "Verify" to validate the chain independently.

## Architecture

```
src/
├── main.js          App shell, tab routing
├── crypto.js        Web Crypto API (SHA-256) wrappers
├── chain.js         Hash chain logic
├── store.js         IndexedDB persistence (raw API)
├── exif.js          Minimal JPEG EXIF parser
├── utils.js         Serialization, formatting, sanitization
└── ui/
    ├── register.js  Evidence registration view
    ├── chain-view.js Chain timeline view
    ├── verify.js    Verification view
    └── export.js    Export view
```

**Zero runtime dependencies.** Vanilla JavaScript, vanilla CSS. Vite is
used only as a dev server and build tool — the production output is plain
static files.

## Security Properties

| Property | Implementation |
|---|---|
| **Client-side only** | Files never leave the browser. Web Crypto API for all hashing. |
| **Constant-time comparison** | Hash verification avoids timing side-channels. |
| **No innerHTML** | All user input rendered via `textContent` — no XSS vectors. |
| **CSV formula injection** | Export escapes fields starting with `=`, `+`, `-`, `@`. |
| **Deterministic hashing** | Keys are recursively sorted before JSON serialization. |
| **Restrictive storage** | IndexedDB with same-origin isolation. |

## Development

```bash
git clone https://github.com/Bellamer/beweiskette.git
cd beweiskette
npm install
npm run dev
```

Open `http://localhost:5173` in your browser.

### Build for Production

```bash
npm run build
```

Output is in `dist/` — static files only.

### Deploy to Cloudflare Pages

```bash
npm run deploy
```

Uses `wrangler.jsonc` for SPA configuration.

## Relationship to Zeitkette

Beweiskette is the evidence-chain counterpart to
[Zeitkette](https://github.com/Bellamer/zeitkette), a CLI tool for
cryptographically verifiable work hour logging. Same hash chain concept,
different domain:

| | Zeitkette | Beweiskette |
|---|---|---|
| **Domain** | Work hours | Digital evidence |
| **Interface** | Python CLI | Web app |
| **Storage** | JSONL file + git | IndexedDB + JSON export |
| **Hashing** | Python hashlib | Web Crypto API |

## Legal Note

Beweiskette creates **evidence of integrity**, not legal certainty.
A hash-chained evidence log demonstrates that records were created in
sequence and have not been modified. However:

- This tool does not constitute legal advice.
- Evidentiary value depends on jurisdiction, context, and the specifics
  of any proceeding.
- Consult a qualified legal professional for specific situations.

## License

MIT
