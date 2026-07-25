# Beweiskette

Digital evidence chain of custody — client-side web application.

## Constraints
- Zero runtime dependencies. Vanilla JS + CSS only. Vite is dev-only tooling.
- All cryptographic operations happen client-side. Files never leave the browser.
- No server, no backend, no API calls, no analytics, no tracking.
- Hash chain must remain intact across all operations. Append-only.
- `npm test` uses Node's built-in runner. No test framework dependency.
- Deploys as static files to Cloudflare Pages.

## Architecture
- src/crypto.js: Web Crypto API (SHA-256) wrappers
- src/canonical.js: Canonical JSON encoder — the exact bytes that get hashed.
  Self-contained on purpose: report.js embeds its source verbatim.
- src/chain.js: Chain construction, validation, verification (format v2)
- src/anchor.js: Head receipts and anchor checking
- src/store.js: IndexedDB persistence (raw API, no library)
- src/exif.js: Minimal JPEG EXIF parser (DateTime, GPS, Camera)
- src/report.js: CSV and self-contained HTML report generation
- src/ui/: Four view modules (register, chain-view, verify, export)
- src/main.js: App shell, tab routing, initialization

## Security
- Client-side only. No network request after page load.
- All interpolation goes through the `html` tagged template in utils.js, which
  escapes by default. Never assign an untagged template literal to innerHTML.
  sanitizeText() is input normalization, NOT HTML escaping.
- Canonical encoding must stay injective: canonical.js throws on values it
  cannot represent unambiguously. Never make it coerce instead.
- Chain ordering comes from `seq`, never from wall-clock timestamps.
- Strict CSP in public/_headers: no inline scripts, no inline styles, no
  unsafe-eval. Do not add a style="" attribute or an eval to the app.
- The exported report must inline canonical.js's source rather than a copy.
- What the chain does and does not prove: docs/THREAT_MODEL.md. Keep README
  claims matching the code.

## Relationship to Zeitkette
- Same hash chain concept, different domain (evidence vs. work hours)
- Zeitkette: Python CLI, JSONL file, git-anchored
- Beweiskette: Browser app, IndexedDB, exportable JSON

## Owner context
Built by Bellamer as an open-source portfolio piece
in the AI trust / cybersecurity / legal-tech space. MIT licensed.
