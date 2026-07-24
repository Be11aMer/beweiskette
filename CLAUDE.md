# Beweiskette

Digital evidence chain of custody — client-side web application.

## Constraints
- Zero runtime dependencies. Vanilla JS + CSS only. Vite is dev-only tooling.
- All cryptographic operations happen client-side. Files never leave the browser.
- No server, no backend, no API calls, no analytics, no tracking.
- Hash chain must remain intact across all operations. Append-only.
- Deploys as static files to Cloudflare Pages.

## Architecture
- src/crypto.js: Web Crypto API (SHA-256) wrappers
- src/chain.js: Hash chain logic (mirrors Zeitkette pattern)
- src/store.js: IndexedDB persistence (raw API, no library)
- src/exif.js: Minimal JPEG EXIF parser (DateTime, GPS, Camera)
- src/ui/: Four view modules (register, chain-view, verify, export)
- src/main.js: App shell, tab routing, initialization

## Security
- Client-side only — zero-trust architecture
- Constant-time hash comparison (no timing side-channels)
- All user input rendered via textContent (no innerHTML XSS vectors)
- CSV export escapes formula injection characters (=, +, -, @)
- Deterministic JSON serialization (sorted keys, no whitespace)

## Relationship to Zeitkette
- Same hash chain concept, different domain (evidence vs. work hours)
- Zeitkette: Python CLI, JSONL file, git-anchored
- Beweiskette: Browser app, IndexedDB, exportable JSON

## Owner context
Built by Bellamer as an open-source portfolio piece
in the AI trust / cybersecurity / legal-tech space. MIT licensed.
