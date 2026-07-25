/**
 * Export artifact generation: CSV summary and the self-contained HTML report.
 *
 * Kept free of DOM, IndexedDB and app-shell imports so it stays a pure
 * function of the entry list — the HTML report is the artifact most likely to
 * be handed to a third party, so it needs to be directly testable.
 */

import { escapeCSVField, truncateHash, html, raw } from './utils.js';
import { sortedStringify } from './canonical.js';
import { HASHED_FIELDS_BY_VERSION, SUPPORTED_VERSIONS, GENESIS } from './chain.js';

/**
 * Sanity-check the encoder source about to be embedded.
 *
 * Deliberately does NOT execute the source. Evaluating it would require
 * `unsafe-eval` in the app's Content-Security-Policy, and weakening the CSP of
 * the whole application to self-check one export path is a bad trade. The real
 * behavioural parity check — reconstructing this source and comparing its
 * output to the app's, digest for digest — lives in test/parity.test.js, where
 * there is no CSP to undermine.
 *
 * What is left here are the two checks that can be made structurally, and that
 * would produce a corrupt artifact rather than a caught error.
 */
function checkEncoderSource(source) {
  if (source.includes('</script')) {
    throw new Error('The canonical encoder source contains a script-closing sequence and cannot be embedded safely.');
  }
  if (!/^function\b/.test(source.trim())) {
    throw new Error('The canonical encoder source is not a complete function declaration; refusing to embed it.');
  }
  return source;
}

/**
 * The verification logic embedded in every exported report.
 *
 * sortedStringify is inlined from its single definition via Function.toString()
 * rather than transcribed. The previous report carried a hand-minified copy
 * that had already drifted — it was missing the `undefined` case — so the same
 * entry could hash differently in the app and in the report, and the report
 * would declare CHAIN BROKEN on a chain the app called INTACT. Consensus code
 * with two copies eventually has two behaviours; the only durable fix is one
 * copy.
 *
 * sortedStringify is deliberately self-contained (it closes over nothing), so
 * its source text is complete and survives minification.
 */
function verifierSource() {
  const encoderSource = checkEncoderSource(sortedStringify.toString());
  return `
const SUPPORTED_VERSIONS = ${JSON.stringify(SUPPORTED_VERSIONS)};
const GENESIS = ${JSON.stringify(GENESIS)};
const HASHED_FIELDS_BY_VERSION = ${JSON.stringify(HASHED_FIELDS_BY_VERSION)};
const ENTRIES = JSON.parse(document.getElementById('chain-data').textContent);

const sortedStringify = ${encoderSource};

async function computeEntryHash(entry) {
  const fields = HASHED_FIELDS_BY_VERSION[entry.schema_version];
  if (!fields) throw new Error('unsupported schema_version ' + entry.schema_version);
  const hashable = {};
  for (const key of fields) hashable[key] = entry[key];
  const bytes = new TextEncoder().encode(sortedStringify(hashable));
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
}

function setResult(text, className) {
  const el = document.getElementById('result');
  el.textContent = text;
  el.className = className;
}

async function verify() {
  if (!globalThis.crypto || !crypto.subtle) {
    setResult('Cannot verify: the Web Crypto API is unavailable in this context. Open this report over https:// or as a local file in a modern browser.', 'broken');
    return;
  }

  let prev = GENESIS;
  const chainId = ENTRIES.length ? ENTRIES[0].chain_id : null;

  for (let i = 0; i < ENTRIES.length; i++) {
    const entry = ENTRIES[i];
    const status = document.getElementById('status-' + i);
    const fail = (label, reason) => {
      status.textContent = label;
      status.className = 'mono fail';
      setResult('CHAIN BROKEN at entry ' + (i + 1) + ' — ' + reason, 'broken');
    };

    if (!SUPPORTED_VERSIONS.includes(entry.schema_version)) {
      fail('FORMAT', 'unsupported schema version'); return;
    }
    if (entry.seq !== i) {
      fail('ORDER', 'entries were reordered or removed'); return;
    }
    if (entry.chain_id !== chainId) {
      fail('FOREIGN', 'entry belongs to a different chain'); return;
    }
    if (entry.prev_hash !== prev) {
      fail('BROKEN', 'link does not match the preceding entry'); return;
    }
    if (await computeEntryHash(entry) !== entry.entry_hash) {
      fail('MODIFIED', 'entry content was modified'); return;
    }

    status.textContent = '\\u2713 OK';
    status.className = 'mono pass';
    prev = entry.entry_hash;
  }

  setResult(
    'CHAIN INTACT \\u2014 ' + ENTRIES.length + ' entries verified. Head: ' + prev
      + '. This shows the records are in order and unaltered; it cannot show whether entries were removed from the end.',
    'intact',
  );
}

document.getElementById('verify-btn').addEventListener('click', () => {
  verify().catch(err => setResult('Verification failed: ' + err, 'broken'));
});
`;
}

export function generateCSV(entries) {
  const headers = ['id', 'timestamp_registered', 'file_name', 'file_hash', 'file_size', 'file_type', 'custodian', 'case_reference', 'notes', 'prev_hash', 'entry_hash'];
  const rows = [headers.join(',')];

  for (const entry of entries) {
    const row = [
      escapeCSVField(entry.id),
      escapeCSVField(entry.timestamp_registered),
      escapeCSVField(entry.evidence.file_name),
      escapeCSVField(entry.evidence.file_hash),
      entry.evidence.file_size,
      escapeCSVField(entry.evidence.file_type),
      escapeCSVField(entry.custody.custodian),
      escapeCSVField(entry.custody.case_reference),
      escapeCSVField(entry.custody.notes),
      escapeCSVField(entry.prev_hash),
      escapeCSVField(entry.entry_hash),
    ].map(v => `"${String(v).replace(/"/g, '""')}"`);
    rows.push(row.join(','));
  }

  // BOM so Excel reads the file as UTF-8 (without it "Müller" renders as
  // "MÃ¼ller"), and CRLF line endings per RFC 4180.
  return '\ufeff' + rows.join('\r\n') + '\r\n';
}

/**
 * Serialize chain data for embedding in the report's
 * <script type="application/json"> block.
 *
 * `<` is escaped to its \u form so that a filename or note containing
 * "</script>" cannot terminate the element and inject markup into a report
 * that gets handed to a counterparty. The result is still valid JSON.
 */
export function embedJSON(value) {
  return JSON.stringify(value).replace(/</g, '\\u003c');
}

export function generateHTMLReport(entries) {
  const generated = new Date().toISOString();

  const entryRows = entries.map((e, i) => html`
    <tr>
      <td>${i + 1}</td>
      <td>${e.evidence.file_name}</td>
      <td class="mono">${truncateHash(e.evidence.file_hash)}</td>
      <td>${e.custody.custodian}</td>
      <td>${e.timestamp_registered}</td>
      <td class="mono" id="status-${i}">—</td>
    </tr>
  `);

  return String(html`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Beweiskette Verification Report</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#070a11;color:#e2e8f0;padding:40px 24px;line-height:1.6}
.container{max-width:900px;margin:0 auto}
h1{font-size:1.4rem;letter-spacing:.08em;text-transform:uppercase;margin-bottom:4px}
.subtitle{color:#94a3b8;font-size:.85rem;margin-bottom:32px}
.meta{font-size:.78rem;color:#64748b;margin-bottom:24px}
table{width:100%;border-collapse:collapse;margin-bottom:24px;font-size:.85rem}
th{text-align:left;padding:10px 12px;background:#111827;border-bottom:2px solid #1e2a42;font-size:.73rem;text-transform:uppercase;letter-spacing:.05em;color:#94a3b8}
td{padding:10px 12px;border-bottom:1px solid #1e2a42}
.mono{font-family:'SF Mono','Cascadia Code',Consolas,monospace;font-size:.75rem;color:#7dd3fc}
.btn{background:#3b82f6;color:#fff;border:none;padding:10px 24px;border-radius:6px;cursor:pointer;font-size:.88rem;font-weight:600}
.btn:hover{background:#60a5fa}
.pass{color:#22c55e;font-weight:600}
.fail{color:#ef4444;font-weight:600}
#result{margin-top:16px;padding:14px 20px;border-radius:8px;font-weight:600;font-size:.9rem}
#result.intact{background:rgba(34,197,94,.08);color:#22c55e;border:1px solid rgba(34,197,94,.25)}
#result.broken{background:rgba(239,68,68,.08);color:#ef4444;border:1px solid rgba(239,68,68,.25)}
.footer{margin-top:48px;padding-top:24px;border-top:1px solid #1e2a42;font-size:.73rem;color:#64748b}
</style>
</head>
<body>
<div class="container">
<h1>Beweiskette</h1>
<p class="subtitle">Digital Evidence Chain of Custody — Verification Report</p>
<p class="meta">Generated: ${generated} | Entries: ${entries.length}</p>
<table>
<thead><tr><th>#</th><th>File</th><th>File Hash</th><th>Custodian</th><th>Registered</th><th>Status</th></tr></thead>
<tbody>${entryRows}</tbody>
</table>
<button class="btn" id="verify-btn">Verify Chain Integrity</button>
<div id="result"></div>
<div class="footer">
<p>This is a self-contained verification report. Open in any browser and click "Verify Chain Integrity" to recompute all hashes and validate the chain.</p>
<p style="margin-top:8px">Beweiskette — github.com/Be11aMer/beweiskette</p>
</div>
</div>
<script type="application/json" id="chain-data">${raw(embedJSON(entries))}</script>
<script>${raw(verifierSource())}
</script>
</body>
</html>`);
}
