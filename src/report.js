/**
 * Export artifact generation: CSV summary and the self-contained HTML report.
 *
 * Kept free of DOM, IndexedDB and app-shell imports so it stays a pure
 * function of the entry list — the HTML report is the artifact most likely to
 * be handed to a third party, so it needs to be directly testable.
 */

import { escapeCSVField, truncateHash, html, raw } from './utils.js';

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
<script>
const ENTRIES=JSON.parse(document.getElementById('chain-data').textContent);
function sortedStringify(o){if(o===null)return'null';if(typeof o==='undefined')return undefined;if(typeof o==='boolean')return o?'true':'false';if(typeof o==='number')return JSON.stringify(o);if(typeof o==='string')return JSON.stringify(o);if(Array.isArray(o))return'['+o.map(sortedStringify).join(',')+']';if(typeof o==='object'){const k=Object.keys(o).sort();const p=k.map(k=>{const v=sortedStringify(o[k]);return v!==undefined?JSON.stringify(k)+':'+v:undefined}).filter(p=>p!==undefined);return'{'+p.join(',')+'}'}return String(o)}
async function computeHash(e){const h={};for(const k of Object.keys(e))if(k!=='entry_hash')h[k]=e[k];const c=sortedStringify(h);const b=new TextEncoder().encode(c);const d=await crypto.subtle.digest('SHA-256',b);return Array.from(new Uint8Array(d),b=>b.toString(16).padStart(2,'0')).join('')}
async function verify(){const r=document.getElementById('result');if(!globalThis.crypto||!crypto.subtle){r.textContent='Cannot verify: the Web Crypto API is unavailable in this context. Open this report over https:// or as a local file in a modern browser.';r.className='broken';return}let prev='GENESIS';let broken=false;for(let i=0;i<ENTRIES.length;i++){const e=ENTRIES[i];const s=document.getElementById('status-'+i);if(e.prev_hash!==prev){s.textContent='BROKEN';s.className='mono fail';r.textContent='CHAIN BROKEN at entry '+(i+1);r.className='broken';broken=true;break}const h=await computeHash(e);if(h!==e.entry_hash){s.textContent='MODIFIED';s.className='mono fail';r.textContent='CHAIN BROKEN at entry '+(i+1)+' (content modified)';r.className='broken';broken=true;break}s.textContent='\\u2713 OK';s.className='mono pass';prev=e.entry_hash}if(!broken){r.textContent='CHAIN INTACT \\u2014 '+ENTRIES.length+' entries verified';r.className='intact'}}
document.getElementById('verify-btn').addEventListener('click',()=>{verify().catch(err=>{const r=document.getElementById('result');r.textContent='Verification failed: '+err;r.className='broken'})});
</script>
</body>
</html>`);
}
