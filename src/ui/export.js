/**
 * Export view — export chain as JSON, CSV, or self-contained HTML report.
 */

import { getAllEntries } from '../store.js';
import { sanitizeText, formatDate, escapeCSVField, truncateHash } from '../utils.js';
import { showToast } from '../main.js';

let selectedFormat = 'json';

export async function render(container) {
  const entries = await getAllEntries();
  selectedFormat = 'json';

  container.innerHTML = `
    <div class="section-header">
      <span class="section-title">Export Evidence Chain</span>
      <span class="status-badge empty">
        <span class="status-dot"></span>
        ${entries.length} ${entries.length === 1 ? 'entry' : 'entries'}
      </span>
    </div>

    ${entries.length === 0 ? `
      <div class="empty-state">
        <svg class="empty-state-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        <p class="empty-state-text">Nothing to export</p>
        <p class="empty-state-hint">Register evidence first, then export your chain.</p>
      </div>
    ` : `
      <div class="export-options" id="format-options">
        <div class="export-option selected" data-format="json">
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
            <polyline points="14 2 14 8 20 8"/>
          </svg>
          <div class="export-option-label">JSON</div>
          <div class="export-option-desc">Full chain data, machine-readable</div>
        </div>
        <div class="export-option" data-format="csv">
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
            <line x1="3" y1="9" x2="21" y2="9"/>
            <line x1="3" y1="15" x2="21" y2="15"/>
            <line x1="9" y1="3" x2="9" y2="21"/>
          </svg>
          <div class="export-option-label">CSV</div>
          <div class="export-option-desc">Spreadsheet-compatible</div>
        </div>
        <div class="export-option" data-format="html">
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="16 18 22 12 16 6"/>
            <polyline points="8 6 2 12 8 18"/>
          </svg>
          <div class="export-option-label">HTML Report</div>
          <div class="export-option-desc">Self-contained, verifiable</div>
        </div>
      </div>

      <div class="btn-group">
        <button class="btn btn-primary" id="download-btn">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="7 10 12 15 17 10"/>
            <line x1="12" y1="15" x2="12" y2="3"/>
          </svg>
          Download
        </button>
        <button class="btn btn-danger" id="clear-all-btn">
          Clear All Data
        </button>
      </div>
    `}
  `;

  if (entries.length === 0) return;

  container.querySelectorAll('.export-option').forEach(opt => {
    opt.addEventListener('click', () => {
      container.querySelectorAll('.export-option').forEach(o => o.classList.remove('selected'));
      opt.classList.add('selected');
      selectedFormat = opt.dataset.format;
    });
  });

  container.querySelector('#download-btn').addEventListener('click', () => downloadExport(entries));

  container.querySelector('#clear-all-btn').addEventListener('click', async () => {
    if (confirm('This will permanently delete all evidence entries from this browser. Exported files will not be affected. Continue?')) {
      const { clearAll } = await import('../store.js');
      await clearAll();
      showToast('All data cleared.');
      render(container);
    }
  });
}

function downloadExport(entries) {
  let content, filename, mimeType;

  if (selectedFormat === 'json') {
    content = JSON.stringify(entries, null, 2);
    filename = `beweiskette_export_${dateStamp()}.json`;
    mimeType = 'application/json';
  } else if (selectedFormat === 'csv') {
    content = generateCSV(entries);
    filename = `beweiskette_export_${dateStamp()}.csv`;
    mimeType = 'text/csv';
  } else if (selectedFormat === 'html') {
    content = generateHTMLReport(entries);
    filename = `beweiskette_report_${dateStamp()}.html`;
    mimeType = 'text/html';
  }

  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
  showToast(`Exported as ${selectedFormat.toUpperCase()}`);
}

function dateStamp() {
  return new Date().toISOString().slice(0, 10);
}

function generateCSV(entries) {
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

  return rows.join('\n');
}

function generateHTMLReport(entries) {
  const generated = new Date().toISOString();

  const entryRows = entries.map((e, i) => `
    <tr>
      <td>${i + 1}</td>
      <td>${sanitizeText(e.evidence.file_name)}</td>
      <td class="mono">${sanitizeText(truncateHash(e.evidence.file_hash))}</td>
      <td>${sanitizeText(e.custody.custodian)}</td>
      <td>${sanitizeText(e.timestamp_registered)}</td>
      <td class="mono" id="status-${i}">—</td>
    </tr>
  `).join('');

  return `<!DOCTYPE html>
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
<p class="meta">Generated: ${sanitizeText(generated)} | Entries: ${entries.length}</p>
<table>
<thead><tr><th>#</th><th>File</th><th>File Hash</th><th>Custodian</th><th>Registered</th><th>Status</th></tr></thead>
<tbody>${entryRows}</tbody>
</table>
<button class="btn" onclick="verify()">Verify Chain Integrity</button>
<div id="result"></div>
<div class="footer">
<p>This is a self-contained verification report. Open in any browser and click "Verify Chain Integrity" to recompute all hashes and validate the chain.</p>
<p style="margin-top:8px">Beweiskette — github.com/Bellamer/beweiskette</p>
</div>
</div>
<script>
const ENTRIES=${JSON.stringify(entries)};
function sortedStringify(o){if(o===null)return'null';if(typeof o==='boolean')return o?'true':'false';if(typeof o==='number')return JSON.stringify(o);if(typeof o==='string')return JSON.stringify(o);if(Array.isArray(o))return'['+o.map(sortedStringify).join(',')+']';if(typeof o==='object'){const k=Object.keys(o).sort();const p=k.map(k=>{const v=sortedStringify(o[k]);return v!==undefined?JSON.stringify(k)+':'+v:undefined}).filter(p=>p!==undefined);return'{'+p.join(',')+'}'}return String(o)}
async function computeHash(e){const h={};for(const k of Object.keys(e))if(k!=='entry_hash')h[k]=e[k];const c=sortedStringify(h);const b=new TextEncoder().encode(c);const d=await crypto.subtle.digest('SHA-256',b);return Array.from(new Uint8Array(d),b=>b.toString(16).padStart(2,'0')).join('')}
async function verify(){const r=document.getElementById('result');let prev='GENESIS';let broken=false;for(let i=0;i<ENTRIES.length;i++){const e=ENTRIES[i];const s=document.getElementById('status-'+i);if(e.prev_hash!==prev){s.textContent='BROKEN';s.className='mono fail';r.textContent='CHAIN BROKEN at entry '+(i+1);r.className='broken';broken=true;break}const h=await computeHash(e);if(h!==e.entry_hash){s.textContent='MODIFIED';s.className='mono fail';r.textContent='CHAIN BROKEN at entry '+(i+1)+' (content modified)';r.className='broken';broken=true;break}s.textContent='\\u2713 OK';s.className='mono pass';prev=e.entry_hash}if(!broken){r.textContent='CHAIN INTACT \\u2014 '+ENTRIES.length+' entries verified';r.className='intact'}}
</script>
</body>
</html>`;
}
