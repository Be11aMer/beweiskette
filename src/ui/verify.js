/**
 * Verify view — verify chain integrity from imported JSON, or verify a single file against a known hash.
 *
 * The chain JSON handled here is untrusted: it typically comes from a
 * counterparty. Everything derived from it is rendered through the `html`
 * tagged template, which escapes interpolated values by default.
 */

import { verifyChain } from '../chain.js';
import { hashFile, constantTimeEqual } from '../crypto.js';
import { formatDate, truncateHash, html, raw } from '../utils.js';

const ICON_PASS = raw('<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>');
const ICON_FAIL = raw('<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>');

/** A single status line with a pass/fail icon. */
function statusLine(ok, message, style = 'margin-top:16px') {
  return html`
    <div class="verify-entry ${ok ? 'pass' : 'fail'}" style="${style}">
      <svg class="verify-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${ok ? ICON_PASS : ICON_FAIL}</svg>
      ${message}
    </div>
  `;
}

export function render(container) {
  container.innerHTML = html`
    <div class="section-header">
      <span class="section-title">Verify Chain</span>
    </div>
    <p style="font-size:0.85rem;color:var(--text-secondary);margin-bottom:20px">
      Import a previously exported chain (JSON) to verify its integrity.
      Every hash is recomputed and every link is checked.
    </p>
    <div class="drop-zone" id="chain-drop-zone" style="padding:32px 24px">
      <svg class="drop-zone-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="width:36px;height:36px">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
        <polyline points="14 2 14 8 20 8"/>
        <line x1="16" y1="13" x2="8" y2="13"/>
        <line x1="16" y1="17" x2="8" y2="17"/>
      </svg>
      <p class="drop-zone-text">Drop chain JSON file here</p>
      <p class="drop-zone-hint">or click to browse</p>
      <input type="file" id="chain-file-input" accept=".json" aria-label="Select chain JSON file">
    </div>
    <div id="chain-verify-results"></div>

    <div class="divider" style="margin:36px 0"></div>

    <div class="section-header">
      <span class="section-title">Verify Single File</span>
    </div>
    <p style="font-size:0.85rem;color:var(--text-secondary);margin-bottom:20px">
      Drop a file to compute its SHA-256 hash. Compare against a known hash to confirm the file hasn't been modified.
    </p>
    <div class="drop-zone" id="file-drop-zone" style="padding:32px 24px">
      <svg class="drop-zone-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="width:36px;height:36px">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <path d="M9 12l2 2 4-4"/>
      </svg>
      <p class="drop-zone-text">Drop file to hash</p>
      <p class="drop-zone-hint">SHA-256 computed locally in your browser</p>
      <input type="file" id="single-file-input" aria-label="Select file to verify">
    </div>
    <div class="form-group">
      <label class="form-label" for="expected-hash">Expected Hash (optional)</label>
      <input class="form-input" type="text" id="expected-hash" placeholder="Paste expected SHA-256 hash to compare" style="font-family:var(--font-mono);font-size:0.8rem">
    </div>
    <div id="file-verify-results"></div>
  `;

  setupChainVerify(container);
  setupFileVerify(container);
}

/** Wire a drop zone + file input pair to a handler. */
function setupDropZone(dropZone, fileInput, onFile) {
  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) onFile(e.dataTransfer.files[0]);
  });
  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) onFile(e.target.files[0]);
  });
}

function setupChainVerify(container) {
  const resultsDiv = container.querySelector('#chain-verify-results');
  setupDropZone(
    container.querySelector('#chain-drop-zone'),
    container.querySelector('#chain-file-input'),
    (file) => verifyChainFile(file, resultsDiv),
  );
}

async function verifyChainFile(file, resultsDiv) {
  try {
    const text = await file.text();
    let entries;
    try {
      entries = JSON.parse(text);
    } catch {
      resultsDiv.innerHTML = statusLine(false, 'Invalid JSON file.');
      return;
    }

    if (!Array.isArray(entries)) {
      resultsDiv.innerHTML = statusLine(false, 'Expected a JSON array of entries.');
      return;
    }

    const result = await verifyChain(entries);

    let summary;
    if (result.intact) {
      summary = html`
        ${statusLine(true, `CHAIN INTACT — ${result.entries} entries verified`)}
        ${entries.length > 0 ? html`
          <div style="font-size:0.78rem;color:var(--text-muted);margin-top:8px;padding-left:30px">
            Range: ${formatDate(entries[0].timestamp_registered)} — ${formatDate(entries[entries.length - 1].timestamp_registered)}
          </div>
        ` : ''}
      `;
    } else {
      summary = html`
        ${statusLine(false, `CHAIN BROKEN at entry ${result.brokenAt}`)}
        <div style="font-size:0.78rem;color:var(--text-muted);margin-top:8px;padding-left:30px">${result.details}</div>
        ${result.brokenId ? html`
          <div style="font-size:0.78rem;color:var(--text-muted);padding-left:30px">ID: ${result.brokenId}</div>
        ` : ''}
      `;
    }

    const rows = entries.map((entry, i) => {
      const ok = result.intact || i + 1 < result.brokenAt;
      const fileName = entry && entry.evidence ? entry.evidence.file_name : `Entry ${i + 1}`;
      return html`
        <div class="verify-entry ${ok ? 'pass' : 'fail'}">
          <svg class="verify-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${ok ? ICON_PASS : ICON_FAIL}</svg>
          <span style="flex:1">${i + 1}. ${fileName}</span>
          <span style="font-family:var(--font-mono);font-size:0.7rem;opacity:0.7">${truncateHash(entry && entry.entry_hash)}</span>
        </div>
      `;
    });

    resultsDiv.innerHTML = html`
      <div class="verify-results">
        ${summary}
        <div style="margin-top:16px">
          <div class="section-title" style="margin-bottom:8px">Entry-by-entry verification</div>
          ${rows}
        </div>
      </div>
    `;
  } catch {
    resultsDiv.innerHTML = statusLine(false, 'Error processing file.');
  }
}

function setupFileVerify(container) {
  const resultsDiv = container.querySelector('#file-verify-results');
  setupDropZone(
    container.querySelector('#file-drop-zone'),
    container.querySelector('#single-file-input'),
    (file) => verifySingleFile(file, container, resultsDiv),
  );
}

async function verifySingleFile(file, container, resultsDiv) {
  try {
    const hash = await hashFile(file);
    const expectedHash = container.querySelector('#expected-hash').value.trim().toLowerCase();

    const matches = expectedHash ? constantTimeEqual(hash, expectedHash) : null;

    resultsDiv.innerHTML = html`
      <div class="file-info" style="margin-top:16px">
        <div class="file-info-row">
          <span class="file-info-label">File</span>
          <span class="file-info-value">${file.name}</span>
        </div>
        <div class="file-info-row">
          <span class="file-info-label">SHA-256</span>
          <span class="file-info-value hash">${hash}</span>
        </div>
      </div>
      ${matches === null ? '' : statusLine(
        matches,
        matches ? 'Hash matches — file is unmodified' : 'Hash does NOT match — file has been modified',
        'margin-top:12px',
      )}
    `;
  } catch {
    resultsDiv.innerHTML = statusLine(false, 'Failed to compute hash.');
  }
}
