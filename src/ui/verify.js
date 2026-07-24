/**
 * Verify view — verify chain integrity from imported JSON, or verify a single file against a known hash.
 */

import { verifyChain } from '../chain.js';
import { hashFile } from '../crypto.js';
import { formatDate, truncateHash, sanitizeText } from '../utils.js';
import { showToast } from '../main.js';

export function render(container) {
  container.innerHTML = `
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

function setupChainVerify(container) {
  const dropZone = container.querySelector('#chain-drop-zone');
  const fileInput = container.querySelector('#chain-file-input');
  const resultsDiv = container.querySelector('#chain-verify-results');

  const handleDrag = (e) => { e.preventDefault(); dropZone.classList.add('dragover'); };
  const handleLeave = () => dropZone.classList.remove('dragover');

  dropZone.addEventListener('dragover', handleDrag);
  dropZone.addEventListener('dragleave', handleLeave);
  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) verifyChainFile(e.dataTransfer.files[0], resultsDiv);
  });
  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) verifyChainFile(e.target.files[0], resultsDiv);
  });
}

async function verifyChainFile(file, resultsDiv) {
  try {
    const text = await file.text();
    let entries;
    try {
      entries = JSON.parse(text);
    } catch {
      resultsDiv.innerHTML = `
        <div class="verify-entry fail" style="margin-top:16px">
          <svg class="verify-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
          Invalid JSON file.
        </div>
      `;
      return;
    }

    if (!Array.isArray(entries)) {
      resultsDiv.innerHTML = `
        <div class="verify-entry fail" style="margin-top:16px">
          <svg class="verify-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
          Expected a JSON array of entries.
        </div>
      `;
      return;
    }

    const result = await verifyChain(entries);

    let html = `<div class="verify-results">`;

    if (result.intact) {
      html += `
        <div class="verify-entry pass" style="margin-top:16px">
          <svg class="verify-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
          CHAIN INTACT — ${result.entries} entries verified
        </div>
      `;

      if (entries.length > 0) {
        const first = formatDate(entries[0].timestamp_registered);
        const last = formatDate(entries[entries.length - 1].timestamp_registered);
        html += `<div style="font-size:0.78rem;color:var(--text-muted);margin-top:8px;padding-left:30px">Range: ${first} — ${last}</div>`;
      }
    } else {
      html += `
        <div class="verify-entry fail" style="margin-top:16px">
          <svg class="verify-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
          CHAIN BROKEN at entry ${result.brokenAt}
        </div>
        <div style="font-size:0.78rem;color:var(--text-muted);margin-top:8px;padding-left:30px">${sanitizeText(result.details)}</div>
      `;

      if (result.brokenId) {
        html += `<div style="font-size:0.78rem;color:var(--text-muted);padding-left:30px">ID: ${sanitizeText(result.brokenId)}</div>`;
      }
    }

    html += `
      <div style="margin-top:16px">
        <div class="section-title" style="margin-bottom:8px">Entry-by-entry verification</div>
    `;

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      const isBroken = !result.intact && result.brokenAt === i + 1;
      const isPast = !result.intact && result.brokenAt && i + 1 > result.brokenAt;
      const statusClass = isBroken ? 'fail' : (isPast ? 'fail' : 'pass');
      const fileName = entry.evidence ? sanitizeText(entry.evidence.file_name) : `Entry ${i + 1}`;

      html += `
        <div class="verify-entry ${statusClass}">
          <svg class="verify-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            ${statusClass === 'pass'
              ? '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>'
              : '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>'}
          </svg>
          <span style="flex:1">${i + 1}. ${fileName}</span>
          <span style="font-family:var(--font-mono);font-size:0.7rem;opacity:0.7">${truncateHash(entry.entry_hash)}</span>
        </div>
      `;
    }

    html += '</div></div>';
    resultsDiv.innerHTML = html;
  } catch (err) {
    resultsDiv.innerHTML = `
      <div class="verify-entry fail" style="margin-top:16px">
        <svg class="verify-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
        Error processing file.
      </div>
    `;
  }
}

function setupFileVerify(container) {
  const dropZone = container.querySelector('#file-drop-zone');
  const fileInput = container.querySelector('#single-file-input');
  const resultsDiv = container.querySelector('#file-verify-results');

  const handleDrag = (e) => { e.preventDefault(); dropZone.classList.add('dragover'); };
  const handleLeave = () => dropZone.classList.remove('dragover');

  dropZone.addEventListener('dragover', handleDrag);
  dropZone.addEventListener('dragleave', handleLeave);
  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) verifySingleFile(e.dataTransfer.files[0], container, resultsDiv);
  });
  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) verifySingleFile(e.target.files[0], container, resultsDiv);
  });
}

async function verifySingleFile(file, container, resultsDiv) {
  try {
    const hash = await hashFile(file);
    const expectedHash = container.querySelector('#expected-hash').value.trim().toLowerCase();

    let matchHtml = '';
    if (expectedHash) {
      const matches = hash === expectedHash;
      matchHtml = `
        <div class="verify-entry ${matches ? 'pass' : 'fail'}" style="margin-top:12px">
          <svg class="verify-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            ${matches
              ? '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>'
              : '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>'}
          </svg>
          ${matches ? 'Hash matches — file is unmodified' : 'Hash does NOT match — file has been modified'}
        </div>
      `;
    }

    resultsDiv.innerHTML = `
      <div class="file-info" style="margin-top:16px">
        <div class="file-info-row">
          <span class="file-info-label">File</span>
          <span class="file-info-value">${sanitizeText(file.name)}</span>
        </div>
        <div class="file-info-row">
          <span class="file-info-label">SHA-256</span>
          <span class="file-info-value hash">${hash}</span>
        </div>
      </div>
      ${matchHtml}
    `;
  } catch {
    resultsDiv.innerHTML = `
      <div class="verify-entry fail" style="margin-top:16px">
        <svg class="verify-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
        Failed to compute hash.
      </div>
    `;
  }
}
