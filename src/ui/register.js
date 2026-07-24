/**
 * Register Evidence view.
 * Drop zone for files, hash computation, EXIF extraction, custody form.
 */

import { hashFile } from '../crypto.js';
import { extractExif } from '../exif.js';
import { createEntry, GENESIS } from '../chain.js';
import { addEntry, getLastEntry } from '../store.js';
import { formatFileSize, truncateHash, sanitizeText, html } from '../utils.js';
import { showToast, navigateTo } from '../main.js';

let currentFile = null;
let currentFileHash = null;
let currentExif = null;

export function render(container) {
  currentFile = null;
  currentFileHash = null;
  currentExif = null;

  container.innerHTML = html`
    <div class="drop-zone" id="drop-zone">
      <svg class="drop-zone-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <path d="M9 12l2 2 4-4"/>
      </svg>
      <p class="drop-zone-text">Drop evidence file here</p>
      <p class="drop-zone-hint">or click to browse — file never leaves your browser</p>
      <input type="file" id="file-input" aria-label="Select evidence file">
    </div>

    <div id="file-info-section"></div>

    <div id="custody-form-section" style="display:none">
      <div class="divider"></div>
      <div class="section-header">
        <span class="section-title">Chain of Custody</span>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label class="form-label" for="custodian">Custodian</label>
          <input class="form-input" type="text" id="custodian" placeholder="John Doe" maxlength="100">
        </div>
        <div class="form-group">
          <label class="form-label" for="case-ref">Case Reference</label>
          <input class="form-input" type="text" id="case-ref" placeholder="CASE-2026-0042" maxlength="50">
        </div>
      </div>
      <div class="form-group">
        <label class="form-label" for="notes">Notes</label>
        <textarea class="form-textarea" id="notes" placeholder="Context about the evidence..." maxlength="500"></textarea>
      </div>
      <div class="btn-group">
        <button class="btn btn-primary" id="register-btn" disabled>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          Register Evidence
        </button>
        <button class="btn btn-secondary" id="clear-btn">Clear</button>
      </div>
    </div>
  `;

  const dropZone = container.querySelector('#drop-zone');
  const fileInput = container.querySelector('#file-input');
  const registerBtn = container.querySelector('#register-btn');
  const clearBtn = container.querySelector('#clear-btn');

  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
  });

  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
      processFile(e.dataTransfer.files[0], container);
    }
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      processFile(e.target.files[0], container);
    }
  });

  registerBtn.addEventListener('click', () => registerEvidence(container));
  clearBtn.addEventListener('click', () => render(container));
}

async function processFile(file, container) {
  currentFile = file;
  const infoSection = container.querySelector('#file-info-section');
  const formSection = container.querySelector('#custody-form-section');
  const registerBtn = container.querySelector('#register-btn');

  infoSection.innerHTML = html`
    <div class="file-info">
      <div class="file-info-row">
        <span class="file-info-label">Computing hash</span>
        <span class="file-info-value">...</span>
      </div>
    </div>
  `;

  try {
    currentFileHash = await hashFile(file);

    const buffer = await file.arrayBuffer();
    currentExif = extractExif(buffer);

    let exifHTML = '';
    if (currentExif) {
      const fields = [];
      if (currentExif.datetime_original || currentExif.datetime) {
        fields.push(['EXIF Date', currentExif.datetime_original || currentExif.datetime]);
      }
      if (currentExif.camera_make || currentExif.camera_model) {
        fields.push(['Camera', [currentExif.camera_make, currentExif.camera_model].filter(Boolean).join(' ')]);
      }
      if (currentExif.gps_lat !== undefined && currentExif.gps_lng !== undefined) {
        fields.push(['GPS', `${currentExif.gps_lat}, ${currentExif.gps_lng}`]);
      }
      if (fields.length > 0) {
        exifHTML = html`
          <div class="file-info-row" style="border-top:1px solid var(--border);margin-top:8px;padding-top:12px">
            <span class="file-info-label" style="color:var(--accent)">EXIF Metadata</span>
            <span class="file-info-value" style="font-size:0.73rem;color:var(--text-muted)">Extracted from file</span>
          </div>
          ${fields.map(([label, value]) => html`
            <div class="file-info-row">
              <span class="file-info-label">${label}</span>
              <span class="file-info-value">${String(value)}</span>
            </div>
          `)}
        `;
      }
    }

    infoSection.innerHTML = html`
      <div class="file-info">
        <div class="file-info-row">
          <span class="file-info-label">File Name</span>
          <span class="file-info-value">${file.name}</span>
        </div>
        <div class="file-info-row">
          <span class="file-info-label">Size</span>
          <span class="file-info-value">${formatFileSize(file.size)}</span>
        </div>
        <div class="file-info-row">
          <span class="file-info-label">Type</span>
          <span class="file-info-value">${file.type || 'unknown'}</span>
        </div>
        <div class="file-info-row">
          <span class="file-info-label">Last Modified</span>
          <span class="file-info-value">${new Date(file.lastModified).toLocaleString('en-GB')}</span>
        </div>
        <div class="file-info-row">
          <span class="file-info-label">SHA-256</span>
          <span class="file-info-value hash">${currentFileHash}</span>
        </div>
        ${exifHTML}
      </div>
    `;

    formSection.style.display = 'block';
    registerBtn.disabled = false;
  } catch (err) {
    infoSection.innerHTML = html`
      <div class="file-info" style="border-color:var(--danger-border)">
        <div class="file-info-row">
          <span class="file-info-label" style="color:var(--danger)">Error</span>
          <span class="file-info-value" style="color:var(--danger)">Failed to process file.</span>
        </div>
      </div>
    `;
  }
}

async function registerEvidence(container) {
  if (!currentFile || !currentFileHash) return;

  const custodian = sanitizeText(container.querySelector('#custodian').value.trim());
  const caseRef = sanitizeText(container.querySelector('#case-ref').value.trim());
  const notes = sanitizeText(container.querySelector('#notes').value.trim());

  const registerBtn = container.querySelector('#register-btn');
  registerBtn.disabled = true;
  registerBtn.textContent = 'Registering...';

  try {
    const evidence = {
      file_hash: currentFileHash,
      file_name: currentFile.name,
      file_size: currentFile.size,
      file_type: currentFile.type || 'unknown',
      file_last_modified: new Date(currentFile.lastModified).toISOString(),
    };

    const metadata = currentExif ? { ...currentExif } : null;

    const custody = {
      custodian: custodian || 'Unknown',
      case_reference: caseRef || '',
      notes: notes || '',
    };

    const lastEntry = await getLastEntry();
    const prevHash = lastEntry ? lastEntry.entry_hash : GENESIS;

    const entry = await createEntry(evidence, metadata, custody, prevHash);
    await addEntry(entry);

    showToast(`Evidence registered — ${truncateHash(entry.entry_hash)}`);
    navigateTo('chain');
  } catch (err) {
    showToast('Failed to register evidence.', true);
    registerBtn.disabled = false;
    registerBtn.textContent = 'Register Evidence';
  }
}
