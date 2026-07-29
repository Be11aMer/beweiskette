/**
 * Verify view — verify chain integrity from imported JSON, or verify a single file against a known hash.
 *
 * The chain JSON handled here is untrusted: it typically comes from a
 * counterparty. Everything derived from it is rendered through the `html`
 * tagged template, which escapes interpolated values by default.
 */

import { verifyChain } from '../chain.js';
import { parseReceipt, checkAnchor, anchorCoverage } from '../anchor.js';
import { readEnvelope } from '../report.js';
import { hashFile, constantTimeEqual } from '../crypto.js';
import { formatDate, truncateHash, html, raw } from '../utils.js';

/** Entries from the most recently imported chain, for the anchor check. */
let importedEntries = null;

const ICON_PASS = raw('<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>');
const ICON_FAIL = raw('<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>');

/** A single status line with a pass/fail icon. */
function statusLine(ok, message, spacing = 'mt-16') {
  return html`
    <div class="verify-entry ${ok ? 'pass' : 'fail'} ${spacing}">
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
    <p class="hint-text">
      Import a previously exported chain (JSON) to verify its integrity.
      Every hash is recomputed and every link is checked.
    </p>
    <div class="drop-zone compact" id="chain-drop-zone">
      <svg class="drop-zone-icon small" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
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

    <div class="divider wide"></div>

    <div class="section-header">
      <span class="section-title">Check Against a Published Receipt</span>
    </div>
    <p class="hint-text">
      A chain that verifies only proves its records are in order and unaltered. It cannot show
      that entries were removed from the end, because nothing in the file commits to how long
      it should be. Paste a receipt published earlier to check the chain still reaches it.
    </p>
    <div class="form-group">
      <label class="form-label" for="receipt-input">Anchor Receipt</label>
      <textarea class="form-textarea mono-block" id="receipt-input" rows="8"
        placeholder="Paste the BEWEISKETTE ANCHOR RECEIPT block here"></textarea>
    </div>
    <div class="btn-group">
      <button class="btn btn-primary" id="check-anchor-btn">Check Anchor</button>
    </div>
    <div id="anchor-results"></div>

    <div class="divider wide"></div>

    <div class="section-header">
      <span class="section-title">Verify Single File</span>
    </div>
    <p class="hint-text">
      Drop a file to compute its SHA-256 hash. Compare against a known hash to confirm the file hasn't been modified.
    </p>
    <div class="drop-zone compact" id="file-drop-zone">
      <svg class="drop-zone-icon small" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <path d="M9 12l2 2 4-4"/>
      </svg>
      <p class="drop-zone-text">Drop file to hash</p>
      <p class="drop-zone-hint">SHA-256 computed locally in your browser</p>
      <input type="file" id="single-file-input" aria-label="Select file to verify">
    </div>
    <div class="form-group">
      <label class="form-label" for="expected-hash">Expected Hash (optional)</label>
      <input class="form-input mono-input" type="text" id="expected-hash" placeholder="Paste expected SHA-256 hash to compare">
    </div>
    <div id="file-verify-results"></div>
  `;

  setupChainVerify(container);
  setupAnchorCheck(container);
  setupFileVerify(container);
}

function setupAnchorCheck(container) {
  const resultsDiv = container.querySelector('#anchor-results');
  const input = container.querySelector('#receipt-input');

  container.querySelector('#check-anchor-btn').addEventListener('click', async () => {
    if (!importedEntries) {
      resultsDiv.innerHTML = statusLine(false, 'Import a chain JSON above first, then check it against the receipt.');
      return;
    }

    let receipt;
    try {
      receipt = await parseReceipt(input.value);
    } catch (err) {
      resultsDiv.innerHTML = statusLine(false, err.message);
      return;
    }

    try {
      const result = await checkAnchor(importedEntries, receipt);
      resultsDiv.innerHTML = html`
        ${statusLine(result.matches, result.matches ? 'ANCHOR CONFIRMED' : 'ANCHOR MISMATCH')}
        <div class="result-note spaced">${result.reason}</div>
      `;
    } catch (err) {
      resultsDiv.innerHTML = statusLine(false, `Could not check the anchor: ${err.message}`);
    }
  });
}

/**
 * Check anchors carried inside an imported export.
 *
 * Reported even when there are none: "this chain carries no anchors" is
 * information a reader needs, because it is the state in which trailing
 * entries can be removed with nothing to contradict it.
 */
async function checkEmbeddedAnchors(entries, anchors, chainResult) {
  if (!chainResult.intact) return '';

  if (!anchors || anchors.length === 0) {
    return html`
      <div class="result-note spaced">
        No anchors are included with this chain, so there is nothing to show that entries
        were not removed from the end.
      </div>
    `;
  }

  // Every anchor is checked, including any whose height exceeds this chain.
  // Those are not "irrelevant" — an anchor committing to entry 40 against a
  // chain that stops at 12 is precisely the evidence of a removed tail, and
  // skipping it would discard the one signal this feature exists to surface.
  const coverage = anchorCoverage(entries, anchors);
  const checks = [];
  for (const anchor of anchors) {
    let receipt;
    try {
      receipt = await parseReceipt(anchor.receipt);
    } catch (err) {
      checks.push({
        truncated: false,
        fragment: statusLine(false, `Anchor at entry ${anchor.seq + 1}: ${err.message}`, 'mt-12'),
      });
      continue;
    }
    const result = await checkAnchor(entries, receipt);
    checks.push({
      truncated: Boolean(result.truncated),
      fragment: html`
        ${statusLine(result.matches, `Anchor at entry ${receipt.seq + 1}: ${result.matches ? 'confirmed' : 'ENTRIES MISSING'}`, 'mt-12')}
        <div class="result-note">${result.reason}</div>
      `,
    });
  }

  const truncated = checks.some((c) => c.truncated);
  return html`
    <div class="mt-16">
      <div class="section-title mb-8">Anchors included with this chain</div>
      <div class="result-note">${truncated
        ? 'This chain no longer reaches a height it was anchored at — entries have been removed from the end.'
        : coverage.summary}</div>
      ${checks.map((c) => c.fragment)}
    </div>
  `;
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
  importedEntries = null;
  try {
    const text = await file.text();
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      resultsDiv.innerHTML = statusLine(false, 'Invalid JSON file.');
      return;
    }

    const envelope = readEnvelope(parsed);
    if (!envelope) {
      resultsDiv.innerHTML = statusLine(false, 'Expected a Beweiskette export or a JSON array of entries.');
      return;
    }

    const entries = envelope.chain;
    importedEntries = entries;
    const result = await verifyChain(entries);

    // Anchors travelling inside the export are checked without being asked
    // for. This is what lets a recipient detect a truncated tail when they
    // have never been sent a receipt.
    const embeddedAnchors = await checkEmbeddedAnchors(entries, envelope.anchors, result);

    let summary;
    if (result.intact) {
      summary = html`
        ${statusLine(true, `CHAIN INTACT — ${result.entries} entries verified`)}
        ${entries.length > 0 ? html`
          <div class="result-note spaced">
            Range: ${formatDate(entries[0].timestamp_registered)} — ${formatDate(entries[entries.length - 1].timestamp_registered)}
          </div>
          <div class="result-note">
            Head: <span class="mono">${result.headHash}</span>
          </div>
          <div class="result-note spaced">
            "Intact" means these ${result.entries} records are in order and unaltered. It does not
            show whether entries were removed from the end — check a published receipt below for that.
          </div>
        ` : ''}
      `;
    } else {
      summary = html`
        ${statusLine(false, `CHAIN BROKEN at entry ${result.brokenAt}`)}
        <div class="result-note spaced">${result.details}</div>
        ${result.brokenId ? html`
          <div class="result-note">ID: ${result.brokenId}</div>
        ` : ''}
      `;
    }

    const rows = entries.map((entry, i) => {
      const ok = result.intact || i + 1 < result.brokenAt;
      const fileName = entry && entry.evidence ? entry.evidence.file_name : `Entry ${i + 1}`;
      return html`
        <div class="verify-entry ${ok ? 'pass' : 'fail'}">
          <svg class="verify-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${ok ? ICON_PASS : ICON_FAIL}</svg>
          <span class="flex-1">${i + 1}. ${fileName}</span>
          <span class="mono-mini">${truncateHash(entry && entry.entry_hash)}</span>
        </div>
      `;
    });

    resultsDiv.innerHTML = html`
      <div class="verify-results">
        ${summary}
        ${embeddedAnchors}
        <div class="mt-16">
          <div class="section-title mb-8">Entry-by-entry verification</div>
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
      <div class="file-info mt-16">
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
        'mt-12',
      )}
    `;
  } catch {
    resultsDiv.innerHTML = statusLine(false, 'Failed to compute hash.');
  }
}
