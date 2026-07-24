/**
 * Export view — export chain as JSON, CSV, or self-contained HTML report.
 */

import { getAllEntries, clearAll } from '../store.js';
import { html } from '../utils.js';
import { generateCSV, generateHTMLReport } from '../report.js';
import { showToast } from '../main.js';

let selectedFormat = 'json';

export async function render(container) {
  const entries = await getAllEntries();
  selectedFormat = 'json';

  container.innerHTML = html`
    <div class="section-header">
      <span class="section-title">Export Evidence Chain</span>
      <span class="status-badge empty">
        <span class="status-dot"></span>
        ${entries.length} ${entries.length === 1 ? 'entry' : 'entries'}
      </span>
    </div>

    ${entries.length === 0 ? html`
      <div class="empty-state">
        <svg class="empty-state-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        <p class="empty-state-text">Nothing to export</p>
        <p class="empty-state-hint">Register evidence first, then export your chain.</p>
      </div>
    ` : html`
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
          <div class="export-option-desc">Spreadsheet summary — not verifiable</div>
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

  // The chain is append-only by construction — there is no API to edit or
  // remove a single entry — but wholesale destruction is still one click away,
  // and it is irreversible. A single confirm() is too thin a barrier in front
  // of an evidence log, so this asks for the word to be typed and nudges
  // toward exporting first.
  container.querySelector('#clear-all-btn').addEventListener('click', async () => {
    const typed = prompt(
      `This permanently deletes all ${entries.length} entries from this browser. `
      + 'It cannot be undone, and any chain you have not exported is lost — '
      + 'exported files are unaffected.\n\n'
      + 'Export first if you have not already.\n\n'
      + 'Type DELETE to confirm:',
    );
    if (typed === null) return;
    if (typed.trim() !== 'DELETE') {
      showToast('Not deleted — confirmation did not match.', true);
      return;
    }
    try {
      await clearAll();
      showToast(`Deleted ${entries.length} entries.`);
      render(container);
    } catch (err) {
      showToast(`Could not clear the store: ${err.message}`, true);
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
