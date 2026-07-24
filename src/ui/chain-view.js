/**
 * Chain View — timeline of all evidence entries with chain integrity status.
 */

import { getAllEntries } from '../store.js';
import { verifyChain } from '../chain.js';
import { formatDate, truncateHash, formatFileSize, html } from '../utils.js';

export async function render(container) {
  const entries = await getAllEntries();
  const verification = await verifyChain(entries);

  if (entries.length === 0) {
    container.innerHTML = html`
      <div class="empty-state">
        <svg class="empty-state-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
          <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
        </svg>
        <p class="empty-state-text">No evidence registered yet</p>
        <p class="empty-state-hint">Switch to the Register tab to add your first piece of evidence.</p>
      </div>
    `;
    return;
  }

  const statusClass = verification.intact ? 'intact' : 'broken';
  const statusText = verification.intact ? 'Chain Intact' : 'Chain Broken';
  const firstDate = formatDate(entries[0].timestamp_registered);
  const lastDate = formatDate(entries[entries.length - 1].timestamp_registered);

  const reversed = [...entries].reverse();
  const entryFragments = reversed.map((entry, i) => {
    const originalIndex = entries.length - 1 - i;
    const entryClass = verification.intact || (verification.brokenAt && originalIndex + 1 < verification.brokenAt)
      ? 'verified' : (verification.brokenAt && originalIndex + 1 === verification.brokenAt ? 'broken' : '');

    const exifFields = [];
    if (entry.metadata) {
      if (entry.metadata.datetime_original || entry.metadata.datetime) {
        exifFields.push(['EXIF Date', entry.metadata.datetime_original || entry.metadata.datetime]);
      }
      if (entry.metadata.camera_make || entry.metadata.camera_model) {
        exifFields.push(['Camera', [entry.metadata.camera_make, entry.metadata.camera_model].filter(Boolean).join(' ')]);
      }
      if (entry.metadata.gps_lat !== undefined && entry.metadata.gps_lng !== undefined) {
        exifFields.push(['GPS', `${entry.metadata.gps_lat}, ${entry.metadata.gps_lng}`]);
      }
    }

    return html`
      <div class="chain-entry ${entryClass}">
        <div class="card">
          <div class="entry-meta">
            <span class="entry-filename">${entry.evidence.file_name}</span>
            <span class="entry-timestamp">${formatDate(entry.timestamp_registered)}</span>
          </div>
          <span class="entry-hash" data-hash="${entry.entry_hash}" title="Click to copy full hash">
            ${truncateHash(entry.entry_hash)}
            <button class="copy-btn" aria-label="Copy hash">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
              </svg>
            </button>
          </span>
          <div class="entry-details">
            <div>
              <div class="entry-detail-label">Custodian</div>
              <div class="entry-detail-value">${entry.custody.custodian}</div>
            </div>
            <div>
              <div class="entry-detail-label">File Size</div>
              <div class="entry-detail-value">${formatFileSize(entry.evidence.file_size)}</div>
            </div>
            ${entry.custody.case_reference ? html`
              <div>
                <div class="entry-detail-label">Case Ref</div>
                <div class="entry-detail-value">${entry.custody.case_reference}</div>
              </div>
            ` : ''}
            <div>
              <div class="entry-detail-label">File Type</div>
              <div class="entry-detail-value">${entry.evidence.file_type}</div>
            </div>
            ${exifFields.map(([label, value]) => html`
              <div>
                <div class="entry-detail-label">${label}</div>
                <div class="entry-detail-value">${String(value)}</div>
              </div>
            `)}
            ${entry.custody.notes ? html`
              <div class="entry-notes">"${entry.custody.notes}"</div>
            ` : ''}
          </div>
        </div>
      </div>
    `;
  });

  container.innerHTML = html`
    <div class="section-header">
      <span class="status-badge ${statusClass}">
        <span class="status-dot"></span>
        ${statusText}
      </span>
      <span class="section-title">${entries.length} ${entries.length === 1 ? 'entry' : 'entries'}</span>
    </div>
    <div style="font-size:0.78rem;color:var(--text-muted);margin-bottom:24px">
      ${firstDate} — ${lastDate}
    </div>
    <div class="chain-timeline">${entryFragments}</div>
  `;

  const COPY_ICON = html`
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
    </svg>
  `;
  const CHECK_ICON = html`
    <svg viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M20 6L9 17l-5-5"/>
    </svg>
  `;

  container.querySelectorAll('.entry-hash').forEach(el => {
    el.addEventListener('click', () => {
      const btn = el.querySelector('.copy-btn');
      navigator.clipboard.writeText(el.dataset.hash).then(() => {
        btn.innerHTML = CHECK_ICON;
        setTimeout(() => { btn.innerHTML = COPY_ICON; }, 1500);
      });
    });
  });
}
