/**
 * Chain View — timeline of all evidence entries with chain integrity status.
 */

import { getAllEntries, getAnchors, putAnchor } from '../store.js';
import { verifyChain } from '../chain.js';
import { buildReceipt, formatReceipt, createAnchorRecord, anchorCoverage, encodeToken, decodeToken, ANCHOR_METHOD } from '../anchor.js';
import { requestTimestamp, verifyToken, VERDICT } from '../rfc3161.js';
import { getTsaSettings } from '../settings.js';
import { formatDate, truncateHash, formatFileSize, html } from '../utils.js';
import { showToast } from '../main.js';

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

  // Only an intact chain can be anchored; anchoring a broken one is meaningless.
  let receipt = null;
  let receiptText = null;
  if (verification.intact) {
    try {
      receipt = await buildReceipt(entries);
      receiptText = formatReceipt(receipt);
    } catch {
      receipt = null;
    }
  }

  const anchors = await getAnchors();
  const coverage = anchorCoverage(entries, anchors);

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
    <div class="chain-range">
      ${firstDate} — ${lastDate}
    </div>
    ${receiptText ? html`
      <div class="receipt-panel">
        <div class="receipt-header">
          <span class="section-title">Head Receipt</span>
          <button class="btn btn-secondary btn-small" id="copy-receipt-btn">Copy</button>
        </div>
        <p class="receipt-hint">
          Publish this somewhere you do not control the timeline of — a git commit, a dated
          email, a public post, a timestamping authority. The chain proves the order of these
          records; a published receipt is what proves they existed by a given moment, and is
          the only thing that reveals entries removed from the end.
        </p>
        <pre class="receipt-block">${receiptText}</pre>
        <div class="receipt-coverage">${coverage.summary}</div>
        <div class="btn-group">
          <button class="btn btn-secondary btn-small" id="timestamp-btn">Timestamp with an authority…</button>
        </div>
        <div id="timestamp-result"></div>

        <div class="mt-12">
          <label class="form-label" for="token-input">Or paste a timestamp token</label>
          <p class="receipt-hint">
            A browser can only reach an authority that sends CORS headers, and most do not —
            they are built for server-side clients, so the request above fails against them.
            That is a property of the authority, not of your chain. Timestamp this receipt with
            <span class="mono">openssl ts</span> (see docs/ANCHORING.md) and paste the base64
            token here: it is checked exactly as one fetched directly would be.
          </p>
          <textarea class="form-textarea mono-input" id="token-input" rows="4"
            placeholder="base64 of a .tsr TimeStampResp or a bare TimeStampToken"></textarea>
          <div class="btn-group mt-12">
            <button class="btn btn-secondary btn-small" id="import-token-btn">Verify and store token</button>
          </div>
          <div id="import-token-result"></div>
        </div>
      </div>
    ` : ''}
    <div class="chain-timeline">${entryFragments}</div>
  `;

  const copyReceiptBtn = container.querySelector('#copy-receipt-btn');
  if (copyReceiptBtn) {
    copyReceiptBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(receiptText)
        .then(() => showToast('Receipt copied — publish it somewhere durable.'))
        .catch(() => showToast('Could not copy. Select the text manually.', true));
    });
  }

  const timestampBtn = container.querySelector('#timestamp-btn');
  if (timestampBtn) {
    timestampBtn.addEventListener('click', () => requestAndStoreTimestamp(receipt, container));
  }

  const importTokenBtn = container.querySelector('#import-token-btn');
  if (importTokenBtn) {
    importTokenBtn.addEventListener('click', () => importAndStoreToken(receipt, container));
  }

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

/**
 * Ask a timestamp authority to sign the current head.
 *
 * The only outbound request the application makes. What will be sent is stated
 * before it is sent, because "client-side only" is the property people choose
 * this tool for — quietly making a network call would break the promise even
 * though the payload is harmless.
 */
async function requestAndStoreTimestamp(receipt, container) {
  const resultDiv = container.querySelector('#timestamp-result');
  const settings = getTsaSettings();

  if (!settings.url) {
    resultDiv.innerHTML = html`
      <div class="result-note spaced">
        No timestamp authority is configured. Add one under Export → Settings, along with its
        certificate, so its signature can actually be checked.
      </div>
    `;
    return;
  }

  const consented = confirm(
    'Send a timestamp request?\n\n'
    + `To: ${settings.url}\n`
    + `Sends: the 32-byte SHA-256 of your chain head (${receipt.head_hash.slice(0, 16)}…)\n\n`
    + 'No file contents, file names, custody details or metadata are transmitted. '
    + 'The authority learns only that something was timestamped.\n\n'
    + 'This is the only network request this application makes.\n\n'
    + 'Note: a browser can only reach an authority that sends CORS headers, and most '
    + 'do not — they are built for server-side clients. If this fails, that is the '
    + 'authority, not your chain: timestamp the head receipt with `openssl ts` instead '
    + '(docs/ANCHORING.md) and paste the token back in. It verifies identically.',
  );
  if (!consented) return;

  resultDiv.innerHTML = html`<div class="result-note spaced">Requesting a timestamp…</div>`;

  try {
    const digest = hexToBytes(receipt.head_hash);
    const { token, nonce } = await requestTimestamp(settings.url, digest);

    const result = await verifyToken(token, {
      expectedDigest: digest,
      pinnedSpki: settings.pins,
      expectedNonce: nonce,
    });

    await storeAndReport(receipt, token, result, resultDiv);
  } catch (err) {
    resultDiv.innerHTML = html`
      <div class="verify-entry fail mt-12">Could not obtain a timestamp</div>
      <div class="result-note">${err.message}</div>
    `;
  }
}

/**
 * Verify a token the user obtained elsewhere and record it as an anchor.
 *
 * This path exists because the direct request usually cannot work. An RFC 3161
 * request must carry Content-Type: application/timestamp-query, which is not
 * CORS-safelisted, so the browser preflights it — and timestamp authorities are
 * built for server-side callers and generally answer no preflight at all. That
 * blocks every browser, not just this one.
 *
 * Fetching the token was never the part carrying the security value. The
 * verification is, and it is identical here: same message-imprint binding, same
 * signed attributes, same pinned-key signature check. Without this path that
 * verifier would be unreachable in production, which would make the whole
 * RFC 3161 implementation decorative.
 *
 * No nonce is expected. A token minted by `openssl ts` carries a nonce this
 * page never saw, so there is nothing to compare it against — and a token that
 * predates the paste is exactly what is wanted. Replay is not a threat here:
 * the token is bound to the head hash, and a token for a *different* head is
 * caught by the imprint check.
 */
async function importAndStoreToken(receipt, container) {
  const resultDiv = container.querySelector('#import-token-result');
  const input = container.querySelector('#token-input');
  const settings = getTsaSettings();

  if (!String(input.value || '').trim()) {
    resultDiv.innerHTML = html`
      <div class="result-note spaced">Paste a base64 token first.</div>
    `;
    return;
  }

  // decodeToken tolerates wrapped lines and PEM armour — see src/anchor.js.
  const token = decodeToken(input.value);
  if (!token || token.length === 0) {
    resultDiv.innerHTML = html`
      <div class="verify-entry fail mt-12">Not valid base64</div>
      <div class="result-note">
        Expected the base64 of a DER timestamp response — for example the output of
        <span class="mono">base64 -w0 token.tsr</span>.
      </div>
    `;
    return;
  }

  try {
    const digest = hexToBytes(receipt.head_hash);
    const result = await verifyToken(token, {
      expectedDigest: digest,
      pinnedSpki: settings.pins,
    });

    await storeAndReport(receipt, token, result, resultDiv);
    if (result.verdict !== VERDICT.INVALID) input.value = '';
  } catch (err) {
    resultDiv.innerHTML = html`
      <div class="verify-entry fail mt-12">Could not read the token</div>
      <div class="result-note">${err.message}</div>
    `;
  }
}

/**
 * Record a verified-or-unverified token and say which it was.
 *
 * INVALID is not stored. UNVERIFIED is, and is labelled as such — "could not be
 * checked" is a state worth keeping, because the token may become checkable
 * later once its signer is pinned. Collapsing it into either neighbour would
 * throw that away.
 */
async function storeAndReport(receipt, token, result, resultDiv) {
  if (result.verdict === VERDICT.INVALID) {
    resultDiv.innerHTML = html`
      <div class="verify-entry fail mt-12">Timestamp rejected</div>
      <div class="result-note">${result.reason}</div>
    `;
    return;
  }

  await putAnchor(createAnchorRecord({
    receipt,
    method: ANCHOR_METHOD.TSA,
    token: encodeToken(token),
    genTime: result.genTime,
    status: result.verdict,
  }));

  const verified = result.verdict === VERDICT.VERIFIED;
  resultDiv.innerHTML = html`
    <div class="verify-entry ${verified ? 'pass' : 'fail'} mt-12">
      ${verified ? 'Timestamp verified and stored' : 'Timestamp stored, but NOT verified'}
    </div>
    <div class="result-note">${result.reason}</div>
    ${verified ? '' : html`
      <div class="result-note">
        Signer key: <span class="mono">${result.signerSpkiSha256 || 'unknown'}</span>.
        Pin it under Export → Settings only after confirming it belongs to the authority
        you intended, from a source other than the response itself.
      </div>
    `}
  `;
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
