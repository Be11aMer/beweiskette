/**
 * Beweiskette — Main application shell.
 * Tab routing, initialization, toast notifications.
 */

import { openDB, requestPersistence } from './store.js';
import { html } from './utils.js';
import { render as renderRegister } from './ui/register.js';
import { render as renderChain } from './ui/chain-view.js';
import { render as renderVerify } from './ui/verify.js';
import { render as renderExport } from './ui/export.js';

const TABS = [
  { id: 'register', label: 'Register', render: renderRegister },
  { id: 'chain', label: 'Chain', render: renderChain },
  { id: 'verify', label: 'Verify', render: renderVerify },
  { id: 'export', label: 'Export', render: renderExport },
];

let currentTab = 'register';

async function init() {
  await openDB();
  renderTabs();
  navigateTo('register');
  reportStorageDurability();
}

/**
 * Tell the user if the browser may discard their chain.
 *
 * IndexedDB is not archival storage. Safari's ITP discards it after roughly a
 * week without interaction, Chrome evicts under storage pressure, and private
 * windows discard it on close. Silently losing a custody log is the worst
 * failure this app has, so when the browser declines to make storage
 * persistent the user is told to export rather than left to assume.
 */
async function reportStorageDurability() {
  const { persisted, supported } = await requestPersistence();
  if (persisted) return;

  const banner = document.createElement('div');
  banner.className = 'storage-warning';
  banner.innerHTML = html`
    <span>
      ${supported
        ? 'This browser has not granted persistent storage, so it may discard this chain to reclaim space.'
        : 'This browser cannot guarantee persistent storage, so it may discard this chain.'}
      Export your chain regularly and keep the exported file as the record.
    </span>
    <button class="banner-dismiss" type="button" aria-label="Dismiss">&times;</button>
  `;
  banner.querySelector('.banner-dismiss').addEventListener('click', () => banner.remove());
  document.getElementById('app').insertBefore(banner, document.getElementById('view-container'));
}

function renderTabs() {
  const nav = document.getElementById('tab-nav');
  nav.innerHTML = '';

  for (const tab of TABS) {
    const btn = document.createElement('button');
    btn.className = 'tab-btn';
    btn.textContent = tab.label;
    btn.dataset.tab = tab.id;
    btn.id = `tab-${tab.id}`;
    btn.addEventListener('click', () => navigateTo(tab.id));
    nav.appendChild(btn);
  }
}

export function navigateTo(tabId) {
  const tab = TABS.find(t => t.id === tabId);
  if (!tab) return;

  currentTab = tabId;

  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tabId);
  });

  const container = document.getElementById('view-container');
  container.innerHTML = '';
  tab.render(container);
}

export function showToast(message, isError = false) {
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.className = `toast${isError ? ' error' : ''}`;
  toast.textContent = message;
  document.body.appendChild(toast);

  setTimeout(() => {
    if (toast.parentNode) toast.remove();
  }, 3000);
}

init();
