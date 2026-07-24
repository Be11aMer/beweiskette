/**
 * Beweiskette — Main application shell.
 * Tab routing, initialization, toast notifications.
 */

import { openDB } from './store.js';
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
