/**
 * IndexedDB persistence layer for Beweiskette.
 * Uses the raw IndexedDB API — no idb library.
 * Stores evidence entries only (no files — files are ephemeral, hashes are permanent).
 */

const DB_NAME = 'beweiskette';
const DB_VERSION = 1;
const STORE_NAME = 'entries';

let dbInstance = null;

/**
 * Open (or create) the IndexedDB database.
 * Returns a cached instance on subsequent calls.
 */
export function openDB() {
  if (dbInstance) return Promise.resolve(dbInstance);

  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        const store = db.createObjectStore(STORE_NAME, { keyPath: 'id' });
        store.createIndex('timestamp_registered', 'timestamp_registered', { unique: false });
        store.createIndex('case_reference', 'custody.case_reference', { unique: false });
      }
    };

    request.onsuccess = (event) => {
      dbInstance = event.target.result;
      resolve(dbInstance);
    };

    request.onerror = (event) => {
      reject(new Error('Failed to open database: ' + event.target.error));
    };
  });
}

/**
 * Add a single entry to the store.
 */
export async function addEntry(entry) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    const request = store.add(entry);
    request.onsuccess = () => resolve();
    request.onerror = (event) => reject(new Error('Failed to add entry: ' + event.target.error));
  });
}

/**
 * Get all entries ordered by timestamp_registered.
 */
export async function getAllEntries() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);
    const index = store.index('timestamp_registered');
    const request = index.getAll();
    request.onsuccess = () => resolve(request.result || []);
    request.onerror = (event) => reject(new Error('Failed to read entries: ' + event.target.error));
  });
}

/**
 * Get the last entry by timestamp (most recent).
 */
export async function getLastEntry() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);
    const index = store.index('timestamp_registered');
    const request = index.openCursor(null, 'prev');
    request.onsuccess = (event) => {
      const cursor = event.target.result;
      resolve(cursor ? cursor.value : null);
    };
    request.onerror = (event) => reject(new Error('Failed to read last entry: ' + event.target.error));
  });
}

/**
 * Get total entry count.
 */
export async function getEntryCount() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);
    const request = store.count();
    request.onsuccess = () => resolve(request.result);
    request.onerror = (event) => reject(new Error('Failed to count entries: ' + event.target.error));
  });
}

/**
 * Clear all entries from the store.
 */
export async function clearAll() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    const request = store.clear();
    request.onsuccess = () => resolve();
    request.onerror = (event) => reject(new Error('Failed to clear store: ' + event.target.error));
  });
}
