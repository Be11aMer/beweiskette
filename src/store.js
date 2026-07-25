/**
 * IndexedDB persistence layer for Beweiskette.
 * Uses the raw IndexedDB API — no idb library.
 * Stores evidence entries only (no files — files are ephemeral, hashes are permanent).
 *
 * Ordering is by the entry's own `seq`, never by wall-clock time. Sorting a
 * chain by timestamp makes a backwards clock step (NTP correction, a
 * suspend/resume, a manual change) or two registrations inside the same
 * millisecond reorder the chain relative to its own links — which surfaces to
 * the user as CHAIN BROKEN on a chain nobody touched.
 */

import { GENESIS, SCHEMA_VERSION, checkAppend, nextConstraints } from './chain.js';

const DB_NAME = 'beweiskette';
const DB_VERSION = 2;
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
      const store = db.objectStoreNames.contains(STORE_NAME)
        ? event.target.transaction.objectStore(STORE_NAME)
        : db.createObjectStore(STORE_NAME, { keyPath: 'id' });

      if (!store.indexNames.contains('timestamp_registered')) {
        store.createIndex('timestamp_registered', 'timestamp_registered', { unique: false });
      }
      if (!store.indexNames.contains('case_reference')) {
        store.createIndex('case_reference', 'custody.case_reference', { unique: false });
      }
      // Unique, so two entries can never occupy the same height: a fork is
      // rejected by the storage engine rather than by convention.
      //
      // Records written under chain format v1 have no `seq` property and are
      // therefore absent from this index entirely. That is deliberate — it is
      // how v1 entries stay readable (see getLegacyEntries) without being
      // silently rewritten. Recomputing their hashes under v2 rules would be
      // indistinguishable from forging them.
      if (!store.indexNames.contains('seq')) {
        store.createIndex('seq', 'seq', { unique: true });
      }
    };

    request.onsuccess = (event) => {
      dbInstance = event.target.result;
      // Another tab requesting a version change must not be left hanging.
      dbInstance.onversionchange = () => {
        dbInstance.close();
        dbInstance = null;
      };
      dbInstance.onclose = () => { dbInstance = null; };
      resolve(dbInstance);
    };

    request.onerror = (event) => {
      reject(new Error('Failed to open database: ' + event.target.error));
    };

    request.onblocked = () => {
      reject(new Error('Database upgrade blocked by another open tab. Close other Beweiskette tabs and reload.'));
    };
  });
}

/**
 * Append an entry to the chain.
 *
 * The head is read and the new entry written inside a single readwrite
 * transaction, and the link is checked before the write is allowed. Reading
 * the head in one transaction and appending in another lets two tabs — or two
 * fast clicks — read the same head and both append, forking the chain.
 *
 * Resolves on tx.oncomplete rather than request.onsuccess: a request can
 * succeed and the transaction still abort (quota exhaustion, unexpected
 * termination), which previously reported "Evidence registered" for an entry
 * that was never committed.
 */
export function addEntry(entry) {
  return openDB().then((db) => new Promise((resolve, reject) => {
    let refusal = null;

    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    const headRequest = store.index('seq').openCursor(null, 'prev');

    headRequest.onsuccess = () => {
      const cursor = headRequest.result;
      const head = cursor ? cursor.value : null;

      const problem = checkAppend(head, entry);
      if (problem) {
        refusal = new Error(
          `Refusing to append: ${problem}. The chain head moved while this entry was being prepared — reload and register again.`,
        );
        tx.abort();
        return;
      }
      store.add(entry);
    };

    tx.oncomplete = () => resolve();
    tx.onabort = () => reject(refusal || tx.error || new Error('Append aborted.'));
    tx.onerror = () => reject(tx.error || new Error('Failed to add entry.'));
  }));
}

/** Read every request result from an index in ascending key order. */
function getAllByIndex(indexName) {
  return openDB().then((db) => new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const request = tx.objectStore(STORE_NAME).index(indexName).getAll();
    request.onsuccess = () => resolve(request.result || []);
    request.onerror = () => reject(new Error('Failed to read entries: ' + request.error));
  }));
}

/** All v2 entries in chain order. */
export function getAllEntries() {
  return getAllByIndex('seq');
}

/** The current chain head, or null if the chain is empty. */
export function getLastEntry() {
  return openDB().then((db) => new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const request = tx.objectStore(STORE_NAME).index('seq').openCursor(null, 'prev');
    request.onsuccess = () => resolve(request.result ? request.result.value : null);
    request.onerror = () => reject(new Error('Failed to read last entry: ' + request.error));
  }));
}

/**
 * What a new entry must claim in order to extend the chain.
 * Returns a fresh chain identity when the store is empty.
 */
export async function getChainState() {
  const head = await getLastEntry();
  const { seq, prevHash, chainId } = nextConstraints(head);
  return { chainId, nextSeq: seq, prevHash, count: head ? head.seq + 1 : 0 };
}

/**
 * Entries written under chain format v1, which this build can no longer
 * verify. Surfaced so they can be exported rather than quietly lost.
 */
export function getLegacyEntries() {
  return openDB().then((db) => new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const request = tx.objectStore(STORE_NAME).getAll();
    request.onsuccess = () => {
      const all = request.result || [];
      resolve(all.filter((e) => e && e.schema_version !== SCHEMA_VERSION));
    };
    request.onerror = () => reject(new Error('Failed to read legacy entries: ' + request.error));
  }));
}

/** Total entry count, including legacy entries. */
export function getEntryCount() {
  return openDB().then((db) => new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const request = tx.objectStore(STORE_NAME).count();
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error('Failed to count entries: ' + request.error));
  }));
}

/** Clear all entries from the store. */
export function clearAll() {
  return openDB().then((db) => new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).clear();
    tx.oncomplete = () => resolve();
    tx.onabort = () => reject(tx.error || new Error('Clear aborted.'));
    tx.onerror = () => reject(tx.error || new Error('Failed to clear store.'));
  }));
}

/**
 * Ask the browser to exempt this origin's storage from eviction.
 *
 * IndexedDB is not durable by default: Safari's ITP discards it after ~7 days
 * without interaction, and Chrome evicts under storage pressure. For a
 * custody log, silently losing the chain is the worst possible failure, so the
 * result is reported to the user rather than assumed.
 *
 * @returns {Promise<{persisted: boolean, supported: boolean}>}
 */
export async function requestPersistence() {
  if (!navigator.storage || !navigator.storage.persist) {
    return { persisted: false, supported: false };
  }
  try {
    const already = navigator.storage.persisted ? await navigator.storage.persisted() : false;
    const persisted = already || await navigator.storage.persist();
    return { persisted, supported: true };
  } catch {
    return { persisted: false, supported: true };
  }
}
