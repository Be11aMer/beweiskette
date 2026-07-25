/**
 * Append rules — the fork-prevention check applied inside the storage layer's
 * readwrite transaction.
 *
 * Under v1 the chain head was selected by maximum wall-clock timestamp and
 * read in a separate transaction from the write. A backwards clock step, two
 * registrations in the same millisecond, or two open tabs could each produce a
 * second entry claiming the same predecessor. The chain forked, and because
 * entries were then returned in timestamp order, verification reported CHAIN
 * BROKEN on a chain nobody had tampered with.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { checkAppend, nextConstraints, createEntry, createChainId, GENESIS } from '../src/chain.js';

function makeEntry({ seq, prevHash, chainId }) {
  return { seq, prev_hash: prevHash, chain_id: chainId };
}

test('an empty chain expects seq 0 linked to GENESIS', () => {
  assert.deepEqual(nextConstraints(null), { seq: 0, prevHash: GENESIS, chainId: null });
});

test('a non-empty chain expects the next height and the head hash', () => {
  const head = { seq: 4, entry_hash: 'ab'.repeat(32), chain_id: 'chain-a' };
  assert.deepEqual(nextConstraints(head), {
    seq: 5,
    prevHash: 'ab'.repeat(32),
    chainId: 'chain-a',
  });
});

test('the first entry of a chain is accepted', () => {
  assert.equal(checkAppend(null, makeEntry({ seq: 0, prevHash: GENESIS, chainId: 'c' })), null);
});

test('a correctly linked successor is accepted', () => {
  const head = { seq: 0, entry_hash: 'cd'.repeat(32), chain_id: 'c' };
  assert.equal(checkAppend(head, makeEntry({ seq: 1, prevHash: 'cd'.repeat(32), chainId: 'c' })), null);
});

test('a second entry claiming the same height is refused', () => {
  // Two tabs, or two fast clicks, both reading the same head.
  const head = { seq: 0, entry_hash: 'cd'.repeat(32), chain_id: 'c' };
  const forked = makeEntry({ seq: 0, prevHash: GENESIS, chainId: 'c' });
  assert.match(checkAppend(head, forked), /expected seq 1/);
});

test('an entry linking to a stale head is refused', () => {
  const head = { seq: 1, entry_hash: 'ef'.repeat(32), chain_id: 'c' };
  const stale = makeEntry({ seq: 2, prevHash: 'cd'.repeat(32), chainId: 'c' });
  assert.match(checkAppend(head, stale), /prev_hash/);
});

test('an entry from another chain is refused', () => {
  const head = { seq: 0, entry_hash: 'cd'.repeat(32), chain_id: 'chain-a' };
  const foreign = makeEntry({ seq: 1, prevHash: 'cd'.repeat(32), chainId: 'chain-b' });
  assert.match(checkAppend(head, foreign), /different chain/);
});

test('the first entry of a chain may declare any chain_id', () => {
  assert.equal(checkAppend(null, makeEntry({ seq: 0, prevHash: GENESIS, chainId: 'brand-new' })), null);
});

test('a backwards clock step does not affect appendability', async () => {
  // The v1 failure: head selection depended on timestamps, so an entry
  // recorded with an earlier timestamp than its own predecessor forked the
  // chain. Ordering is now a property of seq alone.
  const chainId = createChainId();
  const evidence = {
    file_hash: '00'.repeat(32),
    file_name: 'a.bin',
    file_size: 1,
    file_type: 'application/octet-stream',
    file_last_modified: '2026-01-01T00:00:00.000Z',
  };
  const custody = { custodian: 'X', case_reference: '', notes: '' };

  const first = await createEntry({ evidence, metadata: null, custody, prevHash: GENESIS, seq: 0, chainId });
  const second = await createEntry({
    evidence, metadata: null, custody, prevHash: first.entry_hash, seq: 1, chainId,
  });
  // Simulate the clock jumping backwards between the two registrations.
  second.timestamp_registered = '2020-01-01T00:00:00.000Z';

  assert.equal(checkAppend(first, second), null);
});
