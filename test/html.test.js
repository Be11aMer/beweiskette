/**
 * Escaping tests for the `html` tagged template.
 *
 * The attack these defend against is specific to this tool: the Verify view
 * renders a chain JSON supplied by a counterparty. Script execution on this
 * origin grants IndexedDB write access plus the page's own computeEntryHash —
 * everything needed to rewrite the victim's chain into a forgery that still
 * verifies as INTACT.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { html, raw, escapeHTML, sanitizeText } from '../src/utils.js';

test('escapeHTML neutralizes every markup-significant character', () => {
  assert.equal(escapeHTML('<script>'), '&lt;script&gt;');
  assert.equal(escapeHTML('a & b'), 'a &amp; b');
  assert.equal(escapeHTML('"quoted"'), '&quot;quoted&quot;');
  assert.equal(escapeHTML("'quoted'"), '&#39;quoted&#39;');
  // Ampersand must be escaped first, or the other replacements get mangled.
  assert.equal(escapeHTML('&lt;'), '&amp;lt;');
});

test('interpolated values are escaped by default', () => {
  const name = '<img src=x onerror=alert(1)>';
  const out = String(html`<span>${name}</span>`);
  assert.equal(out, '<span>&lt;img src=x onerror=alert(1)&gt;</span>');
  assert.ok(!out.includes('<img'));
});

test('static template text is left alone', () => {
  // Inline SVG and structural markup authored in this repo must survive.
  const out = String(html`<svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10"/></svg>`);
  assert.ok(out.includes('<svg viewBox="0 0 24 24">'));
  assert.ok(out.includes('<path d="M12 22s8-4 8-10"/>'));
});

test('attribute contexts cannot be broken out of', () => {
  const evil = '" onmouseover="alert(1)';
  const out = String(html`<span data-hash="${evil}">x</span>`);
  assert.ok(!out.includes('onmouseover="alert'));
  assert.equal(out, '<span data-hash="&quot; onmouseover=&quot;alert(1)">x</span>');

  const single = "' onmouseover='alert(1)";
  const out2 = String(html`<span data-hash='${single}'>x</span>`);
  assert.ok(!out2.includes("onmouseover='alert"));
});

test('nested html fragments compose without double-escaping', () => {
  const inner = html`<b>${'<evil>'}</b>`;
  const outer = String(html`<div>${inner}</div>`);
  assert.equal(outer, '<div><b>&lt;evil&gt;</b></div>');
});

test('arrays of fragments are joined without double-escaping', () => {
  const rows = ['<a>', '<b>'].map((v) => html`<li>${v}</li>`);
  assert.equal(String(html`<ul>${rows}</ul>`), '<ul><li>&lt;a&gt;</li><li>&lt;b&gt;</li></ul>');
});

test('a plain string of markup is escaped even if it looks like a fragment', () => {
  // The failure mode this guards: calling .join('') on an array of fragments
  // collapses them to a plain string, which must then be treated as untrusted.
  const collapsed = ['<li>ok</li>', '<li>ok</li>'].join('');
  assert.ok(!String(html`<ul>${collapsed}</ul>`).includes('<li>'));
});

test('null, undefined and false render as empty', () => {
  assert.equal(String(html`a${null}b${undefined}c${false}d`), 'abcd');
});

test('raw() opts a value out of escaping', () => {
  assert.equal(String(html`<div>${raw('<hr>')}</div>`), '<div><hr></div>');
});

test('numbers and booleans interpolate as text', () => {
  assert.equal(String(html`<b>${42}</b>`), '<b>42</b>');
  assert.equal(String(html`<b>${true}</b>`), '<b>true</b>');
});

test('sanitizeText strips control characters', () => {
  assert.equal(sanitizeText('a\x00b\x1fc\x7fd'), 'abcd');
  assert.equal(sanitizeText('keep\ttab\nnewline'), 'keep\ttab\nnewline');
});

test('sanitizeText strips bidi override and isolate characters', () => {
  // A custodian name that renders differently than it is stored would let a
  // reviewer and the hash disagree about what the record says.
  const spoofed = 'alice\u202egnp.exe';
  assert.equal(sanitizeText(spoofed), 'alicegnp.exe');
  for (const cp of [0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069]) {
    assert.equal(sanitizeText(`x${String.fromCharCode(cp)}y`), 'xy');
  }
});

test('sanitizeText returns empty string for non-strings', () => {
  for (const v of [null, undefined, 42, {}, []]) {
    assert.equal(sanitizeText(v), '');
  }
});
