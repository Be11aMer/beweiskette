# Threat Model

What Beweiskette proves, what it does not, and who it protects against.

Read this before relying on the tool for anything that matters. Most of the
value in a chain-of-custody tool comes from knowing exactly where its
guarantees stop.

## The short version

Beweiskette produces a **tamper-evident sequence of records**. Given a chain
you already hold, it detects whether any record was altered, reordered, or
removed from the middle.

On its own it does **not** prove when anything happened, does **not** prove a
chain is complete, and does **not** prove that the recorded facts are true.

With an anchor — a published receipt, or an RFC 3161 token signed by a
timestamp authority — it additionally proves the chain existed in a specific
state no later than a specific moment. With a beacon pulse recorded in an
entry, it proves that entry was made no earlier than a specific moment. Between
the two, an entry is bracketed rather than merely bounded.

## The assets

1. **The evidence files themselves.** Never transmitted, never stored by the
   app. Only their SHA-256 digests are recorded.
2. **The chain** — the ordered record of what was registered, by whom, when,
   and with what notes. Held in browser IndexedDB and in exported files.
3. **The integrity claim** — the assertion, to a third party, that this chain
   has not been altered since it was made.

## The adversaries

| | Capability | Covered? |
|---|---|---|
| **A. Later editor** | Can read and write the exported chain file, or the browser's IndexedDB, *after* records were made. Wants to change or remove a record. | **Yes**, for modification and mid-chain removal. **Only with an anchor** for tail truncation. |
| **B. Malicious counterparty** | Sends you a chain file to verify. Wants to make a forged chain look genuine, or to attack your machine through the verifier. | **Partly.** Injection is blocked. A wholly fabricated chain is indistinguishable from a genuine one without an anchor you trust. |
| **C. Dishonest author** | Controls the machine and the clock at the time of registration. Wants to produce a chain that looks like it was made earlier, or that records false facts. | **No**, unless anchored. This is the fundamental limit. |
| **D. Network attacker** | Sits between you and the app's origin, or between you and a timestamp authority. | **Partly.** Serve over HTTPS. Timestamp requests go over https only and carry a digest, and the returned token is verified against a pinned key — so a network attacker cannot substitute a token that verifies. |
| **E. Local malware** | Runs code on your machine while you use the app. | **No.** It can rewrite the chain and recompute valid hashes using the page's own code. |

## What is guaranteed

**Content integrity.** Every entry commits, via SHA-256, to a canonical
encoding of its own contents plus the previous entry's hash. Changing any
byte of any past entry changes its `entry_hash`, which breaks the link every
later entry depends on. Verification recomputes every hash rather than
comparing stored values.

**Ordering.** Each entry carries an explicit `seq`, covered by the digest.
Reordering entries, or deleting one from the middle, is detected directly —
not inferred from whatever order the storage layer happened to return.

**Chain identity.** Each entry carries a `chain_id`. Entries from two separate
chains cannot be spliced into one file that verifies.

**Format identity.** Each entry carries a `schema_version`, so a future change
to the encoding is detectable rather than silently invalidating old chains.

**Locality.** Files are read in the browser and hashed with the Web Crypto
API. File contents are never uploaded. There is no server, no analytics and no
telemetry, and the app makes no network request on its own.

The single exception is deliberate and user-initiated: requesting a trusted
timestamp sends the 32-byte SHA-256 of your chain head, and nothing else, to
the authority you configured. It states what it will send before sending it.
A digest reveals nothing about the file it came from, so the authority learns
only that something was timestamped.

**Rendering safety.** All values from an imported chain are HTML-escaped by
default via an auto-escaping template. This matters because verifying a
counterparty's chain means rendering their data: script execution on this
origin would grant an attacker IndexedDB write access *plus* the page's own
hashing code — everything needed to rewrite your chain into a forgery that
still verifies.

## What is not guaranteed

### Time

`timestamp_registered` comes from the registering machine's clock. Whoever
makes the records controls that clock. A chain dated last year is
indistinguishable from one built this morning on a back-dated laptop.

**Mitigation:** obtain an RFC 3161 timestamp, or publish an anchor receipt. A
timestamp token is signed by the authority, so it is checkable by someone who
does not trust you — which is the whole point, and why fetching the time from
an unsigned API would add nothing. A beacon pulse in a v3 entry's `time_bound`
supplies the other side of the bound. See [ANCHORING.md](ANCHORING.md).

Note the trust model: the app verifies tokens against **pinned** signer keys
rather than building an X.509 path to a root store. That is a narrower claim
than a browser's TLS verification, and it is deliberate — a partial path
implementation that reports "valid" would be worse than none. Confirm
independently with `openssl ts -verify`.

### Completeness

Delete the last three entries from an exported chain and the rest still links
correctly, hashes correctly, and reports CHAIN INTACT. Nothing inside the file
commits to how long it was supposed to be. For a custody log this is the
sharpest limitation: the easiest way to make an inconvenient record disappear
is to stop the story early.

**Mitigation:** anchor, and check against it. Anchors now travel inside the
export, so a recipient detects a truncated tail without having been sent a
receipt beforehand — previously the only way to catch it.

**The limit, stated plainly:** an attacker who truncates can strip the embedded
anchors too. What this buys is that stripping is *conspicuous* — a chain with
no anchors, or anchors stopping well short of the head, is visibly wrong, and
the app reports that state rather than staying silent. The only hard guarantee
remains a verifier holding an independently published anchor. Defence in depth,
not a proof.

### Authenticity of the chain as a whole

There are no signatures. The construction is published and the algorithm ships
in every exported report, so anyone can generate a complete, internally valid
chain with any contents and any timestamps. "CHAIN INTACT" means *this file is
internally consistent* — not *this file is genuine*.

**Mitigation:** an anchor published somewhere the author does not control the
timeline of. Without one, a chain is only as trustworthy as the person handing
it to you.

### Truth of the recorded facts

The tool records what it is told. A custodian name, a case reference and a
note are free text, asserted by whoever typed them. Registering a file proves
that file existed in that state at registration time — nothing about where it
came from, who really handled it, or whether the description is honest. An
anchor faithfully proves that a false record existed by a given time.

### Anything before registration

The chain begins when a file is registered. It says nothing about the file's
provenance beforehand — whether it was already modified, fabricated, or
selectively chosen. EXIF metadata is extracted from the file and is
attacker-controlled: a camera model or GPS coordinate is a claim made by the
file, faithfully recorded, not an independently verified fact.

### Durability of browser storage

IndexedDB is not archival storage. Safari's ITP discards it after roughly
seven days without interaction; Chrome evicts under storage pressure; private
windows discard it on close; clearing site data removes it. The app requests
persistent storage and reports whether it was granted, but the browser decides.

**Mitigation:** export regularly. Treat the browser as a working copy and
exported files as the record.

### Deletion

"Clear All Data" wipes the store. The chain is append-only by construction —
there is no API to edit or remove a single entry — but nothing prevents
destroying it wholesale, and browser storage can be cleared outside the app
entirely. Append-only is a property of the *format*, not a durability
guarantee.

## Notes on specific claims

**"Constant-time comparison."** `constantTimeEqual` compares hashes with a
loop that does not exit early. It is applied consistently, and it costs
nothing — but it should not be read as a meaningful defence here. There is no
secret: both operands are already public, sitting in IndexedDB, in the
exported JSON, and rendered into the DOM. There is also no attacker positioned
to measure timing, and JavaScript cannot guarantee constant-time execution in
any case — string representation changes indexing cost and the JIT is
unconstrained. It is hygiene, not a security property.

**"Client-side only."** True, and verifiable: there is no network code after
page load. Serve over HTTPS anyway — an attacker who can modify the delivered
JavaScript controls everything.

**CSV export** is a lossy summary. It omits EXIF metadata, so a CSV
**cannot be re-verified**. Use the JSON or HTML export as the record.

## Reporting a problem

See [SECURITY.md](../SECURITY.md).
