# Anchoring

A hash chain proves that records were built in the order they claim and have
not been altered since. On its own it proves nothing about *when* they were
made, and nothing about whether records were removed from the end.

Anchoring closes both gaps. It costs one copy-paste.

## Why the chain alone is not enough

Two limitations follow from the same fact — nothing outside the file commits
to it.

**Timestamps are self-asserted.** `timestamp_registered` is read from the
registering machine's clock. Whoever made the records controls that clock.
A chain dated last year is indistinguishable from one built this morning on a
back-dated laptop, and the algorithm that builds it ships in every exported
report.

**Truncation is invisible.** Delete the last three entries from an exported
chain and the remaining entries still link correctly, still hash correctly,
and still report CHAIN INTACT. Nothing in the file says how long it was
supposed to be. For a custody log this is the failure that matters most:
the easiest way to make an inconvenient record disappear is to stop the story
early.

## What an anchor is

A **head receipt** is a short text block naming the chain, its height, and its
head hash:

```
BEWEISKETTE ANCHOR RECEIPT
schema:  2
chain:   3f2a1b8c-4d5e-4f60-8a1b-2c3d4e5f6071
seq:     41
entries: 42
head:    9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
time:    2026-07-24T09:31:04.117Z
check:   1c4a9f0be5d33a72
```

Copy it from the **Chain** tab. Then publish it somewhere whose timeline you
do not control.

That last part is the whole point. The receipt is worthless sitting on your
own disk, where you could rewrite it alongside the chain. It becomes evidence
the moment it exists somewhere you cannot silently revise.

The `check` field is a truncated digest of the other fields. It is not a
security control — anyone can recompute it. It catches the ordinary failure
of a receipt being line-wrapped by an email client or mistyped by hand, so a
mangled receipt reads as *mangled* rather than as a tampered chain.

## Where to publish it

Roughly in order of effort:

| Method | What it establishes | Notes |
|---|---|---|
| **Git commit** | The receipt existed when the commit was pushed | Direct analogue of Zeitkette's anchoring. Push to a remote — a local commit date is as forgeable as the chain. |
| **Email to yourself** | Received-header time at your provider | Weak if you run your own mail server; solid with a third-party provider. |
| **Public post** | Publication time on a platform you do not operate | A dated post, a mailing-list archive, an issue comment. |
| **RFC-3161 timestamp authority** | Cryptographically signed time from a trusted third party | The strongest option and the most legally recognized. Submit the `head` value. |
| **OpenTimestamps** | Inclusion in a Bitcoin block | Free, decentralized, no account. Confirmation takes hours. |

For an RFC-3161 authority, timestamp the head hash directly:

```bash
# Extract the head hash from your receipt, then:
openssl ts -query -digest <HEAD_HASH> -sha256 -cert -out request.tsq
curl -s -H "Content-Type: application/timestamp-query" \
     --data-binary @request.tsq https://freetsa.org/tsr > response.tsr
openssl ts -reply -in response.tsr -text
```

Keep `response.tsr` with your case file. It is a signed statement from a third
party that the head hash existed before that moment.

## How often

Anchor whenever losing the tail would matter:

- After registering a batch of evidence.
- At the close of each working day on an active case.
- Immediately before handing the chain to anyone.

Each receipt stands alone. A newer one does not invalidate an older one — an
older receipt still proves the chain reached that height with that content,
which is exactly what catches a later truncation.

## Checking an anchor

In the **Verify** tab: import the chain JSON, paste the receipt, and click
**Check Anchor**. Four outcomes:

- **Anchor confirmed.** The chain still contains the anchored entry at the
  anchored height with the anchored hash. If entries were appended after the
  receipt was issued, it says how many.
- **Entries are missing.** The chain no longer reaches the anchored height.
  This is truncation, and it is the case that verification alone cannot catch.
- **Entry N does not match the receipt.** The chain reaches that height, but
  with different content — it was rebuilt after the receipt was published.
  Every entry may re-hash correctly; it is simply not the chain that was
  anchored.
- **This receipt was issued for a different chain.** The `chain_id` differs.

## What anchoring still does not give you

An anchor establishes an upper bound — the chain existed *no later than* the
moment of publication. It says nothing about how long before that, and nothing
about whether the recorded facts are true. A person can register a file with a
false custodian name and anchor the result; the anchor then faithfully proves
that a false record existed by a given time.

Anchoring binds records to a moment. It does not make them honest. See
[THREAT_MODEL.md](THREAT_MODEL.md).
