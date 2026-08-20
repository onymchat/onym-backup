# Changelog

What changed on the wire, and what a client would have to change with it.

This operator implements a pinned profile —
[`onym:backup-implementation:object-http-v1`][profile] — so a change here is
usually a change there. Where an entry breaks compatibility it names the
profile amendment it follows, because the profile is what a client is written
against; this repository is one implementation of it.

Nothing is deployed and no client is wired to a live operator, so the breaks
below cost nobody a migration. That stops being true at the first paid
enrolment, and this file exists so the boundary is visible when it arrives.

[profile]: https://github.com/onymchat/onym-system/blob/main/backup/UI-Backup-Object-HTTP.md

## Unreleased

### Breaking

- **`payment_required` carries `manifestUrl`.** §10.1 requires it, and
  without it a client pins issuers from an unsigned refusal — which is
  pinning whatever answered. The issuers stay in the refusal so it is
  legible on its own; only the manifest's copy is signed.
- **A charging operator must declare `BACKUP_OFFERS`.** Refused at boot
  alongside the existing `BACKUP_REVOCATION_URL` check. A `402` naming
  no offer tells a client to buy something without saying what, and the
  payment loop stops there.
- **`upload_incomplete` reports gaps as ranges.** `missingChunks` is an array
  of inclusive `[first, last]` index ranges — ascending, non-overlapping,
  non-adjacent — and `missingChunkCount` is gone. It was previously an array of
  indices capped at 64, which a client with more gaps than the cap could not
  act on in one round trip.
- **`POST /v1/erasures` requires `operationId`** and returns a JSON **array**
  of receipts, one per distinct pinned `termsId` in scope. A receipt pins one
  terms document, so a scope spanning two cannot honestly be described by one
  receipt. A single-terms scope — every scope until an operator publishes new
  terms — yields an array of exactly one.
- **A grant carries `missingChunks`.** Present on a fresh grant as one range
  covering everything, so a resuming client needs no special case.
- **`quota_exceeded` carries `openGrants` and `openGrantBytes`.** Issued grants
  count against both limits, so a refusal that named neither left a client
  seeing usage below the maximum with a 409 beside it.
- **Erasure receipts carry `snapshots`**, naming the references each receipt
  covers. Without it, every receipt for a `scope: "all"` echoed the same scope
  string and differed only in `termsId`.
- **Erase outcomes carry `receiptIds`** and report `scope` where an upload
  outcome reports `digest`. A whole-holder erasure previously answered
  `"digest": "all"`.
- **A grant states its own `acceptedTermsId`.** A resumed grant may carry terms
  older than the request asked for, and the committed snapshot pins the grant's
  — so a client that wanted the newer ones can only tell by being told.

### Added

- **The paid path.** `SeatEntitlement` verification per §10.4 — canonical
  bytes, a signature from an issuer pinned at boot and published in the
  manifest, `audience`, exact-string `subject`, the validity window, and
  absence from the cached revocation epoch. Every failure answers
  `invalid_entitlement` and names the issuers, never which check failed.
- `POST /v1/entitlements` (§9.1), idempotent by `entitlementId` — and
  `X-Onym-Entitlement`, which is what onym-ios and onym-android actually
  send on every authenticated request, and deliberately omit on
  `/v1/exports`. Both run the same verifier. The header is not in the
  profile; refusing it would have broken both clients, and dropping the
  route would have left §9.1 unimplemented.
- A revocation-epoch poller. **A failed poll is not a refusal** (§10.4):
  the last good epoch stays in force, is cached in SQLite so a restart
  during a broker outage comes back with it, and its age is published in
  `/health` as §4.1 requires. A re-published older epoch cannot
  un-revoke anything.
- Lapse and grace (§10.3), derived from entitlement expiry and never
  from a charge — this operator is not the seller and has no charge to
  fail. Each retained snapshot is governed by the `endOfPayment` clause
  of **its own** pinned terms, notice then grace; what stays open is the
  **union** of `duringGrace` across snapshots still in one. `preflight`,
  upload and commit refuse holder-wide, because a lapsed holder is not
  owed new retention by any snapshot's terms. The allowlist is an
  explicit table in `lapse`, not an emergent property of which routes
  happen to check an entitlement.
- Past grace, the sweep expires a snapshot and its bytes go with it,
  reported as `retention_expired` rather than `erased`. The holder did
  not erase it, and **no receipt is minted** — a §11 receipt answers a
  holder's request, and signing one unasked would be evidence of a
  decision they did not make. A terms document declaring a post-grace
  cold state this operator does not implement keeps its bytes and says
  so, rather than deleting on a clause it cannot honour.
- Conformance tests §18.11 (forged issuer, mutated field, expired
  window, wrong audience, wrong subject, revoked id), §18.12 (the
  payment loop, same `operationId` and same bytes across the refusal),
  and §18.13 (export succeeds for a holder with no entitlement, against
  an operator that charges).
- Erase with signed receipts, export, and outcome reconciliation.
- `GET /v1/exports/receipts/{receiptId}` — receipts are §12 container members,
  and without this a holder whose erase response was lost could never obtain
  the receipt they earned.
- Historical terms are stored and served forever (§4.1), with detached
  `.sig` documents over the exact served bytes.
- Error codes `upload_incomplete`, `upload_expired`, `upload_not_found`,
  `receipt_not_found`, `receipt_expired`.
- A reconciliation sweep: orphaned bytes, expired grants, spent replay nonces,
  aged outcomes, receipts and erased references.
- `erasedReferences` in `metadataRetention`, bounding what is remembered about a
  snapshot after its bytes are gone. `list` reports `erased` and a re-erase
  answers `receipt_expired` only while it survives; past it both become "unknown
  digest", which is the operator having genuinely forgotten rather than keeping
  a permanent list of everything a holder erased.

### Fixed

- Retention windows that cannot be represented are refused at boot instead of
  panicking the hourly sweep, and RFC 3339 values are compared as timestamps
  rather than strings.
- Retained blobs are checked for contiguous chunks and their declared byte size
  before download or export; incomplete rows are marked
  `retention_expired`, never reported as retained. Commits no longer adopt an
  existing destination until its digest is verified.
- Chunk files and directory mutations are synced before SQLite records them;
  commit, erase, and orphan cleanup serialize destination changes so a
  concurrent re-upload cannot be unlinked by an erasure.
- Operation reconciliation authenticates the original percent-encoded request
  target, reports erase acceptance as `erasure_acknowledged` rather than the
  client's later `erased` judgement, and every terms entry in an export carries
  its own fetchable URL.
- Existing stores migrate `operation_outcomes.digest` to `subject` and add
  `receiptIds` without losing previously recorded outcomes.
- Erasure replay chooses the newest receipt set across exact scopes and stored
  digest coverage, so re-uploading a digest cannot revive a receipt from its
  earlier storage lifecycle.
- Signed metadata-retention durations come from the same configuration as the
  sweeper, and outcome, receipt, and coverage expiry commits atomically.
- **Re-uploading an erased digest reported `retained` and stored nothing.** The
  erased row kept the `(holder, digest)` primary key, so `INSERT OR IGNORE`
  silently dropped the re-upload while commit answered success, the download
  404'd, and the sweep deleted the committed bytes as orphans. This is §12's
  migration path — the same sealed bytes under the same reference.
- **A crash mid-erase left a live row whose bytes were gone**, so `list`
  reported `retained` about a snapshot that no longer existed. Bookkeeping
  commits in one transaction and the bytes are unlinked after it.
- **A live grant could be duplicated by a terms change.** Resume only fired when
  the request's `acceptedTermsId` matched the grant's, so re-preflighting under
  new terms fell past it and minted a *second* `uploadId` for the same digest —
  two grants against one reference, both consuming quota, when only expiry is
  supposed to release the first.
- Quota was enforced only at preflight, so a holder could preflight N uploads
  against an unmoved count and commit them all.
- Grant expiry was minted and stored and never compared to anything.
- One holder could displace another's outcome record by choosing their
  `operationId`.

### Notes

**A non-null `quota` is refused as `invalid_entitlement`.** The
whitepaper's consumable case expects a replay-protected balance keyed by
`entitlementId`, and this operator does not keep one. Storing a
purchased balance and never decrementing it would be claiming to honour
terms it has not implemented; the columns are in the schema and unused
until a broker actually issues consumables.

**There is no `lapse_state` table**, and earlier schemas that created
one now drop it. Lapse is derived — from the newest unrevoked
entitlement's expiry, then per snapshot from its own pinned terms. A
cached copy would be a per-holder payment record that nothing reads,
that §15 would have to declare, and that can only ever disagree with the
derivation.

Two changes are deliberately *not* here because they are not observable: the
store lock is no longer held across hashing, streaming or unlinking, and
downloads stream rather than buffering the whole snapshot. Both matter under
load and neither changes a byte on the wire.
