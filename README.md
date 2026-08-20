# onym-backup

Retention operator for the Onym device-backup seat.

It holds sealed snapshots and cannot read them. Every snapshot arrives
encrypted under a key derived from the holder's BIP39 recovery phrase,
and no code path here has any way to open one — that is not a promise
about conduct, it is the absence of a capability.

Implements
[`onym:backup-implementation:object-http-v1`](https://github.com/onymchat/onym-system/blob/main/backup/UI-Backup-Object-HTTP.md),
the first concrete profile of
[the device-backup boundary](https://github.com/onymchat/onym-system/blob/main/backup/UI-Backup.md).

## What it is not

- **Not an account system.** A holder is an Ed25519 public key. There is
  no email, no password, no support identifier, and no route that
  reassigns a snapshot's holder.
- **Not recoverable by the operator.** A lost recovery phrase means a
  permanently unreadable archive. Every mechanism that would avoid that
  — an escrowed key, a wrapped key the operator can unwrap, a
  support-driven reset — would make the operator able to read what it
  stores, which is a different seat.
- **Not a log of who did what.** Route, status, byte counts and
  durations are logged. Holder keys, digests, upload ids and operation
  ids are not, and none of them is aggregated per holder over time.

## Free and paid are the same binary

With no `BACKUP_ENTITLEMENT_ISSUERS` configured this operator never
returns `402` and never consults an entitlement. That is the
self-hosting path, and it is deliberately not a build flavour: paid and
self-hosted operators of one profile stay technically compatible, and
entitlement enforcement is a declared capability.

## Status

The §9 route table is complete: preflight, chunked upload, commit,
list, download, erase with signed receipts, export, outcome
reconciliation, and entitlement registration. Quota and grant expiry
are enforced, every terms document is served forever, and a sweep
deletes bytes no row accounts for.

The paid path is implemented — `SeatEntitlement` verification against
issuers pinned at boot, a revocation-epoch poller that keeps serving on
the last good epoch through a broker outage, and lapse and grace
derived per snapshot from the terms it was accepted under.

Two things are worth knowing before running this against a broker:

- **A credential may arrive two ways.** §9.1 specifies
  `POST /v1/entitlements`; both shipped clients instead attach
  `X-Onym-Entitlement` to every authenticated request and deliberately
  omit it on `/v1/exports`. Both paths run the same verifier.
- **A non-null `quota` is refused.** This operator sells a
  subscription, and keeping a purchased balance it never decrements
  would be claiming to honour terms it has not implemented. A
  consumable offer needs that balance built first.

What remains is not code here: nothing issues a `SeatEntitlement` yet,
so the §18.12 payment loop is exercised against a test broker rather
than a real one, and the §18 fixtures — the shared, byte-identical ones
§19 asks for — are still unwritten. Until they exist, conformance is a
claim rather than a result.

```
BACKUP_COMPONENT_ID=onym:component:you \
BACKUP_PUBLIC_URL=https://backup.example \
BACKUP_SIGNING_SEED=$(openssl rand -hex 32) \
cargo run -p onym-backup-operator
```

With no `BACKUP_ENTITLEMENT_ISSUERS` that is a complete free-mode
operator's configuration. A charging one adds three, and refuses to
boot without them — an operator that names issuers but no revocation
URL would honour refunds never, and one that names no offer would send
a `402` telling the client to buy something without saying what:

```
BACKUP_ENTITLEMENT_ISSUERS=onym:key:<broker-hex> \
BACKUP_REVOCATION_URL=https://broker.example/v1/revocations/current \
BACKUP_OFFERS=backup-monthly-v1
```
