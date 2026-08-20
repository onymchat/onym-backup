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

A snapshot can be stored and read back: preflight, chunked upload,
commit, list, download, with quota and grant expiry enforced and a
reconciliation sweep that deletes bytes no row accounts for. Erase with
signed receipts, export, and outcome reconciliation are next, along
with the entitlement path for operators that charge.

```
BACKUP_COMPONENT_ID=onym:component:you \
BACKUP_PUBLIC_URL=https://backup.example \
BACKUP_SIGNING_SEED=$(openssl rand -hex 32) \
cargo run -p onym-backup-operator
```

With no `BACKUP_ENTITLEMENT_ISSUERS` that is a complete free-mode
operator's configuration.
