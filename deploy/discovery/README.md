# Listing this operator in a QA discovery catalog

The iOS and Android apps do not take a backup operator's URL. They read
a **pinned consent record**, and a consent record comes from a signed
discovery catalog entry. So exercising the seat end to end means
publishing a small catalog that lists the operator you are running.

`publish.sh` builds one.

```sh
DISCOVERY_HOST=discovery-qa.example \
OPERATOR_HOST=backup-qa.example \
./publish.sh
```

It creates a provider key on first run, fetches the operator's
`/manifest.json`, pins those exact bytes by digest, signs a provider
manifest and a catalog snapshot, and verifies both before it finishes.
Serve `out/` at `https://$DISCOVERY_HOST/`.

## Before it will work

**Both hosts must be DNS names over HTTPS with no port.** Profile §7
rejects IP literals and any explicit port component — including a
redundant `:443`, which is checked in the raw string before a URL
library can normalize it away. `localhost:8443` fails; a tunnel does
not. The operator itself also refuses to boot unless
`BACKUP_PUBLIC_URL` is `https://`, and the iOS client refuses a
non-https endpoint in every build.

**Run the operator in free mode.** Leave `BACKUP_ENTITLEMENT_ISSUERS`
unset. Nothing issues a `SeatEntitlement` yet, so a charging operator
would refuse every upload with a `402` no client can clear.

## What the script does not decide for you

**The componentId and operator key come from the manifest the operator
serves**, not from this config. A catalog entry names the key a client
will verify that manifest against, so a hand-copied key is a way to pin
the wrong one and discover it later as a signature failure that looks
like anything else.

**Reviewing is yours.** The entry pins a digest over
`reviewed/operator-manifest.json`, and pinning that digest *is* the
review step — nothing downstream re-checks what the document says. Read
it before you publish.

**The fingerprint must reach the device out of band.** It is what a
person checks when they add the source, and reading it off the same
page that served the catalog proves nothing.

**Keep `provider.seed` out of `out/`.** A signing seed published beside
the catalog it signs is a catalog anyone can rewrite. The script writes
it to this directory and serves only `out/`; do not collapse the two.

## Re-publishing

Run it again. Sequence and `previousDigest` are derived from the
existing snapshot's exact bytes, never from a counter — clients reject
a rollback or a fork, so a snapshot built without its predecessor
breaks everyone who already fetched one. Keep `out/catalogs/` between
runs.

`policy.md` and `privacy.md` are cited by digest, so editing either
changes the digest and requires a re-publish. Both are written for a
development catalog and say so; **neither is fit for a published
provider** — the privacy document in particular declines to declare a
retention window, which a real provider may not do.

## This is not enough to QA iOS yet

The apps have discovery pickers for four seats — `notary`,
`transport.message`, `blob.storage`, `moderation`. **There is none for
`storage.backup`**, and `SeatManifestVocabulary.acceptedManifestSeats`
has no entry for it either. Nothing writes a pinned consent record for
a backup operator, so `BackupSeat.consentedManifests` returns empty and
the Device Backup section never appears.

These files are the operator half, and they are correct and needed
regardless. The missing half is a backup `DiscoveryModulePicker` in
onym-ios, and the same gap exists on Android.
