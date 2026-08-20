# QA catalog policy — `backup-qa`

How entries get into the `backup-qa` catalog. This is a **development
catalog**: it exists so the device-backup seat can be exercised end to
end before anything is published, and it is not a listing anyone should
trust.

## What listing means

An entry means one thing: at build time, an operator's signed manifest
was fetched, read by a person, and pinned by digest. It is not review,
endorsement, audit, or a claim the operator is trustworthy.

## Ranking

`placement: "policy-ranked"` throughout, and the ranking is
alphabetical by `componentId`. Nothing here is sponsored and nothing is
for sale — a QA catalog with paid placement would be testing the wrong
thing.

## Relationships

Every entry declares its `relationship` honestly. Entries for operators
run by the same people who publish this catalog declare
`common-owner`, which for a QA catalog is normally all of them.

## Removal

An entry is dropped from the next snapshot when its manifest stops
resolving, when its pinned digest no longer matches what it serves, or
when this catalog stops being needed. There is no notice period,
because there is nobody depending on it.
