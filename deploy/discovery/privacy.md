# QA discovery provider — privacy

What this provider learns when a client fetches from it.

Discovery in the static-snapshot profile is signed files on a file
server. Publishing involves no database and no account.

## What is collected

Whatever the file server logs — at minimum an IP address, a timestamp,
and a path — for as long as that host retains its logs. For a QA
deployment that is the tunnel or object-store provider's default, which
is nobody's considered decision and should not be treated as one.

## What is not collected

There is no per-client identifier, no cookie, no telemetry, and no
record connecting a fetch to an identity. A client fetching a catalog
tells this provider only that someone asked.

## Retention

Not declared, because this is a development provider on a
general-purpose host. **Do not reuse this document for a published
provider** — a real one must declare a real retention window and be
held to it.
