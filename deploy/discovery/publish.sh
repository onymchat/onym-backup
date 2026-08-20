#!/usr/bin/env bash
#
# Build a signed QA discovery catalog listing one backup operator.
#
# The operator's componentId and signing key are read from the manifest
# it actually serves, never typed in here. A catalog entry names the key
# a client will verify the manifest against, so a hand-copied one is a
# way to pin the wrong key and not find out until a signature fails for
# reasons that look like anything else.
#
#   DISCOVERY_HOST=discovery-qa.example \
#   OPERATOR_HOST=backup-qa.example \
#   ./publish.sh
#
# Both hosts must be DNS names reachable over HTTPS with no port
# component — profile §7 rejects IP literals and any explicit port,
# including a redundant :443. A tunnel (ngrok, Cloudflare) satisfies
# this; `localhost:8443` does not.
set -euo pipefail

: "${DISCOVERY_HOST:?set DISCOVERY_HOST, e.g. discovery-qa.example}"
: "${OPERATOR_HOST:?set OPERATOR_HOST, e.g. backup-qa.example}"

for host in "$DISCOVERY_HOST" "$OPERATOR_HOST"; do
  case "$host" in
    *:*|https://*|http://*)
      echo "error: $host must be a bare DNS name — no scheme, no port." >&2
      echo "       Profile §7 rejects an explicit port before URL" >&2
      echo "       normalization can hide it." >&2
      exit 1 ;;
  esac
done

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"
out="${OUT_DIR:-$here/out}"
seed="${SEED_FILE:-$here/provider.seed}"
cli="${ONYM_DISCOVERY:-onym-discovery}"

command -v "$cli" >/dev/null 2>&1 || {
  echo "error: $cli not on PATH." >&2
  echo "       cargo install --path ../../../onym-discovery" >&2
  echo "       or set ONYM_DISCOVERY=/path/to/onym-discovery" >&2
  exit 1
}

mkdir -p "$out/catalogs" "$here/reviewed"

# The provider key. Created once and kept OUT of the served directory —
# `out/` is what gets uploaded, and a seed published beside the catalog
# it signs is a catalog anyone can rewrite.
if [ ! -f "$seed" ]; then
  echo "==> creating provider key"
  "$cli" keygen --out "$seed"
  echo
  echo "    The fingerprint above is what a person checks at"
  echo "    trust-on-first-use pinning. Publish it out of band;"
  echo "    reading it off the same page that served the catalog"
  echo "    proves nothing."
  echo
fi
provider_key="$("$cli" fingerprint --seed "$seed" | awk '/^operator:/ {print $2}')"

# Retrieve, review, then pin — the manifest bytes are hashed into the
# entry at build time, so what a client verifies is what was read here.
echo "==> fetching https://$OPERATOR_HOST/manifest.json"
curl -fsS "https://$OPERATOR_HOST/manifest.json" -o "$here/reviewed/operator-manifest.json"

read -r operator_component operator_key operator_seat <<EOF
$(python3 - "$here/reviewed/operator-manifest.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
print(m.get("componentId", ""), m.get("operator", ""), m.get("seat", ""))
PY
)
EOF

if [ "$operator_seat" != "storage.backup" ]; then
  echo "error: $OPERATOR_HOST declares seat '$operator_seat', not storage.backup." >&2
  exit 1
fi

echo "    componentId  $operator_component"
echo "    operator     $operator_key"
echo
echo "    Read reviewed/operator-manifest.json before continuing. Pinning"
echo "    a digest is the review step; nothing downstream re-checks it."
echo

# Policy and privacy digests over the exact served bytes. Computed
# rather than written down, because a digest that does not match the
# document it cites is worse than no citation: it verifies structurally
# and points at nothing.
digest() { printf 'sha256:%s' "$(shasum -a 256 "$1" | awk '{print $1}')"; }
policy_digest="$(digest policy.md)"
privacy_digest="$(digest privacy.md)"
cp policy.md privacy.md "$out/"

now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# 89 days, inside the profile's 90-day ceiling with room for the
# symmetric 10-minute skew allowance at both ends.
valid_until="$(date -u -v+89d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
  || date -u -d '+89 days' +%Y-%m-%dT%H:%M:%SZ)"

echo "==> building provider manifest"
python3 - <<PY
import json
m = json.load(open("provider-manifest.src.json"))
m["operator"] = "$provider_key"
m["validUntil"] = "$valid_until"
m["privacyProfile"] = "$privacy_digest"
m["privacyProfileUri"] = "https://$DISCOVERY_HOST/privacy.md"
c = m["catalogs"][0]
c["snapshot"] = "https://$DISCOVERY_HOST/catalogs/backup-qa.json"
c["policy"] = "$policy_digest"
c["policyUri"] = "https://$DISCOVERY_HOST/policy.md"
json.dump(m, open("$out/manifest.src.json", "w"), indent=2)
PY
"$cli" sign-manifest --seed "$seed" "$out/manifest.src.json" --out "$out/manifest.json"
rm "$out/manifest.src.json"

echo "==> building catalog snapshot"
python3 - <<PY
import json
c = json.load(open("catalog.config.json"))
c["policyDigest"] = "$policy_digest"
e = c["entries"][0]
e["componentId"] = "$operator_component"
e["operator"] = "$operator_key"
e["manifest"]["uri"] = "https://$OPERATOR_HOST/manifest.json"
e["listedAt"] = "$now"
json.dump(c, open("catalog.config.resolved.json", "w"), indent=2)
PY

# Chain onto the previous snapshot when there is one. Sequence and
# previousDigest come from those exact bytes, never from a counter kept
# here — a client rejects a rollback or a fork, so a snapshot built
# without its predecessor is a snapshot that breaks every client that
# already fetched one.
previous=""
if [ -f "$out/catalogs/backup-qa.json" ]; then
  cp "$out/catalogs/backup-qa.json" "$out/catalogs/backup-qa.previous.json"
  previous="--previous $out/catalogs/backup-qa.previous.json"
fi
# shellcheck disable=SC2086
"$cli" build-snapshot --seed "$seed" \
  --config catalog.config.resolved.json \
  $previous \
  --out "$out/catalogs/backup-qa.json"
rm -f catalog.config.resolved.json "$out/catalogs/backup-qa.previous.json"

echo "==> verifying what was built"
"$cli" verify manifest "$out/manifest.json"
"$cli" verify snapshot "$out/catalogs/backup-qa.json" --manifest "$out/manifest.json"

cat <<EOF

Built in $out — serve that directory at https://$DISCOVERY_HOST/ so
that these resolve:

  https://$DISCOVERY_HOST/manifest.json
  https://$DISCOVERY_HOST/manifest.json.sig
  https://$DISCOVERY_HOST/catalogs/backup-qa.json
  https://$DISCOVERY_HOST/policy.md
  https://$DISCOVERY_HOST/privacy.md

The provider fingerprint to confirm on the device:

$("$cli" fingerprint --seed "$seed")
EOF
