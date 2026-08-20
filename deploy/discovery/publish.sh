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
PROVIDER_KEY="$provider_key" \
VALID_UNTIL="$valid_until" \
PRIVACY_DIGEST="$privacy_digest" \
DISCOVERY_HOST="$DISCOVERY_HOST" \
POLICY_DIGEST="$policy_digest" \
OUT_MANIFEST_SRC="$out/manifest.src.json" \
python3 - <<'PY'
import json, os
m = json.load(open("provider-manifest.src.json"))
m["operator"] = os.environ["PROVIDER_KEY"]
m["validUntil"] = os.environ["VALID_UNTIL"]
m["privacyProfile"] = os.environ["PRIVACY_DIGEST"]
m["privacyProfileUri"] = f"https://{os.environ['DISCOVERY_HOST']}/privacy.md"
c = m["catalogs"][0]
c["snapshot"] = f"https://{os.environ['DISCOVERY_HOST']}/catalogs/backup-qa.json"
c["policy"] = os.environ["POLICY_DIGEST"]
c["policyUri"] = f"https://{os.environ['DISCOVERY_HOST']}/policy.md"
json.dump(m, open(os.environ["OUT_MANIFEST_SRC"], "w"), indent=2)
PY
"$cli" sign-manifest --seed "$seed" "$out/manifest.src.json" --out "$out/manifest.json"
rm "$out/manifest.src.json"

echo "==> building catalog snapshot"
POLICY_DIGEST="$policy_digest" \
OPERATOR_COMPONENT="$operator_component" \
OPERATOR_KEY="$operator_key" \
OPERATOR_HOST="$OPERATOR_HOST" \
LISTED_AT="$now" \
python3 - <<'PY'
import json, os
c = json.load(open("catalog.config.json"))
c["policyDigest"] = os.environ["POLICY_DIGEST"]
e = c["entries"][0]
e["componentId"] = os.environ["OPERATOR_COMPONENT"]
e["operator"] = os.environ["OPERATOR_KEY"]
e["manifest"]["uri"] = f"https://{os.environ['OPERATOR_HOST']}/manifest.json"
e["listedAt"] = os.environ["LISTED_AT"]
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
