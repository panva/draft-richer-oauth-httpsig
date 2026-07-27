#!/usr/bin/env bash
# Regenerate the generatable example include files used by the draft.
#
# Each invocation drives tools/gensig.py from a raw HTTP source and a key,
# writing clean include content (RFC 8792 note prefixed when wrapped, no
# fences) directly to the files referenced by {::include ...} in the draft.
#
# Fixed created/nonce values keep the rendered examples stable across runs.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
ex="$here/examples"
gensig="$here/gensig.py"

py() { python3 "$gensig" "$@"; }

# --- Token request (runtime Ed25519 key) -----------------------------------
# #2 Content-Digest of the form body and #3 the signed token request.
# The runtime key is embedded in the pub param; --runtime-key forces the alg
# param on and drops keyid.
py "$ex/token-request.http" \
    --key "$ex/token-key.jwk" \
    --covered @method @target-uri content-digest authorization \
    --content-digest --runtime-key \
    --tag httpsig-oauth-token-request \
    --nonce b3k2pp5k7z-50gnX1b06 \
    --created 1618884473 \
    --out-digest "$ex/content-digest.hdr" \
    --out-thumbprint "$ex/thumbprint.txt" \
    --out-signed "$ex/token-request-signed.http"

# --- Client registration metadata ------------------------------------------
# #1 the client metadata document. The registered thumbprint is the one just
# computed, so the registration example and the token request describe the same
# key rather than drifting apart.
cat > "$ex/client-metadata.json" <<EOF
{
    "client_id": "https://client.example.com/client-metadata.json",
    "client_name": "Example Client",
    "httpsig_bound_access_token_thumbprint":
        "$(cat "$ex/thumbprint.txt")",
    "httpsig_key_binding_method": "preregistered"
}
EOF

# --- Presenting the bound token (Ed25519) ----------------------------------
# #7 signed message (reused verbatim for #10) and #9 signature base. The same
# key the token was bound to above, so the whole document follows one token and
# one key. The token is already bound, so neither the key nor an identifier for
# it appears on the wire.
py "$ex/rs-request.http" \
    --key "$ex/token-key.jwk" \
    --covered @method @target-uri authorization \
    --no-keyid \
    --tag httpsig-oauth \
    --nonce k9Jyxempel2305Nmx7Rk \
    --created 1776650875 \
    --show-sig-base \
    --out-sig-base "$ex/rs-sig-base.sigbase" \
    --out-signed "$ex/present-request-signed.http"

echo "Regenerated example include files in $ex" >&2
