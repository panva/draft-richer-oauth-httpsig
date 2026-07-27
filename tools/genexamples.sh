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
# The key is embedded in the pub param and named by jws_alg; --runtime-key
# drops keyid, and --jws-alg suppresses the RFC9421 alg param.
py "$ex/token-request.http" \
    --key "$ex/token-key.jwk" \
    --covered @method @target-uri content-digest authorization \
    --content-digest --runtime-key --jws-alg Ed25519 \
    --tag httpsig-oauth-token-request \
    --nonce b3k2pp5k7z-50gnX1b06 \
    --created 1618884473 \
    --out-digest "$ex/content-digest.hdr" \
    --out-signed "$ex/token-request-signed.http"

# --- Presenting the bound token (Ed25519) ----------------------------------
# #7 (also reused verbatim for #8). The token is already bound, so neither the
# key nor an identifier for it appears on the wire.
py "$ex/rs-request.http" \
    --key "$ex/token-key.jwk" \
    --covered @method @target-uri authorization \
    --no-keyid \
    --tag httpsig-oauth \
    --nonce k9Jyxempel2305Nmx7Rk \
    --created 1776650875 \
    --out-signed "$ex/present-request-signed.http"

# --- Presenting with an EC P-256 key (sig base + signed message) -----------
# #9 signature base and #10 signed message, from the same plain message as #7.
py "$ex/rs-request.http" \
    --key "$ex/test-key-ecdsa-p256.pem" \
    --key-id test-key-ecdsa-p256 \
    --covered @method @target-uri authorization \
    --no-keyid \
    --tag httpsig-oauth \
    --nonce k9Jyxempel2305Nmx7Rk \
    --created 1776650875 \
    --show-sig-base \
    --out-sig-base "$ex/rs-sig-base.sigbase" \
    --out-signed "$ex/rs-request-signed.http"

echo "Regenerated example include files in $ex" >&2
