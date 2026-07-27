#!/usr/bin/env python3
"""
Generate RFC9421 HTTP message signatures for IETF I-D artwork.

Outputs are wrapped using the RFC8792 single-backslash algorithm, with
two wrapping strategies:
  - Binary (base64 content in :...: items): wrap at exact column positions
  - Structured fields (RFC8941): soft-break at semantic separators
    (spaces between list items, semicolons before parameters)
"""

import argparse
import base64
import collections
import datetime
import json
import re
import sys
import textwrap
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption,
    load_pem_private_key, load_pem_public_key,
)
from jwcrypto import jwk

from http_message_signatures import (
    HTTPMessageSigner, HTTPSignatureKeyResolver,
    algorithms as sig_algorithms,
)
from http_message_signatures import http_sfv


# ---------------------------------------------------------------------------
# RFC8792 wrapping
# ---------------------------------------------------------------------------

CONTINUATION_INDENT = "  "  # two spaces per RFC8792 convention
MIN_TAIL = 3   # minimum characters after a break point (excluding indent)
TAIL_BACKUP = 5  # how far to back up when the tail is too short


def _adjust_for_short_tail(bp: int, line: str) -> int:
    """Adjust a break point to avoid very short tails.

    Returns the (possibly adjusted) break point. Returns len(line) as a
    sentinel meaning "do not break" when tail == 1, since inserting a
    backslash there costs the same space as the character itself.
    For other short tails (< MIN_TAIL), backs up TAIL_BACKUP positions if
    possible; otherwise leaves the break point unchanged.
    """
    tail = len(line) - bp
    if tail == 1:
        return len(line)  # sentinel: don't break
    if tail >= MIN_TAIL:
        return bp
    backed = bp - TAIL_BACKUP
    if backed > 0 and len(line) - backed >= MIN_TAIL:
        return backed
    return bp  # fall through: leave break where it is


def _wrap_at_column(text: str, max_len: int) -> str:
    """Wrap text at exactly max_len characters using RFC8792 backslash folding.
    Continuation lines are indented with CONTINUATION_INDENT.
    Used for binary (base64) content where there are no natural break points.
    """
    indent = CONTINUATION_INDENT
    lines = []
    while len(text) > max_len:
        # -1 leaves room for the trailing "\" that joins the fold
        bp = _adjust_for_short_tail(max_len - 1, text)
        if bp >= len(text):
            break  # single trailing character: don't break
        lines.append(text[:bp])
        text = indent + text[bp:]
    lines.append(text)
    return "\\\n".join(lines)


def _find_structured_break(line: str, max_len: int) -> int:
    """Find the best break position at or before max_len for a structured field.

    Priority (highest to lowest):
      1. Semicolon ';' — break BEFORE it so the ';' leads the next line
      2. Space ' ' — break AFTER it (the space is a separator, consume it)
      3. Comma ',' — break AFTER it
    Falls back to hard break at max_len if no separator is found.
    Returns the index in `line` where the break (backslash) should be inserted.
    """
    candidate = max_len
    # Search backwards from max_len for a preferred separator
    # We look in a window of the last 30% of the allowed width so we don't
    # produce very short lines.
    window_start = max(0, max_len - max(10, max_len // 3))
    segment = line[window_start:max_len]

    # Prefer ';' — break BEFORE it
    pos = segment.rfind(';')
    if pos != -1:
        return window_start + pos  # break before the ';'

    # Next prefer space — break AFTER it
    pos = segment.rfind(' ')
    if pos != -1:
        return window_start + pos + 1  # keep the space on the current line

    # Then comma — break AFTER it
    pos = segment.rfind(',')
    if pos != -1:
        return window_start + pos + 1

    return candidate  # hard break


def wrap_binary_value(line: str, max_len: int = 69) -> str:
    """Wrap a line that contains a binary (:base64:) structured-field item.

    Wraps the entire line at exact column positions (no separator search).
    The binary content is opaque so position-based splitting is correct.
    """
    if len(line) <= max_len:
        return line
    return _wrap_at_column(line, max_len)


def wrap_structured_field(line: str, max_len: int = 69) -> str:
    """Wrap a structured-field header value, preferring semantic break points.

    Breaks at ';' (before parameters), ' ' (between list items), or ',' as
    fallback, all per the RFC8792 single-backslash scheme.

    Separators are never consumed: for ';' the break is before the character
    so it leads the continuation; for ' ' and ',' the break is after the
    character so it stays on the current line. The RFC8792 unwrap algorithm
    strips only the leading CONTINUATION_INDENT from each continuation line,
    so the separator itself is always reconstructed correctly.
    """
    if len(line) <= max_len:
        return line
    indent = CONTINUATION_INDENT
    parts = []
    while len(line) > max_len:
        # -1 leaves room for the trailing "\" that joins the fold
        bp = _adjust_for_short_tail(_find_structured_break(line, max_len - 1), line)
        if bp >= len(line):
            break  # single trailing character: don't break
        parts.append(line[:bp])
        line = indent + line[bp:]
    parts.append(line)
    return "\\\n".join(parts)


def wrap_line(line: str, max_len: int = 69, is_binary: bool = False) -> str:
    if is_binary:
        return wrap_binary_value(line, max_len)
    return wrap_structured_field(line, max_len)


def _line_contains_binary(header_name: str, value: str) -> bool:
    """Heuristic: is this line's value primarily binary (base64) content?

    Headers whose values are SF Dictionaries containing :byte-sequence: items
    (Signature, Content-Digest, Repr-Digest) get binary wrapping.
    Structured-field-only headers (Signature-Input, Accept-Signature) get
    structured wrapping even though they may contain parameter lists.
    """
    binary_headers = {"signature", "content-digest", "repr-digest"}
    return header_name.lower() in binary_headers


def wrap_http_block(text: str, max_len: int = 69) -> str:
    """Apply RFC8792 wrapping to a multi-line HTTP message block.

    Each line is wrapped independently. The wrapping strategy is chosen per
    line based on whether the header name suggests binary or structured content.
    """
    out = []
    current_header_name = ""
    for line in text.splitlines():
        # Detect the start of a header field
        m = re.match(r'^([A-Za-z0-9!#$%&\'*+\-.^_`|~]+)\s*:', line)
        if m:
            current_header_name = m.group(1)
        binary = _line_contains_binary(current_header_name, line)
        out.append(wrap_line(line, max_len, is_binary=binary))
    return "\n".join(out)


def wrap_sig_base(text: str, max_len: int = 69) -> str:
    """Wrap a signature base string.

    The last line ("@signature-params") is treated as a structured field;
    all other lines contain header values that may include binary bytes.
    """
    out = []
    for line in text.splitlines():
        if line.startswith('"@signature-params"'):
            out.append(wrap_structured_field(line, max_len))
        else:
            # header value lines; check if likely binary
            m = re.match(r'^"([^"]+)":\s*(.*)', line, re.DOTALL)
            if m and _line_contains_binary(m.group(1), m.group(2)):
                out.append(wrap_binary_value(line, max_len))
            else:
                out.append(wrap_structured_field(line, max_len))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Key loading
# ---------------------------------------------------------------------------

# Keys are RFC9421 algorithm identifiers (Section 3.3).
ALGORITHM_MAP = {
    "rsa-pss-sha512":       sig_algorithms.RSA_PSS_SHA512,
    "rsa-v1_5-sha256":      sig_algorithms.RSA_V1_5_SHA256,
    "ecdsa-p256-sha256":    sig_algorithms.ECDSA_P256_SHA256,
    "ed25519":              sig_algorithms.ED25519,
    "hmac-sha256":          sig_algorithms.HMAC_SHA256,
}


class KeyMaterial:
    """Holds a private key (PEM bytes) and the algorithm class to use."""
    def __init__(self, private_pem: bytes, public_pem: Optional[bytes],
                 algorithm: type, key_id: str):
        self.private_pem = private_pem
        self.public_pem = public_pem
        self.algorithm = algorithm
        self.key_id = key_id

    def as_resolver(self) -> HTTPSignatureKeyResolver:
        priv = self.private_pem
        pub = self.public_pem

        class _Resolver(HTTPSignatureKeyResolver):
            def resolve_private_key(self, key_id):
                return priv
            def resolve_public_key(self, key_id):
                return pub

        return _Resolver()


def _algorithm_from_jwk_type(kty: str, crv: Optional[str]) -> type:
    """Infer the RFC9421 algorithm from JWK kty/crv. Ignores the 'alg' field.

    RSA keys are ambiguous (rsa-pss-sha512 vs rsa-v1_5-sha256) and require
    an explicit --alg.
    """
    if kty == "OKP" and crv == "Ed25519":
        return sig_algorithms.ED25519
    if kty == "EC" and crv == "P-256":
        return sig_algorithms.ECDSA_P256_SHA256
    if kty == "oct":
        return sig_algorithms.HMAC_SHA256
    raise ValueError(
        f"Cannot auto-detect algorithm for kty={kty!r}, crv={crv!r}. "
        f"Use --alg with one of: {', '.join(ALGORITHM_MAP)}"
    )


def _algorithm_from_private_key(key) -> type:
    """Infer the RFC9421 algorithm from a loaded cryptography private key.

    RSA keys are ambiguous (rsa-pss-sha512 vs rsa-v1_5-sha256) and require
    an explicit --alg.
    """
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519 as _ed25519
    if isinstance(key, ec.EllipticCurvePrivateKey):
        if isinstance(key.curve, ec.SECP256R1):
            return sig_algorithms.ECDSA_P256_SHA256
        raise ValueError(
            f"Unsupported EC curve {key.curve.name!r}. "
            f"Use --alg with one of: {', '.join(ALGORITHM_MAP)}"
        )
    if isinstance(key, _ed25519.Ed25519PrivateKey):
        return sig_algorithms.ED25519
    raise ValueError(
        f"Cannot auto-detect algorithm for key type {type(key).__name__}. "
        f"Use --alg with one of: {', '.join(ALGORITHM_MAP)}"
    )


def load_key(key_path: Path, key_id: Optional[str] = None,
             algorithm_override: Optional[str] = None) -> KeyMaterial:
    """Load a key from a JWK (JSON) or PEM file."""
    raw = key_path.read_bytes()

    # Try JWK first
    try:
        data = json.loads(raw)
        # Support bare JWK or JWK Set {"keys": [...]}
        if "keys" in data:
            if key_id:
                jwk_data = next((k for k in data["keys"] if k.get("kid") == key_id), None)
                if not jwk_data:
                    raise ValueError(f"Key id '{key_id}' not found in JWK Set")
            else:
                jwk_data = data["keys"][0]
        else:
            jwk_data = data

        k = jwk.JWK.from_json(json.dumps(jwk_data))
        kid = key_id or jwk_data.get("kid", key_path.stem)

        # Determine algorithm
        if algorithm_override:
            algorithm = ALGORITHM_MAP[algorithm_override]
        else:
            algorithm = _algorithm_from_jwk_type(
                jwk_data.get("kty"), jwk_data.get("crv")
            )

        if jwk_data.get("kty") == "oct":
            # Symmetric key — use raw bytes
            secret = base64.urlsafe_b64decode(jwk_data["k"] + "==")
            return KeyMaterial(
                private_pem=secret, public_pem=secret,
                algorithm=algorithm, key_id=kid,
            )

        priv_pem = k.export_to_pem(private_key=True, password=None) if k.has_private else None
        pub_pem = k.export_to_pem(private_key=False, password=None)
        if priv_pem is None:
            raise ValueError("JWK does not contain a private key — cannot sign")

        return KeyMaterial(private_pem=priv_pem, public_pem=pub_pem,
                           algorithm=algorithm, key_id=kid)

    except (json.JSONDecodeError, KeyError):
        pass  # not JSON, try PEM

    # PEM key
    kid = key_id or key_path.stem
    try:
        priv = load_pem_private_key(raw, password=None)
    except Exception:
        raise ValueError(f"Could not parse private key from {key_path}")

    algorithm = (ALGORITHM_MAP[algorithm_override] if algorithm_override
                 else _algorithm_from_private_key(priv))
    pub = priv.public_key()
    priv_pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pub_pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return KeyMaterial(private_pem=priv_pem, public_pem=pub_pem,
                       algorithm=algorithm, key_id=kid)


# ---------------------------------------------------------------------------
# HTTP message parsing
# ---------------------------------------------------------------------------

class HTTPRequest:
    """Minimal HTTP request object compatible with http_message_signatures."""

    def __init__(self, method: str, url: str,
                 headers: dict, body: Optional[bytes] = None):
        self.method = method.upper()
        self.url = url
        self.headers = collections.OrderedDict(
            (k, v) for k, v in headers.items()
        )
        self.body = body

    def render(self) -> str:
        """Render back to HTTP/1.1 wire format."""
        from urllib.parse import urlsplit
        parsed = urlsplit(self.url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        lines = [f"{self.method} {path} HTTP/1.1"]
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}")
        if self.body:
            lines.append("")
            lines.append(self.body.decode(errors="replace"))
        return "\n".join(lines)


_RFC8792_SINGLE = re.compile(r"NOTE:\s*'\\'\s*line wrapping per RFC\s*8792", re.IGNORECASE)
_RFC8792_DOUBLE = re.compile(r"NOTE:\s*'\\\\'\s*line wrapping per RFC\s*8792", re.IGNORECASE)


def unfold_rfc8792(text: str) -> str:
    """Undo RFC8792 single- or double-backslash line wrapping.

    Detects the algorithm from the RFC8792 note line at the start of the text
    and strips it before unfolding.

    Single-backslash: lines ending with a lone '\\' are joined to the next
    line after stripping the backslash and leading whitespace.

    Double-backslash: lines ending with '\\\\' are joined to the next line
    after stripping the trailing '\\\\', and the leading '\\\\' plus
    whitespace from the continuation line.
    """
    lines = text.splitlines()
    if not lines:
        return text

    first = lines[0].strip()
    if _RFC8792_DOUBLE.match(first):
        mode = "double"
        lines = lines[1:]
    elif _RFC8792_SINGLE.match(first):
        mode = "single"
        lines = lines[1:]
    else:
        return text  # no RFC8792 marker, return as-is

    # Drop a blank line immediately after the note
    if lines and lines[0].strip() == "":
        lines = lines[1:]

    result = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if mode == "single":
            while line.endswith("\\") and not line.endswith("\\\\"):
                line = line[:-1]
                i += 1
                if i < len(lines):
                    line += lines[i].lstrip(" \t")
        else:  # double
            while line.endswith("\\\\"):
                line = line[:-2]
                i += 1
                if i < len(lines):
                    cont = lines[i]
                    if cont.startswith("\\\\"):
                        cont = cont[2:].lstrip(" \t")
                    line += cont
        result.append(line)
        i += 1
    return "\n".join(result)


def parse_http_request(text: str) -> HTTPRequest:
    """Parse a minimal HTTP/1.1 request from text, unfolding RFC8792 wrapping if present."""
    text = unfold_rfc8792(text)
    lines = text.splitlines()
    if not lines:
        raise ValueError("Empty HTTP message")

    # Request line: METHOD path HTTP/1.1
    method, path, *_ = lines[0].split()

    headers: dict = {}
    body_start = len(lines)
    i = 1
    while i < len(lines):
        line = lines[i]
        if line == "":
            body_start = i + 1
            break
        if ':' not in line:
            raise ValueError(f"Malformed header line: {line!r}")
        name, _, value = line.partition(':')
        headers[name.strip()] = value.strip()
        i += 1

    body_lines = lines[body_start:]
    body = "\n".join(body_lines).encode() if body_lines else None

    # Reconstruct a full URL from the Host header and path
    host = headers.get("Host", headers.get("host", "example.com"))
    scheme = "https"
    url = f"{scheme}://{host}{path}"

    return HTTPRequest(method=method, url=url, headers=headers, body=body)


# ---------------------------------------------------------------------------
# Inspectable signer — captures signature base before returning
# ---------------------------------------------------------------------------

def runtime_key_params(public_pem: bytes, algorithm: type) -> "collections.OrderedDict":
    """Map a public key into the `pub` signature parameter per {#embed-keys}.

    Returns an OrderedDict of parameter name -> bytes (serialized as a Byte
    Sequence by http_sfv). EC keys use the SEC1 uncompressed point form
    (0x04 || X || Y); Ed25519 uses the raw 32-octet public key A. RSA is out
    of scope for the inline representation.
    """
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519

    pub = load_pem_public_key(public_pem)
    params: "collections.OrderedDict[str, bytes]" = collections.OrderedDict()

    if isinstance(pub, ec.EllipticCurvePublicKey):
        params["pub"] = pub.public_bytes(Encoding.X962,
                                         PublicFormat.UncompressedPoint)
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        params["pub"] = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    else:
        raise ValueError(f"Cannot embed public key of type {type(pub).__name__}")

    return params


class InspectableSigner(HTTPMessageSigner):
    """HTTPMessageSigner that stores the last signature base for inspection.

    If ``extra_params`` is set, those parameters are merged into every
    signature's parameters so they appear in Signature-Input and are covered
    by the signature base (used for runtime public-key embedding).

    If ``drop_keyid`` is set, the keyid parameter the library always emits is
    removed. The draft omits keyid for runtime key introduction and for token
    presentation.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.last_sig_base: Optional[str] = None
        self.last_sig_elements: Optional[dict] = None
        self.extra_params: Optional[dict] = None
        self.drop_keyid: bool = False

    def _build_signature_base(self, message, *, covered_component_ids, signature_params):
        if self.drop_keyid:
            signature_params.pop("keyid", None)
        if self.extra_params:
            signature_params.update(self.extra_params)
        result = super()._build_signature_base(
            message,
            covered_component_ids=covered_component_ids,
            signature_params=signature_params,
        )
        self.last_sig_base = result[0]
        self.last_sig_elements = result[2]
        return result


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

RFC8792_NOTE = "NOTE: '\\' line wrapping per RFC 8792"


def content_digest_sha256(body: bytes) -> str:
    """Return the Content-Digest header value for a SHA-256 body digest."""
    import hashlib
    digest = hashlib.sha256(body).digest()
    cd = http_sfv.Dictionary()
    cd["sha-256"] = digest
    return str(cd)


def _artwork_block(content: str, label: str = "") -> str:
    fence = f"~~~ {label}".rstrip()
    return f"{fence}\n{content}\n~~~"


def _with_wrap_note(wrapped: str) -> str:
    """Prepend the RFC 8792 note if the content contains line wrapping.

    Rendered outputs that use the single-backslash fold must carry the note
    (and a following blank line) so the wrapping is self-describing.
    """
    if any(line.endswith("\\") and not line.endswith("\\\\")
           for line in wrapped.splitlines()):
        return f"{RFC8792_NOTE}\n\n{wrapped}"
    return wrapped


def format_output(
    request_original: HTTPRequest,
    request_signed: HTTPRequest,
    sig_base: str,
    key: KeyMaterial,
    max_len: int,
    show_sig_base: bool,
    show_keys: bool,
    show_original: bool,
) -> str:
    sections = []

    if show_original:
        sections.append("Original HTTP Request:\n" +
                        _artwork_block(wrap_http_block(request_original.render(), max_len),
                                       "http-message"))

    if show_keys:
        pub_b64 = base64.b64encode(key.public_pem).decode()
        wrapped_pub = wrap_binary_value(pub_b64, max_len)
        sections.append("Public Key (PEM, base64):\n" +
                        _artwork_block(wrapped_pub))

    if show_sig_base:
        wrapped_base = wrap_sig_base(sig_base, max_len)
        sections.append("Signature Base:\n" +
                        _artwork_block(wrapped_base))

    signed_msg = request_signed.render()
    wrapped_msg = wrap_http_block(signed_msg, max_len)
    sections.append("Signed HTTP Request:\n" +
                    _artwork_block(wrapped_msg, "http-message"))

    return "\n\n".join(sections)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("request", metavar="REQUEST", type=Path,
                   help="File containing the HTTP request in HTTP/1.1 text format")
    p.add_argument("--key", "-k", required=True, type=Path,
                   help="Key file (JWK JSON or PEM)")
    p.add_argument("--key-id", "-K",
                   help="Key ID (kid); auto-detected from JWK if omitted")
    p.add_argument("--alg", "-a",
                   help=f"Signing algorithm; required for RSA keys. "
                        f"One of: {', '.join(ALGORITHM_MAP)}")
    p.add_argument("--covered", "-c", nargs="+", metavar="COMPONENT",
                   default=["@method", "@authority", "@target-uri"],
                   help='Covered components (default: @method @authority @target-uri)')
    p.add_argument("--label", "-l", default="sig1",
                   help="Signature label (default: sig1)")
    p.add_argument("--created", type=int, default=None,
                   help="Unix timestamp for 'created' parameter (default: now)")
    p.add_argument("--nonce",
                   help="Nonce value for the signature")
    p.add_argument("--tag",
                   help="Application-specific tag for the signature")
    p.add_argument("--include-alg-param", action="store_true",
                   help="Include the 'alg' parameter in Signature-Input")
    p.add_argument("--runtime-key", action="store_true",
                   help="Embed the public key in the 'pub' signature parameter "
                        "per the draft's Embedding a Public Key Value section. "
                        "Implies --include-alg-param and --no-keyid.")
    p.add_argument("--no-keyid", action="store_true",
                   help="Omit the 'keyid' parameter from Signature-Input")
    p.add_argument("--output", "-o", type=Path, default=None,
                   help="Output file (default: stdout)")
    p.add_argument("--width", "-w", type=int, default=69,
                   help="Maximum line width for RFC8792 wrapping (default: 69)")
    p.add_argument("--show-sig-base", action="store_true",
                   help="Include the signature base in the output")
    p.add_argument("--show-keys", action="store_true",
                   help="Include public key material in the output")
    p.add_argument("--show-original", action="store_true",
                   help="Include the original (unsigned) request in the output")
    # Direct output targets: each writes only that artifact's content, with no
    # section label or fence, prefixed with the RFC 8792 note when wrapped.
    # Suitable for kramdown-rfc {::include ...} files.
    p.add_argument("--content-digest", action="store_true",
                   help="Compute a SHA-256 Content-Digest of the request body "
                        "and add it to the message before signing")
    p.add_argument("--out-signed", type=Path, default=None,
                   help="Write the signed HTTP message to this file")
    p.add_argument("--out-sig-base", type=Path, default=None,
                   help="Write the signature base to this file")
    p.add_argument("--out-digest", type=Path, default=None,
                   help="Write the Content-Digest header line to this file "
                        "(implies --content-digest)")
    return p


def main() -> None:
    args = build_arg_parser().parse_args()

    # Load key
    key = load_key(args.key, key_id=args.key_id, algorithm_override=args.alg)

    # Parse request
    request_text = args.request.read_text()
    request = parse_http_request(request_text)
    original = parse_http_request(request_text)  # keep a clean copy

    # Content-Digest: compute over the body and add before signing so it can
    # be a covered component. --out-digest implies computing the digest.
    digest_value: Optional[str] = None
    if args.content_digest or args.out_digest is not None:
        digest_value = content_digest_sha256(request.body or b"")
        request.headers["Content-Digest"] = digest_value

    # --runtime-key forces the alg parameter to be present
    include_alg = args.include_alg_param or args.runtime_key

    # Build signer
    signer = InspectableSigner(
        signature_algorithm=key.algorithm,
        key_resolver=key.as_resolver(),
    )

    # The draft omits keyid whenever the key is not identified by reference:
    # runtime key introduction carries pub instead, and presentation to the RS
    # relies on the access token binding.
    signer.drop_keyid = args.no_keyid or args.runtime_key

    if args.runtime_key:
        if key.public_pem is None:
            raise SystemExit("--runtime-key requires a key with public material")
        signer.extra_params = runtime_key_params(key.public_pem, key.algorithm)

    created_dt = (
        datetime.datetime.fromtimestamp(args.created)
        if args.created is not None
        else datetime.datetime.now()
    )

    signer.sign(
        request,
        key_id=key.key_id,
        created=created_dt,
        nonce=args.nonce,
        tag=args.tag,
        label=args.label,
        include_alg=include_alg,
        covered_component_ids=args.covered,
    )

    sig_base = signer.last_sig_base or ""

    # Direct artifact outputs: clean content, NOTE-prefixed when wrapped.
    if args.out_signed is not None:
        content = _with_wrap_note(wrap_http_block(request.render(), args.width))
        args.out_signed.write_text(content + "\n")
        print(f"Wrote signed message to {args.out_signed}", file=sys.stderr)

    if args.out_sig_base is not None:
        content = _with_wrap_note(wrap_sig_base(sig_base, args.width))
        args.out_sig_base.write_text(content + "\n")
        print(f"Wrote signature base to {args.out_sig_base}", file=sys.stderr)

    if args.out_digest is not None:
        content = _with_wrap_note(
            wrap_line("Content-Digest: " + (digest_value or ""),
                      args.width, is_binary=True))
        args.out_digest.write_text(content + "\n")
        print(f"Wrote content-digest to {args.out_digest}", file=sys.stderr)

    # If any direct output target was given, skip the combined stdout report
    # unless an explicit --output was also requested.
    any_target = any(t is not None for t in
                     (args.out_signed, args.out_sig_base, args.out_digest))
    if any_target and args.output is None:
        return

    output = format_output(
        request_original=original,
        request_signed=request,
        sig_base=sig_base,
        key=key,
        max_len=args.width,
        show_sig_base=args.show_sig_base,
        show_keys=args.show_keys,
        show_original=args.show_original,
    )

    if args.output:
        args.output.write_text(output + "\n")
        print(f"Written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
