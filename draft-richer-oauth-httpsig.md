---
title: 'OAuth Proof of Possession Tokens with HTTP Message Signatures'
docname: draft-richer-oauth-httpsig-latest
category: std

ipr: trust200902
area: Security
workgroup: OAUTH
keyword: Internet-Draft

stand_alone: yes
pi: [toc, tocindent, sortrefs, symrefs, strict, compact, comments, inline, docmapping]

author:
  - ins: J. Richer
    name: Justin Richer
    organization: MongoDB
    email: ietf@justin.richer.org
    role: editor
  - ins: A. Parecki
    name: Aaron Parecki
    organization: Okta
    email: aaron@parecki.com
  - ins: P. Bastian
    name: Paul Bastian
    organization: Bundesdruckerei
    email: paul.bastian@posteo.de
  - ins: F. Skokan
    name: Filip Skokan
    organization: Okta
    email: panva.ip@gmail.com
  - ins: C. Bormann
    name: Christian Bormann
    organization: SPRIND
    email: chris.bormann@gmx.de

normative:
    BCP195:
    DIGEST: RFC9530
    OAUTH: RFC6749
    STRUCTURED: RFC9651
    MTLS: RFC8705
    HTTPSIG: RFC9421
    DPOP: RFC9449
    PAR: RFC9126
    DYNREG: RFC7591
    HTTPAUTH: RFC7235
    RFC8032:
    RFC9964:
    SEC1:
        target: https://www.secg.org/sec1-v2.pdf
        title: "SEC 1: Elliptic Curve Cryptography"
        author:
            org: Certicom Research
        date: 2009-05
        refcontent: "Standards for Efficient Cryptography, Version 2.0"

informative:
    I-D.ietf-oauth-signed-http-request:
    I-D.ietf-oauth-client-id-metadata-document:
    SIGNED-INTROSPECTION: RFC9701

--- abstract

This extension to the OAuth 2.0 authorization framework defines a method for using
HTTP Message Signatures to bind access tokens to keys held by OAuth 2.0 clients.

--- middle

# Introduction

The OAuth 2.0 framework provides methods for clients to get delegated access tokens from an
authorization server for accessing protected resources.

OAuth access tokens can be bearer tokens, or bound to a variety of mechanisms including mutual TLS, DPoP, or other presentation mechanisms.
Bearer tokens are simple to implement but also have the significant security downside of
allowing anyone who sees the access token to use that token.

{{HTTPSIG}} defines a generic mechanism that is used to sign HTTP requests and responses.

This specification defines means to bind access tokens to a key held by the client, a token type
value, a token response for indicating that a token is meant to be used with {{HTTPSIG}}
presentation, and a method for presenting bound access tokens in HTTP requests using {{HTTPSIG}}.

This work complements and builds on experience with {{DPOP}} and {{MTLS}}, as well as
implementations of {{I-D.ietf-oauth-signed-http-request}}, a spiritual predecessor to this
specification and other forms of OAuth proof-of-possession work.

\[\[ Editor's note: we want to give developers clear guidance on when to use HTTPSig vs. DPoP vs. mTLS vs. Bearer vs. whatever else \]\]

## Terminology

{::boilerplate bcp14}

This document contains non-normative examples of partial and complete HTTP messages, JSON structures, URLs, query components, keys, and other elements. Some examples use a single trailing backslash '\' to indicate line wrapping for long values, as per {{!RFC8792}}. The `\` character and leading spaces on wrapped lines are not part of the value.

# Requesting an HTTP Message Signature Bound Access Token {#binding}

To bind an access token to a key, the AS needs to know which key to bind to which token. This specification defines two common methods depending on the needs of the client:

- A static method that depends on key material available as part of the client registration
- A runtime method that allows a client to introduce key material during the token request phase of {{OAUTH}}

As part of its registration, a client MUST indicate which method it will use, using either the `httpsig_key_binding_method` client registration metadata parameter defined (TBD) in {{IANA}} when using Dynamic Client Registration ({{DYNREG}}) or Client ID Metadata Document ({{I-D.ietf-oauth-client-id-metadata-document}}), or via an out of band method.

\[\[ Editor's note: do we want to add an AS/RS metadata parameter to signal support for each type? \]\]

\[\[ Editor's note: Are there any other patterns of key introduction we should cover? I put PAR in the appendix as a note. \]\]

## Pre-Registration of Keys {#preregister}

A client pre-registering its keys for {{HTTPSIG}} binding MUST include the key in its registered `jwks` value or make it available from its `jwks_uri` endpoint. The JWK MUST have a `kid` field and MUST indicate a signing algorithm in its `alg` field. The key ID for the public key used for HTTP Message Signature bound access tokens MUST be identified using the `httpsig_bound_access_token_kid` field in the client's metadata.

\[\[ Editor's note: do we want to have a client field for the signing alg or just leave that to the key all the time? I prefer to keep it in the key. \]\]

A pre-registered key MUST be an asymmetric key, and the registered JWK MUST be its public key. A shared secret MUST NOT be used to bind an access token; see {{Security}}.

If the key is pre-registered, the signature algorithm MUST be derived from the indicated key. The client MUST NOT include the `alg` or `pub` signature parameters.

Note that pre-registration can occur statically or dynamically (such as by using {{DYNREG}}), as long as the key is associated with the client's `client_id` before the token request is made.

### Example Client Registration

A client can publish the key binding parameters as part of a {{I-D.ietf-oauth-client-id-metadata-document}} alongside its `jwks` or `jwks_uri` values. For example, a client with the `client_id` value `https://client.example.com/client-metadata.json` would publish the following document at that URL, indicating that it uses a pre-registered key:

~~~ json
{
    "client_id": "https://client.example.com/client-metadata.json",
    "client_name": "Example Client",
    "jwks": {
        "keys": [
            {
                "kty": "OKP",
                "use": "sig",
                "crv": "Ed25519",
                "kid": "j-0Ny45NWmqGq6GQ",
                "x": "iuemcj_GhRHmY_yCsMlDNp3BQgPZDdG00VRsg_BgU3s",
                "alg": "EdDSA"
            }
        ]
    },
    "httpsig_bound_access_token_kid": "j-0Ny45NWmqGq6GQ",
    "httpsig_key_binding_method": "preregistered"
}
~~~

## Token Request Key Introduction {#runtime}

Instead of pre-registering a key, a client can introduce its key during the token request in a similar fashion as {{DPOP}}.

To use this mode, the client MUST:

* Include the `alg` signature parameter with a value from the "HTTP Signature Algorithms" registry, indicating an asymmetric signature algorithm for which this document defines a public key encoding in {{embed-keys}}.
* Include its public key in the `pub` signature parameter as described in {{embed-keys}}.

The client MUST NOT include the `keyid` signature parameter.

The included key MUST be appropriate for the indicated algorithm.

## Token Request {#request}

The presence of an HTTP Message Signature with the tag `httpsig-oauth-token-request` indicates that the client is requesting a bound token. The client MUST include a message signature of the indicated key.

Additionally, the client MUST calculate and include the digest of the request body and include it as the Content-Digest header defined in {{DIGEST}}.

For example, a form-encoded request body consisting of:

~~~
{::include tools/examples/token-request-body.form}
~~~

Would create the following Content-Digest header:

~~~
{::include tools/examples/content-digest.hdr}
~~~

A client using this method MUST sign the token endpoint request using {{HTTPSIG}} with the appropriate key. The covered components MUST include:

- `@method` the HTTP method of the request
- `@target-uri` the full request URI of the request (note that this includes the scheme, authority, path, and query)
- `content-digest` the digest of the request body

The covered components MUST include the client's authentication, if available. If using HTTP Basic, this means including the `authorization` field.

The signature MUST include the following parameters:

- `created` a timestamp for signature creation; this MUST be within a small number of seconds of issuance (e.g. 30 seconds to account for clock skew)
- `nonce` a random unique value that the AS can use to prevent signature replay within the small validity time window
- `tag` a string indicating that this is being used for requesting a bound token, MUST be the value "httpsig-oauth-token-request"
- `keyid` the identifier for the key to be used for binding the token; this parameter is included only if the client uses pre-registered keys as in {{preregister}}, in which case the value MUST match the `httpsig_bound_access_token_kid` value

Additionally, if the key is presented at runtime, the `alg` and `pub` signature parameters MUST be included as defined in {{runtime}}.

An example request to the token endpoint (using a runtime-provided key here) can look like the following:

~~~ http-message
{::include tools/examples/token-request-signed.http}
~~~

# Embedding a Public Key Value {#embed-keys}

When encoding a public key value in a runtime request as in {{runtime}}, the client includes the public key material in the `pub` signature parameter attached to the signature input, encoded as a Byte Sequence as defined in {{STRUCTURED}}.

The contents of the `pub` parameter are the public key material appropriate to the signature algorithm indicated by the `alg` signature parameter, as defined in the following sections.

## ECDSA

If the `alg` value is `ecdsa-p256-sha256` or `ecdsa-p384-sha384`, the `pub` parameter contains the uncompressed point representation of the public key: the single octet `0x04` followed by the big-endian, zero-padded, fixed-length encodings of the key's X and Y coordinates. This is the output of the Elliptic-Curve-Point-to-Octet-String Conversion in Section 2.3.3 of {{SEC1}} with point compression off.

For `ecdsa-p256-sha256`, the X and Y values are exactly 32 octets each and the `pub` value is exactly 65 octets. For `ecdsa-p384-sha384`, the X and Y values are exactly 48 octets each and the `pub` value is exactly 97 octets.

## Ed25519

If the `alg` value is `ed25519`, the `pub` parameter contains the Ed25519 public key `A`, which is the encoding of the point `[s]B` as specified in {{Section 5.1.5 of RFC8032}}.

The key value is exactly 32 octets in length.

## ML-DSA

If the `alg` value indicates an ML-DSA algorithm, the `pub` parameter contains the ML-DSA public key, using the same encoding as the `pub` parameter of an AKP JSON Web Key defined in {{Section 3 of RFC9964}}, prior to its base64url encoding.

\[\[ Editor's note: ML-DSA algorithm identifiers for use with {{HTTPSIG}} are being defined in separate work; a reference will be added here once that document is available. \]\]

# Issuing an HTTP Message Signature Bound Access Token {#issuing}

The AS MUST validate the signature of the token request sent in {{request}} against the identified key and the algorithm associated with that key.

The request MUST fail with an error if any of the following occur:

- The client uses pre-registered keys as in {{preregister}} and the key named in `keyid` cannot be found or is not associated with the requesting client
- The client uses pre-registered keys as in {{preregister}} and the `alg` or `pub` parameter is present
- The client introduces its key at runtime as in {{runtime}} and the `keyid` parameter is present
- There is more than one signature with the tag "httpsig-oauth-token-request"
- The `created` value of the signature is too far in the past
- The `nonce` value is used more than once within the validity window of the signature

When issuing an access token bound to a key using HTTP Message Signatures, the AS associates the granted token with the key used in the requesting signature. All presentations of this token at any RS MUST contain an HTTP message signature as described in {{presenting}}.

An HTTP Message Signature bound access token MUST have a `token_type` value of `httpsig`.

~~~
HTTP 200 OK
Content-Type: application/json

{
    "access_token": "2340897.34j123-134uh2345n",
    "token_type": "httpsig"
}
~~~

The client MUST associate this returned access token with the key used to make the requst.

\[\[ Editor's note: we should define confirmation methods for access tokens here, including JWT values and introspection response values to allow the RS to verify the signature w/o the client's registration information. Leaving the following sections as placeholders. \]\]

## Encoding Confirmation in a JWT

## Returning Confirmation in Token Introspection

# Presenting an HTTP Message Signature Bound Access Token {#presenting}

HTTP Message Signature bound access token MUST be presented in an HTTP Authorization field using the `HTTPSig` authorization scheme.

~~~
Authorization: HTTPSig 2340897.34j123-134uh2345n
~~~

Note that HTTP authorization schemes defined in {{HTTPAUTH}} are case-insensitive, and so all the following are equivalent:

~~~
Authorization: HTTPSig 2340897.34j123-134uh2345n
Authorization: httpsig 2340897.34j123-134uh2345n
Authorization: HTTPSIG 2340897.34j123-134uh2345n
Authorization: Httpsig 2340897.34j123-134uh2345n
Authorization: hTtPsIg 2340897.34j123-134uh2345n
~~~

When presenting an HTTP Message Signature bound access token to an RS, the client MUST include a signature compliant with {{HTTPSIG}}. The covered components MUST include:

- `@method` the HTTP method of the request
- `@target-uri` the full request URI of the request (note that this includes the scheme, authority, path, and query)
- `authorization` the access token value being presented

The RS MAY require additional components to be covered by the signature, and the client MUST include any additional fields or components of the HTTP request that are relevant to the security of the RS. For example, if the API being served by the RS declares that incoming content type makes a material difference, the RS SHOULD require signing of the Content-Type header in addition to the above.

The request MAY include multiple signatures to serve different needs.

If the request includes an entity body (such as a POST, PUT, or QUERY), the client SHOULD calculate the digest as per {{DIGEST}} and also sign the digest header (such as Content-Digest).

The signature MUST include the following parameters:

- `created` a timestamp for signature creation; this MUST be within a small number of seconds of issuance (e.g. 30 seconds to account for clock skew)
- `nonce` a random unique value that the AS can use to prevent signature replay within the small validity time window
- `tag` a string indicating that this is being used for requesting a bound token, MUST be the value "httpsig-oauth"

The RS determines the key from the binding of the presented access token, and so the client MUST NOT include the `alg`, `keyid`, or `pub` signature parameters.

For example, the following signed request includes a signature with the needed parameters:

~~~ http-message
{::include tools/examples/present-request-signed.http}
~~~

# Validating an HTTP Message Signature Bound Resource Request {#validating}

In order for a request protected by an HTTP Message Signature bound access token to be considered valid, the RS MUST perform the following checks:

- The presented signature validates using the key bound to the token
- The signature validates using the HTTP_VERIFY algorithm associated with the key
- The `created` value is not too far in the past (e.g. 30 seconds to account for clock skew and network delays)
- The `nonce` value has not been previously used within the time validity window of this request
- The `tag` value is "httpsig-oauth"
- The covered components and parameters include all items enumerated in {{presenting}}, including the Authorization header field
- The `alg`, `keyid`, and `pub` parameters are not present

The last of these checks, and the corresponding checks in {{issuing}}, are required rather than optional: {{Section 3.2.1 of HTTPSIG}} allows an application to impose requirements beyond those of {{HTTPSIG}}, but requires that it enforce them during verification and fail any signature that does not conform.

If the request includes an entity body (such as a POST, PUT, or QUERY) and a digest as per {{DIGEST}}, the RS MUST validate the digest.

If the request includes multiple signatures tagged "httpsig-oauth", all signatures MUST be validated.

For example, to validate the request:

~~~ http-message
{::include tools/examples/rs-request-signed.http}
~~~

The RS determines the key bound to the token (in this example, assume the RS introspects the token to get the key material). The RS determines the algorithm from the key material.

In this example, the token is bound to the ECDSA P-256 key `test-key-ecdsa-p256`, giving the `ecdsa-p256-sha256` algorithm. The signature input string is:

~~~
{::include tools/examples/rs-sig-base.sigbase}
~~~

The RS then calculates the signature validation against the signature base using the key using the algorithm appropriate HTTP_VERIFY function, per {{HTTPSIG}}.

# Acknowledgements {#Acknowledgements}

# IANA Considerations {#IANA}

\[\[ TBD: register the token type and new parameters into their appropriate registries, as well as the JWT and introspection parameters needed for confirmation methods. This includes registering the `pub` signature parameter defined in {{embed-keys}} in the "HTTP Signature Metadata Parameters" registry established by {{HTTPSIG}}. \]\]

# Security Considerations {#Security}

\[\[ TBD. \]\]

- All requests have to be over TLS or equivalent as per {{BCP195}}.
- Leakage of a private key alongside a token allows for re-presentation of that token.
- Insufficient coverage of a message allows a signature to be attached to a different message.
- Failure to check derived attributes allows a signature to be replayed.
- Signatures could be replayed outside of their vailidty window if not checked.
- An access token cannot be bound to a shared secret. Every party that validates a presented signature needs the key that produced it, and {{Section 7.3.3 of HTTPSIG}} notes that a verifier holding symmetric key material is thereby able to produce a valid signature of its own. Binding a token to a shared secret would let every RS that accepts it produce requests indistinguishable from the client's. The client's registered `jwks` and `jwks_uri` values carry public keys only ({{DYNREG}}), so such a key has nowhere to be registered in any case.

# Privacy Considerations {#Privacy}

\[\[ TBD. \]\]

- Re-use of a public-key for tokens at multiple RS's can allow tracking of a client/user combination based on the key identity.

--- back

# Document History {#history}


- -03
    - Added co-authors
    - Changed inline key presentation from a header field carrying a JWK to a single `pub` signature parameter carrying the raw public key
    - Limited the inline key representation to ECDSA, Ed25519, and ML-DSA
    - Required the `alg` signature parameter for runtime key introduction
    - Removed `keyid` from runtime key introduction and from token presentation
    - Required the bound key to be asymmetric, disallowing shared secrets

- -02
    - Editorial fixes
    - Added example of client registration metadata parameter in CIMD

- -01
    - Added key binding semantics
    - Updated references
    - Updated presentation requirements
    - Added appendix for potential future work
    - Added some basic security and privacy considerations, to be expanded upon group discussion

- -00
    - Initial individual draft.

# Potential Other Work

{{HTTPSIG}} provides a generic mechanism for signing arbitrary HTTP messages, both requests and responses. While this specification is focused solely on OAuth access token issuance and usage, {{HTTPSIG}} could be used in other places in the OAuth ecosystem and this appendix exists to capture some of those ideas.

## Client Authentication

Similarly to {{MTLS}}, {{HTTPSIG}} could be used as a generic client authentication mechanism for the client calling the AS for any authenticated call, including token PAR, the token endpoint. Since {{HTTPSIG}} allows for multiple signatures with different usage parameters (including `tag`), this could be layered on top of even the runtime token request key binding, allowing a client to use one key for authentication and another for token use.

## AS Responses

Since {{HTTPSIG}} can be used to sign responses, an AS could sign its responses from backend endpoints (including the token endpoint, revocation endpoint, discovery endpoint, introspection endpoint, etc) with an issuer-based key, providing a layer of protection in addition to the TLS transport. Signed response mechanisms like {{SIGNED-INTROSPECTION}} could be replaced with this method in many use cases.

## Non-Repudiation of Requests

Since {{HTTPSIG}} allows a signed response to contain elements of the request that triggered the response, an AS or RS could use this mechanism to provide non-repudiation of a response to bind it to a particular request parameter set.

## PAR Key Introduction

Keys for this purpose could be introduced during a {{PAR}} request phase, as part of the call to the PAR endpoint.

## Accept-Signature Support

The `Accept-Signature` mechanism in {{HTTPSIG}} allows for runtime discovery of not only the applicability of signatures but also the expected coverage, for particular uses.

# Test Vectors

\[\[ Editor's note: we really should have end-to-end test vectors with keys and stuff all in here, not just inline. \]\]
