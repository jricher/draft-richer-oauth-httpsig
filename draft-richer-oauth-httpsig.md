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
    JWK: RFC7517
    JWA: RFC7518
    POPKEY: RFC7800
    RFC9864:
    RFC8032:
    FIPS204:
        title: "Module-Lattice-Based Digital Signature Standard"
        author:
            org: "National Institute of Standards and Technology (NIST)"
        date: 2024-08
        seriesinfo:
            "NIST": "FIPS 204"
            "DOI": "10.6028/NIST.FIPS.204"
        target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
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

As part of its registration, a client MUST indicate which method it will use, using either the `httpsig_key_binding_method` client registration metadata parameter defined in {{IANA}} when using Dynamic Client Registration ({{DYNREG}}) or Client ID Metadata Document ({{I-D.ietf-oauth-client-id-metadata-document}}), or via an out of band method.

\[\[ Editor's note: do we want to add an AS/RS metadata parameter to signal support for each type? \]\]

\[\[ Editor's note: Are there any other patterns of key introduction we should cover? I put PAR in the appendix as a note. \]\]

## Pre-Registration of Keys {#preregister}

A client pre-registering its key for {{HTTPSIG}} binding MUST include the key in its registered `jwks` value or make it available from its `jwks_uri` endpoint. The JWK MUST have a `kid` member and MUST indicate a signing algorithm in its `alg` member.

The key MUST be an asymmetric key, and the registered JWK MUST be its public key. A shared secret MUST NOT be used to bind an access token, as described in {{Security}}.

The client selects which of its registered keys the token is bound to when it makes the token request, as described in {{request}}. The client's metadata names the key set rather than a key within it, allowing a client to add and retire keys without any change to its registration.

Note that pre-registration can occur statically or dynamically (such as by using {{DYNREG}}), as long as the key is associated with the client's `client_id` before the token request is made.

### Example Client Registration

A client can publish its key binding metadata as part of a {{I-D.ietf-oauth-client-id-metadata-document}} alongside its `jwks` or `jwks_uri` values. For example, a client with the `client_id` value `https://client.example.com/client-metadata.json` would publish the following document at that URL, indicating that it uses a pre-registered key:

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
                "alg": "Ed25519"
            }
        ]
    },
    "httpsig_key_binding_method": "preregistered"
}
~~~

## Token Request Key Introduction {#runtime}

Instead of pre-registering a key, a client can introduce its key during the token request in a similar fashion as {{DPOP}}.

A client using this method presents its public key in the token request itself, as described in {{request}}. The key is not registered with the AS beforehand, and the AS binds a token to the presented key subject to its own policy.

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

The signature MUST include the following signature parameters:

- `created` a timestamp for signature creation; this MUST be within a small number of seconds of issuance (e.g. 30 seconds to account for clock skew)
- `nonce` a random unique value that the AS can use to prevent signature replay within the small validity time window
- `tag` a string indicating that this is being used for requesting a bound token, MUST be the value "httpsig-oauth-token-request"

The remaining signature parameters identify the key, and depend on the key binding method.

With a pre-registered key as in {{preregister}}:

- `keyid` MUST be included. Its value MUST match the `kid` member of a key in the client's registered `jwks` value or at its `jwks_uri` endpoint.
- `alg` and `pub` MUST NOT be included. The algorithm comes from the identified key, as described in {{alg-preregistered}}.

With a runtime-introduced key as in {{runtime}}:

- `alg` MUST be included, with a value from the "HTTP Signature Algorithms" registry as described in {{alg-runtime}}.
- `pub` MUST be included, carrying the public key as described in {{embed-keys}}.
- `keyid` MUST NOT be included, as the key is presented in full.

An example token request using a pre-registered key can look like the following:

~~~ http-message
{::include tools/examples/token-request-prereg-signed.http}
~~~

An example token request introducing the same key at runtime can look like the following:

~~~ http-message
{::include tools/examples/token-request-signed.http}
~~~

# Signature Algorithms {#algorithms}

The two key binding methods name signature algorithms in different registries. A key bound by one method is never used with the other, and this document neither defines nor relies on any correspondence between the two registries.

## Pre-Registered Keys {#alg-preregistered}

A pre-registered key is a JSON Web Key {{JWK}} whose `alg` value names an algorithm from the "JSON Web Signature and Encryption Algorithms" registry established by {{JWA}}. Signatures made with such a key use the JOSE signing algorithms of {{Section 3.3.7 of HTTPSIG}}, which take the algorithm from the key material. The `alg` signature parameter is not used with those algorithms, and the client MUST NOT include it.

The JWK's `alg` value MUST be fully specified. A polymorphic identifier such as `EdDSA`, which names a different signature algorithm depending on the key it is used with, MUST NOT be used. The fully specified equivalent defined in {{RFC9864}} is used in its place.

## Runtime-Introduced Keys {#alg-runtime}

A runtime-introduced key names its algorithm in the `alg` signature parameter, using a value from the "HTTP Signature Algorithms" registry established by {{Section 6.2 of HTTPSIG}}, as required by {{Section 3.3 of HTTPSIG}}. The algorithm MUST be an asymmetric signature algorithm for which this document defines a public key encoding in {{embed-keys}}.

\[\[ Editor's note: we keep the two paths apart on purpose. Bridging them would mean asserting that some JWS algorithm and some "HTTP Signature Algorithms" entry are the same algorithm, and the two registries are maintained independently with nothing requiring either to track the other. Are we happy to pay a second code path at the RS to avoid that? \]\]

# Embedding a Public Key Value {#embed-keys}

When encoding a public key value in a runtime request as in {{runtime}}, the client includes the public key material in the `pub` signature parameter attached to the signature input, encoded as a Byte Sequence as defined in {{STRUCTURED}}.

The contents of the `pub` signature parameter are the public key material appropriate to the signature algorithm indicated by the `alg` signature parameter, as defined in the following sections.

## ECDSA

If the `alg` value is `ecdsa-p256-sha256` or `ecdsa-p384-sha384`, the `pub` signature parameter contains the uncompressed point representation of the public key, which is the single octet `0x04` followed by the big-endian, zero-padded, fixed-length encodings of the key's X and Y coordinates. This is the output of the Elliptic-Curve-Point-to-Octet-String Conversion in Section 2.3.3 of {{SEC1}} with point compression off.

For `ecdsa-p256-sha256`, the X and Y values are exactly 32 octets each and the `pub` value is exactly 65 octets. For `ecdsa-p384-sha384`, the X and Y values are exactly 48 octets each and the `pub` value is exactly 97 octets.

## Ed25519

If the `alg` value is `ed25519`, the `pub` signature parameter contains the Ed25519 public key `A`, which is the encoding of the point `[s]B` as specified in {{Section 5.1.5 of RFC8032}}.

The key value is exactly 32 octets in length.

## ML-DSA

If the `alg` value indicates an ML-DSA algorithm, the `pub` signature parameter contains the ML-DSA public key encoded as described in Section 7.2 of {{FIPS204}}, which is the output of the `pkEncode` routine, Algorithm 22 of {{FIPS204}}.

The value is exactly 1312 octets for the ML-DSA-44 parameter set, 1952 octets for ML-DSA-65, and 2592 octets for ML-DSA-87.

\[\[ Editor's note: ML-DSA algorithm identifiers for use with {{HTTPSIG}} are being defined in separate work. We should add a reference here once that document is available. \]\]


# HTTP Signature Key Confirmation Method {#htsk}

A key introduced at runtime as in {{runtime}} is not a JSON Web Key and has no JWK representation, so the confirmation methods of {{POPKEY}} cannot carry it. This document defines the HTTP Signature Key confirmation method for that purpose, using the member name `htsk`.

The value of the `htsk` member is a JSON object with two members:

- `alg`: the algorithm identifier from the "HTTP Signature Algorithms" registry, as a string
- `pub`: the base64url encoding, without padding, of the `pub` octets defined in {{embed-keys}} for that algorithm

Both members MUST be present. A recipient MUST reject the confirmation if it does not recognize the `alg` value or if the `pub` value is not a well-formed public key for that algorithm.

~~~ json
{
    "alg": "ed25519",
    "pub": "iuemcj_GhRHmY_yCsMlDNp3BQgPZDdG00VRsg_BgU3s"
}
~~~

The `htsk` member is used in the `cnf` claim of a JWT and in the `cnf` member of a token introspection response, as described in {{issuing}}.

# Issuing an HTTP Message Signature Bound Access Token {#issuing}

The AS MUST validate the signature of the token request sent in {{request}} against the identified key and the algorithm associated with that key.

The request MUST fail with an error if any of the following occur:

- With a pre-registered key as in {{preregister}}, the key named in `keyid` cannot be found or is not associated with the requesting client
- With a pre-registered key as in {{preregister}}, the `alg` or `pub` signature parameter is present, or the JWK's `alg` value is not a fully specified asymmetric algorithm as required by {{alg-preregistered}}
- With a runtime-introduced key as in {{runtime}}, the `keyid` signature parameter is present, or the `alg` or `pub` signature parameter is absent
- With a runtime-introduced key as in {{runtime}}, the `alg` value is not an asymmetric algorithm for which this document defines a public key encoding in {{embed-keys}}, or the `pub` value is not a well-formed public key for it
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

The confirmation carries the key the token is bound to, allowing an RS to validate a presented signature without reference to the client's registration. The member carrying the key depends on the key binding method and indicates which algorithm registry applies:

- A pre-registered key is carried in the `jwk` member of the `cnf` claim, as defined in {{Section 3.2 of POPKEY}}, and names its algorithm in the JWK's `alg` value as in {{alg-preregistered}}
- A runtime-introduced key is carried in the HTTP Signature Key (`htsk`) member defined in {{htsk}}, and names its algorithm in that object's `alg` member as in {{alg-runtime}}

## Encoding Confirmation in a JWT

A token bound to a pre-registered key can look like the following:

~~~ json
{
    "iss": "https://server.example.com",
    "aud": "https://resource.example.com",
    "cnf": {
        "jwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "Ed25519",
            "x": "iuemcj_GhRHmY_yCsMlDNp3BQgPZDdG00VRsg_BgU3s"
        }
    }
}
~~~

A token bound to a runtime-introduced key can look like the following:

~~~ json
{
    "iss": "https://server.example.com",
    "aud": "https://resource.example.com",
    "cnf": {
        "htsk": {
            "alg": "ed25519",
            "pub": "iuemcj_GhRHmY_yCsMlDNp3BQgPZDdG00VRsg_BgU3s"
        }
    }
}
~~~

A confirmation MUST carry exactly one of these members.

## Returning Confirmation in Token Introspection

The same `cnf` member is returned in a token introspection response.

\[\[ Editor's note: we need to register `htsk` in the "JWT Confirmation Methods" registry. Nothing further is needed for introspection, since `cnf` is already a registered token introspection response parameter and carries the same structure. \]\]

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

The signature MUST include the following signature parameters:

- `created` a timestamp for signature creation; this MUST be within a small number of seconds of issuance (e.g. 30 seconds to account for clock skew)
- `nonce` a random unique value that the AS can use to prevent signature replay within the small validity time window
- `tag` a string indicating that this is being used for requesting a bound token, MUST be the value "httpsig-oauth"

The client MUST NOT include the `alg`, `keyid`, or `pub` signature parameters, as the RS determines the key from the binding of the presented access token.

For example, the following signed request includes a signature with the needed signature parameters:

~~~ http-message
{::include tools/examples/present-request-signed.http}
~~~

# Validating an HTTP Message Signature Bound Resource Request {#validating}

In order for a request protected by an HTTP Message Signature bound access token to be considered valid, the RS MUST perform the following checks:

- The presented signature validates using the key the token is bound to
- For a `jwk` confirmation, the signature validates under the HTTP_VERIFY application of the JWS algorithm named by the JWK's `alg` member, applied as described in {{Section 3.3.7 of HTTPSIG}}
- For an `htsk` confirmation, the signature validates under the HTTP_VERIFY primitive of the named "HTTP Signature Algorithms" entry
- The `created` value is not too far in the past (e.g. 30 seconds to account for clock skew and network delays)
- The `nonce` value has not been previously used within the time validity window of this request
- The `tag` value is "httpsig-oauth"
- The covered components and signature parameters include all items enumerated in {{presenting}}, including the Authorization header field
- The `alg`, `keyid`, and `pub` signature parameters are not present

The check on the `alg`, `keyid`, and `pub` signature parameters, and the corresponding checks in {{issuing}}, are required rather than optional. {{Section 3.2.1 of HTTPSIG}} allows an application to impose requirements beyond those of {{HTTPSIG}}, but requires that it enforce them during verification and fail any signature that does not conform.

If the request includes an entity body (such as a POST, PUT, or QUERY) and a digest as per {{DIGEST}}, the RS MUST validate the digest.

If the request includes multiple signatures tagged "httpsig-oauth", all signatures MUST be validated.

For example, to validate the request:

~~~ http-message
{::include tools/examples/rs-request-signed.http}
~~~

Nothing in the request identifies the key, so the RS determines the key and the algorithm from the token's confirmation method (in this example, assume the RS introspects the token to get it). The same request validates under either binding method, and only the confirmation differs.

If the token was issued for a pre-registered key, the confirmation carries the JWK and the algorithm is the JWS algorithm named by its `alg` member:

~~~ json
{
    "cnf": {
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "x": "R4YT13Ra4frLCH75BdM53OEHYi_YY2eQgR43BWWQpVw",
            "y": "UFVFPBGODokYW06OXCqDskhZSU3RpUI6fR8_OCz2doo"
        }
    }
}
~~~

If the token was issued for a key introduced at runtime, the confirmation carries the same key as an `htsk` member, and the algorithm is the "HTTP Signature Algorithms" value named by its `alg` member:

~~~
{
    "cnf": {
        "htsk": {
            "alg": "ecdsa-p256-sha256",
            "pub": "BEeGE9d0WuH6ywh--QXTOdzhB2Iv2GNnkIEeNwVlkKVcUF\
              VFPBGODokYW06OXCqDskhZSU3RpUI6fR8_OCz2doo"
        }
    }
}
~~~

The signature base is the same in either case:

~~~
{::include tools/examples/rs-sig-base.sigbase}
~~~

The RS then calculates the signature validation against the signature base using the key using the algorithm appropriate HTTP_VERIFY function, per {{HTTPSIG}}.

# Acknowledgements {#Acknowledgements}

# IANA Considerations {#IANA}

\[\[ TBD: register the `httpsig` token type, the `httpsig_key_binding_method` client registration metadata parameter, the `pub` signature parameter defined in {{embed-keys}} in the "HTTP Signature Metadata Parameters" registry established by {{HTTPSIG}}, and the HTTP Signature Key (`htsk`) confirmation method in the "JWT Confirmation Methods" registry. The `jwk` confirmation method is already registered by {{POPKEY}}, and `cnf` is already a registered token introspection response parameter. \]\]

# Security Considerations {#Security}

\[\[ TBD. \]\]

- All requests have to be over TLS or equivalent as per {{BCP195}}.
- Leakage of a private key alongside a token allows for re-presentation of that token.
- Insufficient coverage of a message allows a signature to be attached to a different message.
- Failure to check derived attributes allows a signature to be replayed.
- Signatures could be replayed outside of their vailidty window if not checked.
- An access token cannot be bound to a shared secret. Every party that validates a presented signature needs the key that produced it, and a verifier holding symmetric key material can produce a valid signature of its own as per {{Section 7.3.3 of HTTPSIG}}. Binding a token to a shared secret would allow every RS that accepts it to produce requests indistinguishable from the client's. The client's registered `jwks` and `jwks_uri` values carry public keys only ({{DYNREG}}).

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
    - Kept each binding method within a single algorithm registry, with no correspondence defined between the two
    - Required pre-registered JWK algorithm identifiers to be fully specified
    - Defined the `jwk` confirmation method for pre-registered keys and a new HTTP Signature Key (`htsk`) confirmation method for runtime-introduced keys
    - Removed the `httpsig_bound_access_token_kid` client metadata field in favor of selecting a pre-registered key with the `keyid` signature parameter

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

Similarly to {{MTLS}}, {{HTTPSIG}} could be used as a generic client authentication mechanism for the client calling the AS for any authenticated call, including token PAR, the token endpoint. Since {{HTTPSIG}} allows for multiple signatures with different signature parameters (including `tag`), this could be layered on top of even the runtime token request key binding, allowing a client to use one key for authentication and another for token use.

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
