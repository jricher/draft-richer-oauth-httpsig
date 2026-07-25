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

normative:
    BCP195:
    DIGEST: RFC9530
    HTTP: RFC9111
    JWK: RFC7517
    OAUTH: RFC6749
    OAUTH-BEARER: RFC6750
    STRUCTURED: RFC9651
    MTLS: RFC8705
    HTTPSIG: RFC9421
    DPOP: RFC9449
    RAR: RFC9636
    PAR: RFC9126
    DYNREG: RFC7591
    JSON: RFC8259
    HTTPAUTH: RFC7235
    RFC8032:

informative:
    I-D.ietf-oauth-signed-http-request:
    SIGNED-INTROSPECTION: RFC9701

--- abstract

This extension to the OAuth 2.0 authorization framework defines a method for using
HTTP Message Signatures to bind access tokens to keys held by OAuth 2.0 clients.

--- middle

# Introduction

The OAuth 2.0 framework provides methods for clients to get delegated access tokens from an
authorization server for accessing protected resources. The access tokens at the center
of OAuth 2.0 can be bound to a variety of different mechanisms, including bearer tokens,
mutual TLS, or other presentation mechanisms.

Bearer tokens are simple to implement but also have the significant security downside of
allowing anyone who sees the access token to use that token. {{HTTPSIG}} defines a generic
mechanism that is used to sign HTTP requests and responses.

This specification defines means to bind access tokens to a key held by the client, a token type
value and token response for indicating that a token is meant to be used with {{HTTPSIG}}
presentation, and a method for presenting bound access tokens in HTTP requests using
{{HTTPSIG}}.

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

As part of its registration, a client MUST indicate which method it will use.

\[\[ Editor's note: do we want to add a client metadata parameter to signal this, as well as an AS/RS metadata parmaeter to signal support for each type? \]\]

\[\[ Editor's note: Are there any other patterns of key introduction we should cover? I put PAR in the appendix as a note. \]\]

## Pre-Registration of Keys {#preregister}

A client pre-registering its keys for {{HTTPSIG}} binding MUST include the key in its registered `jwks` value or make it available from its `jwks_uri` endpoint. The JWK MUST have a `kid` field and MUST indicate a signing algorithm in its `alg` field. The key ID for the public used for HTTP Message Signature bound access tokens MUST be identified using the `httpsig_bound_access_token_kid` field in the client's metadata.

\[\[ Editor's note: do we want to have a client field for the signing alg or just leave that to the key all the time? I prefer to keep it in the key. \]\]

A pre-registered key MAY be a shared secret (such as for use in an HMAC signature), but public key cryptography is RECOMMENDED.

If the key is pre-registered, the signature algorithm MUST be derived from the indicated key and the `alg` signature parameter MUST NOT be used.

Note that pre-registration can occur statically or dynamically (such as by using {{DYNREG}}), as long as the key is associated with the client's `client_id` before the token request is made.

## Token Request Key Introduction {#runtime}

Instead of pre-registering a key, a client can introduce its key during the token request in a similar fashion as {{DPOP}}.

To use this mode, the client MUST:

* Include the `alg` signature parameter with a valid value from the HTTP Message Signatures Algorithms Registry indicating an asymmetric signature algorithm.
* Present its public key in the as described in {{embed-keys}}.
* Include the `kid` signature parameter uniquely identifying the key.

The included key MUST be appropriate for the indicated algorithm.

## Token Request {#request}

The presence of an HTTP Message Signature with the tag "httpsig-oauth-token-request" indicates that the client is requesting a bound token. The client MUST include a message signature of the indicated key.

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
- `keyid` the `kid` value for the key to be used for binding the token; if client uses pre-registered keys as in {{preregister}}, the value MUST match the `httpsig_bound_access_token_kid` value

Additionally, if the key is presented at runtime, the parameters and public key MUST be included as signature parameters as defined in {{runtime}}.

An example request to the token endpoint (using a runtime-provided key here) can look like the following:

~~~ http-message
{::include tools/examples/token-request-signed.http}
~~~

# Embedding a Public Key Value {#embed-keys}

When encoding a public key value in a runtime request as in {{runtime}}, the client includes the public key material appropriate to the signature algorithm being used.

## Elliptic Curve

If the `alg` value is `ecdsa-p256-sha256` or `ecdsa-p384-sha384`, the public key is encoded in two additional signature parameters and values attached to the signature input:

- `pub_key_x`: the big-endian encoded, zero-padded bytes of the key's X value, encoded as a Byte Sequence
- `pub_key_y`: the big-endian encoded, zero-padded bytes of the key's Y value, encoded as a Byte Sequence

For `ecdsa-p256-sha256`, the key values are padded to exactly 32 bytes each. For `ecdsa-p384-sha384`, the key values are padded to exactly 48 bytes each.

## Edwards Elliptic Curve

If the `alg` value is `ed25519`, the public key is encoded in one additional signature parameter and value attached to the signature input:

- `pub_key_a`: the little-endian encoded compressed Edwards point defined in {{RFC8032}}, encoded as a Byte Sequence

The key value is exactly 32 bytes in length.

## RSA

If the `alg` value is `rsa-pss-sha512` or `rsa-v1_5-sha256`, the public key is encoded in two additional signature parameters and values attached to the signature input:

- `pub_key_n`: the big-endian encoded unsigned modulus of the key (no sign byte and no leading 0x00 octet), encoded as a Byte Sequence
- `pub_key_e`: the big-endian encoded exponent of the key, encoded as a Byte Sequence

# Issuing an HTTP Message Signature Bound Access Token {#issuing}

The AS MUST validate the signature of the token request sent in {{request}} against the identified key and the algorithm associated with that key.

The request MUST fail with an error if any of the following occur:

- The key named in `kid` cannot be found or is not associated with the requesting client
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
Authorization: hTpTsIg 2340897.34j123-134uh2345n
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
- `keyid` the `kid` value for the key used to sign the request

The client MUST NOT include an `alg` signature parameter.

For example, the following signed request includes a signature with the needed parameters:

~~~ http-message
{::include tools/examples/present-request-signed.http}
~~~

# Validating an HTTP Message Signature Bound Access Token Request {#validating}

In order for a request protected by an HTTP Message Signature bound access token to be considered valid, the RS MUST perform the following checks:

- The presented signature validates using the key associated with the token
- The signature validates using the algorithm associated with the key
- The `created` value is not too far in the past (e.g. 30 seconds to account for clock skew and network delays)
- The `nonce` value has not been previously used within the time validity window of this request
- The `tag` value is "httpsig-oauth"
- The covered components and parameters include all items enumerated in {{presenting}}

If the request includes an entity body (such as a POST, PUT, or QUERY) and a digest as per {{DIGEST}}, the RS MUST validate the digest.

If the request includes multiple signatures tagged "httpsig-oauth", all signatures MUST be validated.

For example, to validate the request:

~~~ http-message
{::include tools/examples/present-request-signed.http}
~~~

The RS determines the key bound to the token and validates the `kid` value against that key. The RS determines the algorithm from the key and performs signature validation per {{HTTPSIG}} on the

In this example, the client has a key with the `kid` value of `test-key-rsa-pss` which uses the JWA `alg` value of `PS512`. The signature input string is:

~~~
{::include tools/examples/rs-sig-base.sigbase}
~~~

This results in the following signed HTTP message, including the access token.

~~~ http-message
{::include tools/examples/rs-request-signed.http}
~~~

An RS receiving such a signed message and a bound access token MUST verify the HTTP Message Signature as described in {{HTTPSIG}}. The RS MUST verify that all required portions of the HTTP request are covered by the signature by examining the contents of the signature parameters.


# Acknowledgements {#Acknowledgements}

# IANA Considerations {#IANA}

\[\[ TBD: register the token type and new parameters into their appropriate registries, as well as the JWT and introspection parameters needed for confirmation methods. \]\]

# Security Considerations {#Security}

\[\[ TBD. \]\]

- All requests have to be over TLS or equivalent as per {{BCP195}}.
- Leakage of a private key alongside a token allows for re-presentation of that token.
- Insufficient coverage of a message allows a signature to be attached to a different message.
- Failure to check derived attributes allows a signature to be replayed.
- Signatures could be replayed outside of their vailidty window if not checked.

# Privacy Considerations {#Privacy}

\[\[ TBD. \]\]

- Re-use of a public-key for tokens at multiple RS's can allow tracking of a client/user combination based on the key identity.

--- back

# Document History {#history}

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
