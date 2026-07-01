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

Defined in RFC6750, OAuth access tokens are bearer tokens.
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

To bind an access token to a key, the authorization server (AS) needs to know which key to bind to which token. This specification defines two common methods depending on the needs of the client:

- A static method that depends on key material available as part of the client registration
- A runtime method that allows a client to introduce key material during the token request phase of {{OAUTH}}

As part of its registration, a client MUST indicate which method it will use, using either the `httpsig_key_binding_method` client registration metadata parameter defined in {{iana-dynreg}} when using Dynamic Client Registration ({{DYNREG}}) or Client ID Metadata Document ({{I-D.ietf-oauth-client-id-metadata-document}}), or via an out of band method.

\[\[ Editor's note: do we want to add an AS/RS metadata parameter to signal support for each type? \]\]

\[\[ Editor's note: Are there any other patterns of key introduction we should cover? I put PAR in the appendix as a note. \]\]

## Pre-Registration of Keys {#preregister}

A client pre-registering its keys for {{HTTPSIG}} binding MUST include the key in its registered `jwks` value or make it available from its `jwks_uri` endpoint. The JWK MUST have a `kid` field and MUST indicate a signing algorithm in its `alg` field. The key ID for the public key used for HTTP Message Signature bound access tokens MUST be identified using the `httpsig_bound_access_token_kid` field in the client's metadata.

\[\[ Editor's note: do we want to have a client field for the signing alg or just leave that to the key all the time? I prefer to keep it in the key. \]\]

A pre-registered key MAY be a shared secret (such as for use in an HMAC signature), but public key cryptography is RECOMMENDED.

Note that pre-registration can occur statically or dynamically (such as by using {{DYNREG}}), as long as the key is associated with the client's `client_id` before the token request is made.

## Token Request Key Introduction {#runtime}

Instead of pre-registering a key, a client can introduce its key during the token request in the same fashion as {{DPOP}}.

The client MUST present its public key in the Signature-Key header field. The field is an HTTP Structured Field consisting of a Binary value containing the bytes of the {{JSON}} serialized {{JWK}} form of the key material.

The JWK MUST have a `kid` field. The key MUST be a public key (and neither a private key nor a shared secret key). The JWK MUST have an `alg` value that indicates a signature algorithm.

For example, the following JWK public key:

~~~ json
{
    "kty": "OKP",
    "use": "sig",
    "crv": "Ed25519",
    "kid": "j-0Ny45NWmqGq6GQ",
    "x": "iuemcj_GhRHmY_yCsMlDNp3BQgPZDdG00VRsg_BgU3s",
    "alg": "EdDSA"
}
~~~

Can be encoded to the following Signature-Key field value (this example uses a compact JSON serialization that removes whitespace):

~~~
NOTE: '\' line wrapping per RFC 8792

Signature-Key: :eyJrdHkiOiJPS1AiLCJ1c2UiOiJzaWciLCJjcnYiOiJFZDI1NTE5I\
  iwia2lkIjoiai0wTnk0NU5XbXFHcTZHNFV4TGpHak51bG9rdHVndE9XNGpmR0NDZ2Vm\
  USIsIngiOiJpdWVtY2pfR2hSSG1ZX3lDc01sRE5wM0JRZ1BaRGRHMDBWUnNnX0JnVTN\
  zIiwiYWxnIjoiRWREU0EifQ==:
~~~

\[\[ Editor's note: this is a really awkward way to encode a JWK. We could try to break apart the JSON but there's not a 1:1 map to HTTP Structured Fields we can rely on. We could just put the minified JSON into a string but the double quotes would need to be escaped. This is the least bad version I could come up with right now. \]\]

## Token Request {#request}

The presence of an HTTP Message Signature with the tag `httpsig-oauth-token-request` indicates that the client is requesting a bound token. The client MUST include a message signature of the indicated key.

Additionally, the client MUST calculate and include the digest of the request body and include it as the Content-Digest header defined in {{DIGEST}}.

For example, a form-encoded request body consisting of:

~~~
NOTE: '\' line wrapping per RFC 8792

grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA\
&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
~~~

Would create the following Content-Digest header:

~~~
Content-Digest: sha-256=:4fEzRVTGqfZg7lqf/d3oxXu837pvb3L0GN24+F1VkZk=:
~~~

A client using this method MUST sign the token endpoint request using {{HTTPSIG}} with the appropriate key. The covered components MUST include:

- `@method` the HTTP method of the request
- `@target-uri` the full request URI of the request (note that this includes the scheme, authority, path, and query)
- `content-digest` the digest of the request body

If a signature key is presented at runtime as described in {{runtime}}, the covered components MUST include:

- `signature-key` the encoded public key used to sign this request

The covered components MUST include the client's authentication, if available. If using HTTP Basic, this means including the `authorization` field.

The signature MUST include the following parameters:

- `created` a timestamp for signature creation; this MUST be within a small number of seconds of issuance (e.g. 30 seconds to account for clock skew)
- `nonce` a random unique value that the AS can use to prevent signature replay within the small validity time window
- `tag` a string indicating that this is being used for requesting a bound token, MUST be the value "httpsig-oauth-token-request"
- `keyid` the `kid` value for the key to be used for binding the token; if client uses pre-registered keys as in {{preregister}}, the value MUST match the `httpsig_bound_access_token_kid` value; if the key is presented at runtime as in {{runtime}}, the value MUST match the `kid` of the JWK in the Signature-Key field

The signature algorithm MUST be derived from the indicated key. The `alg` signature parameter MUST NOT be used.

An example request to the token endpoint (using a runtime-provided key here) can look like the following:

~~~ http-message
POST /token HTTP/1.1
Host: server.example.com
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
Content-Type: application/x-www-form-urlencoded
Signature-Key: :eyJrdHkiOiJPS1AiLCJ1c2UiOiJzaWciLCJjcnYiOiJFZDI1NTE5I\
  iwia2lkIjoiai0wTnk0NU5XbXFHcTZHNFV4TGpHak51bG9rdHVndE9XNGpmR0NDZ2Vm\
  USIsIngiOiJpdWVtY2pfR2hSSG1ZX3lDc01sRE5wM0JRZ1BaRGRHMDBWUnNnX0JnVTN\
  zIiwiYWxnIjoiRWREU0EifQ==:
Content-Digest: sha-256=:4fEzRVTGqfZg7lqf/d3oxXu837pvb3L0GN24+F1VkZk=:
Signature-Input: sig1=("@method" "@target-uri" "content-digest" \
  "signature-key" "authorization");created=1618884473\
  ;keyid="j-0Ny45NWmqGq6G4UxLjGjNuloktugtOW4jfGCCgefQ"\
  ;nonce="b3k2pp5k7z-50gnX1b06";tag="httpsig-oauth-token-request"
Signature: sig1=:AWyxebrJ6u8CMi0B3TyX9G1G3XT45UW5zIn8mhsyXdmjTUtGS+1M\
  XiydKv5z0GLCrMhVSFe691jF98DRNNSPAg==:

grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA&\
redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
~~~

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
- `keyid` the `kid` value for the key used to sign the request

The client MUST NOT include an `alg` signature parameter.

For example, the following signed request includes a signature with the needed parameters:

~~~ http-message
NOTE: '\' line wrapping per RFC 8792

GET /foo HTTP/1.1
Host: example.com
Date: Mon, 20 Apr 2026 02:07:55 GMT
Authorization: HTTPSig 2340897.34j123-134uh2345n
Signature-Input: sig1=("@method" "@target-uri" "authorization")\
  ;created=1776650875;keyid="j-0Ny45NWmqGq6G4UxLjGjNuloktugtOW4jfGCCg\
  efQ";nonce="k9Jyxempel2305Nmx7Rk";tag="httpsig-oauth"
Signature: sig1=:kFJC2WoBbrQc8tsKiowIb8oeIA533qmKvzdKf8kndJ7kaLxGmm2v\
  9+IPB8kLE0WUea8KryJGSV7ji1apLkeKBg==:
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
NOTE: '\' line wrapping per RFC 8792

GET /foo HTTP/1.1
Host: example.com
Date: Mon, 20 Apr 2026 02:07:55 GMT
Authorization: HTTPSig 2340897.34j123-134uh2345n
Signature-Input: sig1=("@method" "@target-uri" "authorization")\
  ;created=1776650875;keyid="j-0Ny45NWmqGq6G4UxLjGjNuloktugtOW4jfGCCg\
  efQ";nonce="k9Jyxempel2305Nmx7Rk";tag="httpsig-oauth"
Signature: sig1=:kFJC2WoBbrQc8tsKiowIb8oeIA533qmKvzdKf8kndJ7kaLxGmm2v\
  9+IPB8kLE0WUea8KryJGSV7ji1apLkeKBg==:
~~~

The RS determines the key bound to the token and validates the `kid` value against that key. The RS determines the algorithm from the key and performs signature validation per {{HTTPSIG}} on the

In this example, the client has a key with the `kid` value of `test-key-rsa-pss` which uses the JWA `alg` value of `PS512`. The signature input string is:

~~~
"@request-target": get /foo
"host": example.org
"authorization": HTTPSig 2340897.34j123-134uh2345n
"@signature-params": ("@request-target" "host" "authorization")\
  ;created=1618884475;keyid="test-key-rsa-pss"
~~~

This results in the following signed HTTP message, including the access token.

~~~ http-message
NOTE: '\' line wrapping per RFC 8792

GET /foo HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Authorization: HTTPSig 2340897.34j123-134uh2345n
Signature-Input: sig1=("@request-target" "host" "authorization")\
  ;created=1618884475;keyid="test-key-rsa-pss"
Signature: sig1=:o+Fy/a6IIWhHwnMFhsHqfXEpheWGBMOU3pheT50zA8rL5F8Nur\
  xBKAPylMGBWYCKH5Bd+TB0Co6vqANlXyOCM9Zr5c/UmR5WGex5/OgJJmfN7gOVOH5\
  pB2Zxa233xsohfwo9liBlctukN5//E3F04rKjIkoeTFJiS+hMcOzn29esgFSEl4Jy\
  oO5Q8snMIsC56ZAPYwU7rJis1Wvl6Y9/9tpW6gIn/SHwArhPQSAb0zZy6mCiw654n\
  CaKw5NYJ9S0DZlnV4T7nJtdZsHOkddF6kH4WVka3ev0xONI5kYkEdR1Gw0VAE9thi\
  p+3/aFoUVTJ/1J6JfehZpXqehwv3KNoQ==:
~~~

An RS receiving such a signed message and a bound access token MUST verify the HTTP Message Signature as described in {{HTTPSIG}}. The RS MUST verify that all required portions of the HTTP request are covered by the signature by examining the contents of the signature parameters.


# Acknowledgements {#Acknowledgements}

# IANA Considerations {#IANA}

\[\[ TBD: register the token type and new parameters into their appropriate registries, as well as the JWT and introspection parameters needed for confirmation methods. \]\]

## OAuth Dynamic Client Registration Metadata {#iana-dynreg}

This specification requests registration of the following client metadata name in the "OAuth Dynamic Client Registration Metadata" registry established by {{DYNREG}}.

### httpsig_key_binding_method

Client Metadata Name:
: `httpsig_key_binding_method`

Client Metadata Description:
: Indicates which method the client uses to bind a key for HTTP Message Signature bound access tokens. The value MUST be one of `preregistered`, indicating that the client uses a key registered ahead of time as described in {{preregister}}, or `runtime`, indicating that the client introduces its key at the time of the token request as described in {{runtime}}.

Change Controller:
: IETF

Reference:
: This document

#### Example

A client can publish this parameter as part of a {{I-D.ietf-oauth-client-id-metadata-document}}, alongside its `jwks` and `httpsig_bound_access_token_kid` values. For example, a client with the `client_id` value `https://client.example.com/client-metadata.json` would publish the following document at that URL, indicating that it uses a pre-registered key:

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
