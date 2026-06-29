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
       target: 'https://www.rfc-editor.org/info/bcp195'
       title: Recommendations for Secure Use of Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)
       date: May 2015
       author:
         -
           ins: Y. Sheffer
         -
           ins: R. Holz
         -
           ins: P. Saint-Andre
    RFC2119:
    RFC3230:
    RFC3986:
    RFC5646:
    RFC7234:
    RFC7468:
    RFC7515:
    RFC7517:
    RFC6749:
    RFC6750:
    RFC8174:
    RFC8259:
    RFC8705:
    I-D.ietf-httpbis-message-signatures:
    I-D.ietf-oauth-signed-http-request:
    I-D.ietf-oauth-dpop:
    I-D.ietf-secevent-subject-identifiers:
    I-D.ietf-oauth-rar:

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
allowing anyone who sees the access token to use that token. This extension defines a token type
that binds the token to a presentation key known to the client. The client uses
[HTTP Message Signatures](I-D.ietf-httpbis-message-signatures)
to sign requests using its key, thereby proving its right to present the
associated access token.

## Terminology

{::boilerplate bcp14}

This document contains non-normative examples of partial and complete HTTP messages, JSON structures, URLs, query components, keys, and other elements. Some examples use a single trailing backslash '\' to indicate line wrapping for long values, as per {{!RFC8792}}. The `\` character and leading spaces on wrapped lines are not part of the value.

# Token Response {#token}

When the client makes an access token request, the AS associates the generated access token with the client's registered key from the client's `jwks` or `jwks_uri` field. All presentations of this token at any RS MUST contain an HTTP message signature as described in {{presenting}}.

A bound access token MUST have a `token_type` value of `httpsig`. The response MUST contain a `keyid` value which indicates the key the client MUST use when presenting the access token {{presenting}}. The value of this `keyid` field MUST uniquely identify a key from the client's registered key set by its `kid` value.

~~~
{
    "access_token": "2340897.34j123-134uh2345n",
    "token_type": "httpsig",
    "keyid": "test-key-rsa-pss"
}
~~~

\[\[ Editor's note: while this document deals only with using a pre-registered key, it would be possible to have different key binding mechanisms, such as the client presenting an ephemeral key during the token request or the AS generating and assigning a key alongside the token. The WG needs to decide if this is in scope of this document or not. The presentation mechanisms would be the same. \]\]

# Presenting an HTTP Message Signature Bound Access Token {#presenting}

The algorithm and key used for the HTTP Message Signature are derived from the client's registered information. The key is taken from the client's registered `jwks` or `jwks_uri` field, identified by the `keyid` field of the token response {{token}}. The signature algorithm is determined by the `alg` field of the identified key, following the method for JSON Web Algorithm selection described in {{I-D.ietf-httpbis-message-signatures}}.

The client MUST include the access token value in an `Authorization` header using scheme `HTTPSig`. Note that the scheme value `HTTPSig` is not case sensitive.

~~~
Authorization: HTTPSig 2340897.34j123-134uh2345n
~~~

The client MUST include an HTTP Message Signature that covers, at minimum:

 - The request target of the RS being called
 - The `Host` header of the RS being called
 - The `Authorization` header containing the access token value.

The signature parameters MUST include a `created` signature parameter. The RS SHOULD use this field to ensure freshness of the signed request, appropriate to the API being protected.

The client MUST NOT include an `alg` signature parameter, since the algorithm is determined by the client's registered key. The client MUST include the `keyid` signature parameter set to the value returned in the token response {{token}}.

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

An RS receiving such a signed message and a bound access token MUST verify the HTTP Message Signature as described in {{I-D.ietf-httpbis-message-signatures}}. The RS MUST verify that all required portions of the HTTP request are covered by the signature by examining the contents of the signature parameters.

\[\[ Editor's note: we should define confirmation methods for access tokens here, including JWT values and introspection response values to allow the RS to verify the signature w/o the client's registration information. \]\]

# Acknowledgements {#Acknowledgements}

# IANA Considerations {#IANA}

\[\[ TBD: register the token type and new parameters into their appropriate registries, as well as the JWT and introspection parameters. \]\]

# Security Considerations {#Security}

\[\[ TBD: There are a lot of security considerations to add. \]\]

All requests have to be over TLS or equivalent as per {{BCP195}}.

# Privacy Considerations {#Privacy}

\[\[ TBD: There are a lot of privacy considerations to add. \]\]

--- back

# Document History {#history}

- -00
    - Initial individual draft.

