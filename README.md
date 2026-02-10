# `ez-oauth`

A modular OAuth 2.0 client build on classes the old fashioned way (i.e. no AI
slop). Proudly built on top of
[`openid-client`](https://github.com/panva/openid-client) to be OAuth 2.0
compliant. Works with bun, deno, and node.js.

## Features

- OAuth 2.0
  - Authorization Server Metadata discovery
  - Authorization Code flow
  - Machine-to-machine flow
  - Refresh Token, Device Authorization, Client-Initiated Backchannel
    Authentication (CIBA), and Client Credentials Grants
  - Token Introspection and Revocation
  - Authorization Server Issuer Identification
  - JWT Secured Introspection, Response Mode (JARM), Authorization Request
    (JAR), and UserInfo
- MCP + OAuth 2.0
  - Dynamic Client Registration (DCR)
  - Client ID Metadata Documents
    ([CIMD](https://www.ietf.org/archive/id/draft-parecki-oauth-client-id-metadata-document-00.html))
  - Support for
    [RFC 9728 .well-known/oauth-protected-resource](https://datatracker.ietf.org/doc/html/rfc9728#name-obtaining-protected-resourc)
- Automatic token storage
  - Bun/[`redis`](https://npm.im/redis) compatible `RedisStorageProvider`
  - in-memory storage provider for testing/non-distributed use cases

## Planned Features

- Expand RFC 9728 support to include `application/oauth-protected-resource-jwt`
  responses
