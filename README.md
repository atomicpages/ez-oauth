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

## Client credentials (M2M)

For machine-to-machine flows, use `ClientCredentialsGrant` with an
`OAuthConfig`. A redirect URI is **not** required for this flow — omit
`redirectUri` in discovery options:

```ts
import { ClientCredentialsGrant, OAuthConfig } from "ez-oauth";

const config = await OAuthConfig.fromDiscovery("https://accounts.example.com", {
  clientId: process.env.CLIENT_ID!,
  clientSecret: process.env.CLIENT_SECRET!,
  // redirectUri omitted — not used for client credentials
});

config.withScopes(["scope1", "scope2"]);

const grant = new ClientCredentialsGrant(config);
const tokens = await grant.getToken(); // optional: pass { resource: "..." } for RFC 8707
```

Optional caching: pass a `StorageProvider` as `options.cache` so tokens are
reused until near expiry. See
[scratches/client-credentials-grant.ts](scratches/client-credentials-grant.ts)
for a full example.

## Planned Features

- Expand RFC 9728 support to include `application/oauth-protected-resource-jwt`
  responses
