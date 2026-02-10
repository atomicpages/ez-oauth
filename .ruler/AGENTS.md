# AGENTS.md

Use these rules for all work in this repository.

Project intent

- Library: modular OAuth 2.0 client built on openid-client
- Runtime: Bun-first, but should remain compatible with Node and Deno where
  possible

Tech and tooling

- TypeScript ESM (`"type": "module"`); keep strict typing and avoid implicit
  anys
- Use Bun tooling (`bun test`, `bun run`, `bun build`); avoid npm/yarn/pnpm
- Formatting/linting via Biome (tabs, double quotes); keep output
  Biome-compatible

Code patterns

- Prefer small classes with clear responsibilities (see `src/OAuthConfig.ts`,
  `src/OAuthState.ts`)
- Storage providers implement `StorageProvider` and may be sync or async; keep
  API shape stable
- OAuth flows should use openid-client helpers rather than custom crypto/URL
  building

Safety and correctness

- OAuth security: preserve PKCE, state, nonce handling; avoid weakening
  verification flows
- Avoid introducing provider-specific behavior in base classes; subclass for
  provider overrides

Docs structure

- Additional context lives in other `.ruler/*.md` files; keep them concise and
  practical
