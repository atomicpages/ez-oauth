# Architecture Notes

Core concepts

- `OAuthConfig` wraps `openid-client` `Configuration` and owns discovery, fetch
  customization, and redirect URI handling.
- `OAuthState` encapsulates state/nonce/PKCE generation and serialization.
- `OAuthClient` wires config + state + optional storage into higher-level
  operations (authorization URL, token handling, etc.).

Provider-specific behavior

- Implement provider-specific overrides by subclassing `OAuthConfig` and/or
  `OAuthClient`.
- Keep base types generic; avoid provider logic in shared classes.

Storage

- `StorageProvider` is an interface with sync/async-friendly methods.
- Implementations should treat values as opaque strings and avoid side effects
  beyond storage.
