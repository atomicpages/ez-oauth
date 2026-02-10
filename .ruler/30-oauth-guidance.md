# OAuth Guidance

Security-critical behavior

- Preserve PKCE, state, and nonce semantics; never weaken or remove validation
  steps.
- Prefer `openid-client` helpers for URL construction, token processing, and
  PKCE utilities.

Discovery

- Use `OAuthConfig.discover` and `openid-client` discovery utilities instead of
  manual metadata fetching.
- Keep protected resource discovery behind explicit APIs (see `OAuthConfig`
  protected resource discovery helper).

Compatibility

- Maintain Bun/Node/Deno compatibility by avoiding Node-only globals unless
  guarded or abstracted.
