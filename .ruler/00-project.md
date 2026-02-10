# Project Overview

Simple OAuth client library targeting OAuth 2.0 and related drafts, built on top
of `openid-client`. It exposes class-based APIs for configuration, state
handling, and storage, with a focus on clean, explicit flow handling.

Key entry points

- `index.ts`: package entry
- `src/OAuthConfig.ts`: configuration wrapper and discovery helpers
- `src/OAuthClient.ts`: higher-level client behavior (flow orchestration)
- `src/state/OAuthState.ts`: PKCE/state/nonce management
- `src/storage/*`: storage provider interface and implementations
