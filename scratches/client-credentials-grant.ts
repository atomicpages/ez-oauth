/**
 * Scratch: dedicated client-credentials flow (M2M).
 * Uses OAuthConfig; optional StorageProvider cache. No new methods on OAuthConfig.
 *
 * Run: bun run scratches/client-credentials-grant.ts
 */

import * as client from "openid-client";
import { OAuthConfig } from "../src/OAuthConfig";
import type { StorageProvider } from "../src/storage/StorageProvider";

const CACHE_KEY_PREFIX = "oauth_cc";
const CACHE_VALIDITY_BUFFER_MS = 60 * 1000; // 60s before expiry we refetch

type TokenEndpointResponse = Awaited<
  ReturnType<typeof client.clientCredentialsGrant>
>;

type ClientCredentialsGrantOptions = {
  cache?: StorageProvider;
  /** If not set, key is derived from client_id + scope */
  cacheKey?: string;
};

function defaultCacheKey(config: OAuthConfig): string {
  const clientId = config.config.clientMetadata().client_id ?? "unknown";
  const scopeKey = [...config.scopes].sort().join(" ") || "default";
  // simple slug: no spaces so keys are readable
  const slug = scopeKey.replace(/\s+/g, "_");
  return `${CACHE_KEY_PREFIX}:${clientId}:${slug}`;
}

/** Cached entry shape (what we store as JSON in StorageProvider). */
type CachedTokenEntry = {
  access_token: string;
  expires_at: number; // unix ms
  // optional: store full response if callers need token_type, scope, etc.
  scope?: string;
  token_type?: string;
};

function parseCached(raw: string | null): CachedTokenEntry | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as CachedTokenEntry;
    if (
      typeof parsed.access_token !== "string" ||
      typeof parsed.expires_at !== "number"
    ) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function toCached(res: TokenEndpointResponse): CachedTokenEntry {
  const expiresIn = res.expires_in ?? 3600;
  const expiresAt = Date.now() + expiresIn * 1000;
  return {
    access_token: res.access_token,
    expires_at: expiresAt,
    scope: res.scope,
    token_type: res.token_type,
  };
}

/**
 * Client-credentials (M2M) token acquisition. Uses OAuthConfig; optionally
 * caches tokens via StorageProvider so backends don't reimplement caching.
 */
export class ClientCredentialsGrant {
  constructor(
    private readonly config: OAuthConfig,
    private readonly options: ClientCredentialsGrantOptions = {},
  ) {}

  /**
   * Get an access token. Uses cache if configured and entry is still valid.
   */
  async getToken(
    parameters?: Record<string, string>,
  ): Promise<TokenEndpointResponse> {
    const key = this.options.cacheKey ?? defaultCacheKey(this.config);

    if (this.options.cache) {
      const raw = await Promise.resolve(this.options.cache.get(key));
      const cached = parseCached(raw);
      if (cached && cached.expires_at > Date.now() + CACHE_VALIDITY_BUFFER_MS) {
        // Minimal TokenEndpointResponse; openid-client helpers (claims, expiresIn) only exist on fresh responses
        return {
          access_token: cached.access_token,
          expires_in: Math.max(
            0,
            Math.floor((cached.expires_at - Date.now()) / 1000),
          ),
          token_type: cached.token_type ?? "Bearer",
          ...(cached.scope && { scope: cached.scope }),
        } as TokenEndpointResponse;
      }
    }

    const tokens = await this.requestToken(parameters);

    if (this.options.cache) {
      const value = JSON.stringify(toCached(tokens));
      await Promise.resolve(this.options.cache.save(key, value));
    }

    return tokens;
  }

  /**
   * Request a token from the AS (no cache). Useful when you want to force
   * a fresh token or don't use cache.
   */
  async requestToken(
    parameters?: Record<string, string>,
  ): Promise<TokenEndpointResponse> {
    const params: Record<string, string> = {
      ...this.config.additionalParams,
      ...(parameters ?? {}),
    };
    if (this.config.scopes.length > 0) {
      params.scope = this.config.scopes.join(" ");
    }

    return client.clientCredentialsGrant(this.config.config, params);
  }
}

// --- Example usage (no cache) ---

async function exampleNoCache() {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  if (!clientId || !clientSecret) return;

  // Config must have client_id + client_secret (e.g. from discover).
  const config = await OAuthConfig.fromDiscovery(
    "https://accounts.google.com",
    {
      clientId,
      clientSecret,
      redirectUri: "http://localhost:3005/callback", // not used for grant
    },
  );
  config.withScopes(["https://www.googleapis.com/auth/cloud-platform"]);

  const grant = new ClientCredentialsGrant(config);
  const tokens = await grant.getToken();
  console.log(
    "access_token (first 20 chars):",
    tokens.access_token.slice(0, 20) + "...",
  );
  console.log("expires_in:", tokens.expires_in);
}

// --- Example with cache (MemoryStorageProvider) ---

async function exampleWithCache() {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  if (!clientId || !clientSecret) return;

  const { MemoryStorageProvider } = await import(
    "../src/storage/MemoryStorageProvider"
  );
  const cache = new MemoryStorageProvider();

  const config = await OAuthConfig.fromDiscovery(
    "https://accounts.google.com",
    {
      clientId,
      clientSecret,
      redirectUri: "http://localhost:3005/callback",
    },
  );
  config.withScopes(["https://www.googleapis.com/auth/cloud-platform"]);

  const grant = new ClientCredentialsGrant(config, { cache });

  // First call hits the AS
  const t1 = await grant.getToken();
  // Second call returns cached (same key)
  const t2 = await grant.getToken();
  console.log("Same token (cached):", t1.access_token === t2.access_token);
}

// Run if executed directly
const main = async () => {
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
    console.log(
      "Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to run the example.",
    );
    console.log("Scratch code is in scratches/client-credentials-grant.ts");
    return;
  }
  await exampleNoCache();
  await exampleWithCache();
};

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
