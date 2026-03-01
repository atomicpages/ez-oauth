import type { DPoPOptions } from "openid-client";
import * as client from "openid-client";
import { OAuthClientError } from "./errors/OAuthClientError";
import type { OAuthConfig } from "./OAuthConfig";
import type { StorageProvider } from "./storage/StorageProvider";

/** Response type from openid-client clientCredentialsGrant (RFC 6749 §4.4). */
export type ClientCredentialsTokenResponse = Awaited<
  ReturnType<typeof client.clientCredentialsGrant>
>;

const CACHE_KEY_PREFIX = "oauth_cc";
/** Tokens are treated as expired this many ms before expires_at so we refetch in time. */
export const CACHE_VALIDITY_BUFFER_MS = 60 * 1000;

export type ClientCredentialsGrantOptions = {
  /** Optional cache for access tokens.
   * Key format: `oauth_cc:{client_id}:{scope_slug}`
   * unless cacheKey is set.
   */
  cache?: StorageProvider;
  /**
   * Override cache key; otherwise derived from client_id + scope.
   */
  cacheKey?: string;
};

function defaultCacheKey(config: OAuthConfig): string {
  const clientId = config.config.clientMetadata().client_id ?? "unknown";
  const scopeKey = [...config.scopes].sort().join(" ") || "default";
  const slug = scopeKey.replace(/\s+/g, "_");

  return `${CACHE_KEY_PREFIX}:${clientId}:${slug}`;
}

type CachedTokenEntry = {
  access_token: string;
  expires_at: number;
  scope?: string;
  token_type?: string;
};

function parseCached(raw: string | null): CachedTokenEntry | null {
  if (!raw) {
    return null;
  }

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

function toCached(res: ClientCredentialsTokenResponse): CachedTokenEntry {
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
 * OAuth 2.0 Client Credentials Grant (RFC 6749 §4.4) for machine-to-machine (M2M) access.
 * Uses openid-client's clientCredentialsGrant; does not use redirect_uri (not required for this flow).
 *
 * Config must have a token endpoint (e.g. from OAuthConfig.fromDiscovery or fromDcr).
 * For client-credentials-only usage, omit redirectUri in discovery options.
 *
 * Caching (optional): when `options.cache` is provided, tokens are stored and reused until
 * they are within CACHE_VALIDITY_BUFFER_MS of expiry. Cache key is oauth_cc:{client_id}:{scope_slug}
 * unless options.cacheKey is set.
 */
export class ClientCredentialsGrant {
  constructor(
    private readonly config: OAuthConfig,
    private readonly options: ClientCredentialsGrantOptions = {},
  ) {}

  /**
   * Get an access token. Uses cache when configured and the cached entry is still valid.
   * @param parameters - Optional scope, resource (RFC 8707), or other token endpoint parameters.
   * @param grantOptions - Optional DPoP options for sender-constrained tokens.
   */
  async getToken(
    parameters?: Record<string, string>,
    grantOptions?: DPoPOptions,
  ): Promise<ClientCredentialsTokenResponse> {
    const key = this.options.cacheKey ?? defaultCacheKey(this.config);

    if (this.options.cache) {
      const raw = await Promise.resolve(this.options.cache.get(key));
      const cached = parseCached(raw);

      if (cached && cached.expires_at > Date.now() + CACHE_VALIDITY_BUFFER_MS) {
        return {
          access_token: cached.access_token,
          expires_in: Math.max(
            0,
            Math.floor((cached.expires_at - Date.now()) / 1000),
          ),
          token_type: cached.token_type ?? "Bearer",
          ...(cached.scope && { scope: cached.scope }),
        } as ClientCredentialsTokenResponse;
      }
    }

    const tokens = await this.requestToken(parameters, grantOptions);

    if (this.options.cache) {
      const value = JSON.stringify(toCached(tokens));
      await Promise.resolve(this.options.cache.save(key, value));
    }

    return tokens;
  }

  /**
   * Request a token from the AS (no cache). Use when you need a fresh token or do not use cache.
   * @param parameters - Optional scope, resource (RFC 8707), or other token endpoint parameters.
   * @param grantOptions - Optional DPoP options for sender-constrained tokens.
   */
  async requestToken(
    parameters?: Record<string, string>,
    grantOptions?: DPoPOptions,
  ): Promise<ClientCredentialsTokenResponse> {
    const additional = this.config.additionalParams as Record<
      string,
      string | string[]
    >;

    const params: Record<string, string> = Object.fromEntries(
      Object.entries(additional).map(([k, v]) => [
        k,
        Array.isArray(v) ? v.join(" ") : v,
      ]),
    );

    Object.assign(params, parameters ?? {});

    if (this.config.scopes.length > 0) {
      params["scope"] = this.config.scopes.join(" ");
    }

    try {
      return await client.clientCredentialsGrant(
        this.config.config,
        params,
        grantOptions,
      );
    } catch (e) {
      if (e instanceof client.ClientError) {
        let reason: unknown;

        const cause = e.cause as
          | {
              response?: { body?: { json?: () => Promise<unknown> } };
            }
          | undefined;

        if (cause?.response?.body?.json) {
          try {
            reason = await cause.response.body.json();
          } catch {
            reason = undefined;
          }
        }

        throw new OAuthClientError(
          "Failed to get tokens from client credentials grant",
          { cause: e, reason },
        );
      }

      throw e;
    }
  }
}
