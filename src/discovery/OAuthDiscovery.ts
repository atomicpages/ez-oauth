import assert from "node:assert";
import ky from "ky";
import type { Configuration } from "openid-client";
import * as client from "openid-client";
import { toURL } from "../utils/url";

const PROTECTED_RESOURCE_DISCOVERY_JWT_MEDIA_TYPE =
  "application/oauth-protected-resource-jwt";

const PROTECTED_RESOURCE_DISCOVERY_JSON_MEDIA_TYPE =
  "application/oauth-protected-resource+json";

/**
 * Result shape from RFC 9728 protected resource discovery
 * (application/oauth-protected-resource+json).
 * The library does not cache this; callers may cache if desired.
 */
export type ProtectedResourceDiscoveryResult = {
  authorization_servers: [string, ...string[]];
  bearer_methods_supported: [string, ...string[]];
  resource_endpoints?: [string, ...string[]];
  resource_signing_alg_values_supported?: [string, ...string[]];
  resource: string;
  resource_documentation: string;
};

export type OAuthDiscoveryAlgorithm = NonNullable<
  client.DiscoveryRequestOptions["algorithm"] | "protected-resource"
>;

export type DiscoverOptions = {
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
  algorithm?: OAuthDiscoveryAlgorithm;
};

export type DcrOptions = {
  redirectUri: string | URL;
  algorithm?: OAuthDiscoveryAlgorithm;
};

/**
 * Stateless OAuth/OIDC discovery and DCR.
 * No internal caching; callers who need caching should cache the returned
 * Configuration or wrap discovery in their own cache.
 */
export class OAuthDiscovery {
  private constructor() {}
  /**
   * Fetch protected resource discovery (RFC 9728) from
   * /.well-known/oauth-protected-resource (optional resourcePath for
   * multi-resource-per-host). Does not cache; each call may hit the network.
   * @throws if response is JWT-signed metadata (not supported)
   */
  static async getProtectedResourceDiscovery(
    issuer: URL | string,
    resourcePath?: string,
  ): Promise<ProtectedResourceDiscoveryResult | null> {
    const base = toURL(issuer);

    const path = resourcePath
      ? `.well-known/oauth-protected-resource/${resourcePath}`
      : ".well-known/oauth-protected-resource";

    base.pathname = path;

    const res = await ky.get(base.toString(), {
      headers: {
        Accept: PROTECTED_RESOURCE_DISCOVERY_JSON_MEDIA_TYPE,
      },
    });

    if (!res.ok) {
      return null;
    }

    if (
      res.headers
        .get("Content-Type")
        ?.includes(PROTECTED_RESOURCE_DISCOVERY_JWT_MEDIA_TYPE)
    ) {
      throw new Error(
        `${PROTECTED_RESOURCE_DISCOVERY_JWT_MEDIA_TYPE} is not supported`,
      );
    }

    try {
      const json = await res.json<ProtectedResourceDiscoveryResult>();

      return json;
    } catch {
      throw new Error(`Invalid protected resource discovery: ${res.url}`);
    }
  }

  /**
   * Resolve the authorization server URL for discovery/DCR.
   * For oidc/oauth2 returns normalized issuer; for protected-resource
   * fetches protected resource discovery and returns first authorization_servers[0].
   */
  static async resolveAuthorizationServerUrl(
    issuer: URL | string,
    algorithm: OAuthDiscoveryAlgorithm = "oidc",
  ): Promise<URL> {
    if (algorithm === "protected-resource") {
      const discovery =
        await OAuthDiscovery.getProtectedResourceDiscovery(issuer);

      assert.ok(
        discovery && discovery.authorization_servers.length > 0,
        "No authorization servers found",
      );

      return new URL(discovery.authorization_servers[0]);
    }

    return toURL(issuer);
  }

  /**
   * Perform AS metadata discovery and return openid-client Configuration.
   * Does not cache; callers may cache the result.
   */
  static async discover(
    issuer: URL | string,
    options: DiscoverOptions,
  ): Promise<Configuration> {
    const algorithm = options.algorithm ?? "oidc";

    const server = await OAuthDiscovery.resolveAuthorizationServerUrl(
      issuer,
      algorithm,
    );

    const discoveryAlgorithm =
      algorithm === "protected-resource" ? "oauth2" : algorithm;

    return client.discovery(
      server,
      options.clientId,
      options.clientSecret,
      undefined,
      { algorithm: discoveryAlgorithm },
    );
  }

  /**
   * Dynamic Client Registration at the given issuer.
   * Resolves AS URL when algorithm is protected-resource; does not cache.
   */
  static async dcr(
    issuer: URL | string,
    options: DcrOptions,
  ): Promise<Configuration> {
    const algorithm = options.algorithm ?? "oidc";

    const server = await OAuthDiscovery.resolveAuthorizationServerUrl(
      issuer,
      algorithm,
    );

    return client.dynamicClientRegistration(server, {});
  }
}
