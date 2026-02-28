import assert from "node:assert";
import {
  createLocalJWKSet,
  createRemoteJWKSet,
  decodeJwt,
  type JSONWebKeySet,
  type JWK,
  jwtVerify,
} from "jose";
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

/**
 * Options for verifying JWT-signed protected resource metadata (RFC 9728).
 * When the server returns Content-Type application/oauth-protected-resource-jwt
 * or JSON with a signed_metadata claim, callers must pass one of these so the
 * library can verify the signature. No silent decode-without-verify.
 */
export type ProtectedResourceDiscoveryJwtOptions =
  | { jwks: JSONWebKeySet | string }
  | {
      getKey: (issuer: string) => Promise<CryptoKey | JWK>;
    };

/**
 * Options for getProtectedResourceDiscovery. Only required when the server
 * returns JWT-signed metadata (JWT body or JSON signed_metadata).
 */
export type GetProtectedResourceDiscoveryOptions = {
  jwt?: ProtectedResourceDiscoveryJwtOptions;
};

/** JWT payload claims for RFC 9728 signed metadata (same names as metadata params). */
type SignedMetadataPayload = {
  resource?: string;
  authorization_servers?: string[];
  bearer_methods_supported?: string[];
  resource_documentation?: string;
  resource_endpoints?: string[];
  resource_signing_alg_values_supported?: string[];
  [key: string]: unknown;
};

function requestResourceIdFromIssuer(
  issuer: URL | string,
  resourcePath?: string,
): string {
  const u = toURL(issuer);

  let id = `${u.origin}${u.pathname}`.replace(/\/$/, "");

  if (resourcePath) {
    id = id ? `${id}/${resourcePath}` : `${u.origin}/${resourcePath}`;
  }

  return id;
}

function payloadToResult(
  payload: SignedMetadataPayload,
): ProtectedResourceDiscoveryResult | null {
  const resource = payload.resource;
  const authorization_servers = payload.authorization_servers;

  if (
    typeof resource !== "string" ||
    !Array.isArray(authorization_servers) ||
    authorization_servers.length === 0
  ) {
    return null;
  }

  const first = authorization_servers as [string, ...string[]];
  const bearer = payload.bearer_methods_supported;

  return {
    resource,
    authorization_servers: first,
    bearer_methods_supported:
      Array.isArray(bearer) && bearer.length > 0
        ? (bearer as [string, ...string[]])
        : ["header"],
    resource_documentation:
      typeof payload.resource_documentation === "string"
        ? payload.resource_documentation
        : "",
    ...(payload.resource_endpoints && {
      resource_endpoints: payload.resource_endpoints as [string, ...string[]],
    }),
    ...(payload.resource_signing_alg_values_supported && {
      resource_signing_alg_values_supported:
        payload.resource_signing_alg_values_supported as [string, ...string[]],
    }),
  };
}

async function verifySignedMetadata(
  jwt: string,
  options: ProtectedResourceDiscoveryJwtOptions,
  requestResourceId: string,
): Promise<ProtectedResourceDiscoveryResult | null> {
  let payload: SignedMetadataPayload;

  if ("getKey" in options) {
    const unverified = decodeJwt(jwt) as SignedMetadataPayload & {
      iss?: string;
    };
    const iss = unverified.iss;

    if (typeof iss !== "string") {
      return null;
    }

    const key = await options.getKey(iss);
    const verified = await jwtVerify(jwt, key);
    payload = verified.payload as SignedMetadataPayload;
  } else {
    const getKey =
      typeof options.jwks === "string"
        ? createRemoteJWKSet(new URL(options.jwks))
        : createLocalJWKSet(options.jwks);

    const verified = await jwtVerify(jwt, getKey);
    payload = verified.payload as SignedMetadataPayload;
  }

  const result = payloadToResult(payload);

  if (!result || result.resource !== requestResourceId) {
    return null;
  }

  return result;
}

export type OAuthDiscoveryAlgorithm = NonNullable<
  client.DiscoveryRequestOptions["algorithm"] | "protected-resource"
>;

export type DiscoverOptions = {
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
  algorithm?: OAuthDiscoveryAlgorithm;
  /** Required when algorithm is protected-resource and the server returns JWT-signed metadata. */
  protectedResourceJwt?: ProtectedResourceDiscoveryJwtOptions;
};

export type DcrOptions = {
  redirectUri: string | URL;
  algorithm?: OAuthDiscoveryAlgorithm;
  /** Required when algorithm is protected-resource and the server returns JWT-signed metadata. */
  protectedResourceJwt?: ProtectedResourceDiscoveryJwtOptions;
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
   *
   * Supports (1) JSON (application/oauth-protected-resource+json) and
   * (2) JWT-signed metadata (Content-Type application/oauth-protected-resource-jwt
   * or JSON with a signed_metadata claim). For JWT or signed_metadata, pass
   * `options.jwt` with `jwks` (JWKS object or jwks_uri string) or `getKey(issuer)`
   * to verify the signature; otherwise the method throws. RFC 9728 Section 3.3:
   * the `resource` claim must match the resource identifier used for the request.
   *
   * @param issuer - Resource identifier or base URL for the well-known request
   * @param resourcePath - Optional path for multi-resource-per-host
   * @param options - Optional; required when response is JWT or contains signed_metadata
   */
  static async getProtectedResourceDiscovery(
    issuer: URL | string,
    resourcePath?: string,
    options?: GetProtectedResourceDiscoveryOptions,
  ): Promise<ProtectedResourceDiscoveryResult | null> {
    const base = toURL(issuer);
    const path = resourcePath
      ? `.well-known/oauth-protected-resource/${resourcePath}`
      : ".well-known/oauth-protected-resource";
    base.pathname = path;
    const requestResourceId = requestResourceIdFromIssuer(issuer, resourcePath);

    const res = await ky.get(base.toString(), {
      headers: {
        Accept: `${PROTECTED_RESOURCE_DISCOVERY_JSON_MEDIA_TYPE}, ${PROTECTED_RESOURCE_DISCOVERY_JWT_MEDIA_TYPE}`,
      },
    });

    if (!res.ok) {
      return null;
    }

    const contentType = res.headers.get("Content-Type") ?? "";

    if (contentType.includes(PROTECTED_RESOURCE_DISCOVERY_JWT_MEDIA_TYPE)) {
      if (!options?.jwt) {
        throw new Error(
          `Verification required for ${PROTECTED_RESOURCE_DISCOVERY_JWT_MEDIA_TYPE}. Pass options.jwt with jwks or getKey to verify the signature (RFC 9728 Section 3.3).`,
        );
      }

      const jwt = await res.text();

      return verifySignedMetadata(jwt, options.jwt, requestResourceId);
    }

    try {
      const json = (await res.json()) as ProtectedResourceDiscoveryResult & {
        signed_metadata?: string;
      };

      if (json.signed_metadata) {
        if (!options?.jwt) {
          throw new Error(
            "Verification required for signed_metadata. Pass options.jwt with jwks or getKey to verify the signature (RFC 9728 Section 3.3).",
          );
        }

        const merged = await verifySignedMetadata(
          json.signed_metadata,
          options.jwt,
          requestResourceId,
        );

        if (merged) {
          const { signed_metadata: _sm, ...rest } = json;
          return { ...rest, ...merged } as ProtectedResourceDiscoveryResult;
        }

        return null;
      }

      if (
        typeof json.resource !== "string" ||
        !Array.isArray(json.authorization_servers) ||
        json.authorization_servers.length === 0
      ) {
        return null;
      }
      return json as ProtectedResourceDiscoveryResult;
    } catch (e) {
      if (e instanceof Error && e.message.startsWith("Verification required")) {
        throw e;
      }
      throw new Error(`Invalid protected resource discovery: ${res.url}`);
    }
  }

  /**
   * Resolve the authorization server URL for discovery/DCR.
   * For oidc/oauth2 returns normalized issuer; for protected-resource
   * fetches protected resource discovery and returns first authorization_servers[0].
   * Pass protectedResourceJwt when the server returns JWT-signed metadata.
   */
  static async resolveAuthorizationServerUrl(
    issuer: URL | string,
    algorithm: OAuthDiscoveryAlgorithm = "oidc",
    resourcePath?: string,
    protectedResourceJwt?: ProtectedResourceDiscoveryJwtOptions,
  ): Promise<URL> {
    if (algorithm === "protected-resource") {
      const discovery = await OAuthDiscovery.getProtectedResourceDiscovery(
        issuer,
        resourcePath,
        protectedResourceJwt ? { jwt: protectedResourceJwt } : undefined,
      );

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
      undefined,
      options.protectedResourceJwt,
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
      undefined,
      options.protectedResourceJwt,
    );

    return client.dynamicClientRegistration(server, {});
  }
}
