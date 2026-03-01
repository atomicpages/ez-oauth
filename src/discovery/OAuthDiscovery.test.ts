import { afterEach, expect, mock, test } from "bun:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import type { Configuration } from "openid-client";
import * as realOpenIdClient from "openid-client";

const RESOURCE_ID = "https://resource.example.com";
const AS_ISSUER = "https://as.example.com";

afterEach(() => {
  mock.restore();
});

test("plain JSON without signed_metadata returns unchanged (no options needed)", async () => {
  const json = {
    resource: RESOURCE_ID,
    authorization_servers: [AS_ISSUER],
    bearer_methods_supported: ["header"],
    resource_documentation: "https://resource.example.com/docs",
  };

  mock.module("ky", () => ({
    default: {
      get: async () => ({
        ok: true,
        url: RESOURCE_ID,
        headers: new Headers({
          "Content-Type": "application/oauth-protected-resource+json",
        }),
        json: async () => json,
        text: async () => "",
      }),
    },
  }));

  const { OAuthDiscovery: Discovery } = await import("./OAuthDiscovery");
  const result = await Discovery.getProtectedResourceDiscovery(RESOURCE_ID);

  expect(result).not.toBeNull();
  if (!result) throw new Error("expected result");
  expect(result.resource).toBe(RESOURCE_ID);
  expect(result.authorization_servers).toEqual([AS_ISSUER]);
});

test("JWT or signed_metadata present but no options.jwt throws", async () => {
  const jwt =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyZXNvdXJjZSI6Imh0dHBzOi8vZXhhbXBsZS5jb20iLCJhdXRob3JpemF0aW9uX3NlcnZlcnMiOlsiaHR0cHM6Ly9hcy5leGFtcGxlLmNvbSJdfQ.x";
  mock.module("ky", () => ({
    default: {
      get: async () => ({
        ok: true,
        url: RESOURCE_ID,
        headers: new Headers({
          "Content-Type": "application/oauth-protected-resource-jwt",
        }),
        text: async () => jwt,
        json: async () => ({}),
      }),
    },
  }));

  const { OAuthDiscovery: Discovery } = await import("./OAuthDiscovery");

  await expect(
    Discovery.getProtectedResourceDiscovery(RESOURCE_ID),
  ).rejects.toThrow(/Verification required/);
});

test("JWT response with valid signature and matching resource returns metadata", async () => {
  const { publicKey, privateKey } = await generateKeyPair("ES256");
  const jwks = await exportJWK(publicKey);
  const jwksSet = { keys: [{ ...jwks, alg: "ES256", use: "sig" }] };

  const payload = {
    resource: RESOURCE_ID,
    authorization_servers: [AS_ISSUER],
    bearer_methods_supported: ["header"],
    resource_documentation: "https://resource.example.com/docs",
    iss: AS_ISSUER,
  };
  const signedJwt = await new SignJWT(payload as Record<string, unknown>)
    .setProtectedHeader({ alg: "ES256" })
    .sign(privateKey);

  mock.module("ky", () => ({
    default: {
      get: async () => ({
        ok: true,
        url: `${RESOURCE_ID}/.well-known/oauth-protected-resource`,
        headers: new Headers({
          "Content-Type": "application/oauth-protected-resource-jwt",
        }),
        text: async () => signedJwt,
        json: async () => ({}),
      }),
    },
  }));

  const { OAuthDiscovery: Discovery } = await import("./OAuthDiscovery");
  const result = await Discovery.getProtectedResourceDiscovery(
    RESOURCE_ID,
    undefined,
    {
      jwt: { jwks: jwksSet },
    },
  );

  expect(result).not.toBeNull();
  if (!result) throw new Error("expected result");
  expect(result.resource).toBe(RESOURCE_ID);
  expect(result.authorization_servers).toEqual([AS_ISSUER]);
});

test("JSON with signed_metadata and valid signature returns merged result (signed overrides)", async () => {
  const { publicKey, privateKey } = await generateKeyPair("ES256");
  const jwks = await exportJWK(publicKey);
  const jwksSet = { keys: [{ ...jwks, alg: "ES256", use: "sig" }] };

  const signedPayload = {
    resource: RESOURCE_ID,
    authorization_servers: [AS_ISSUER],
    bearer_methods_supported: ["header", "body"],
    resource_documentation: "https://resource.example.com/signed-docs",
    iss: AS_ISSUER,
  };
  const signedJwt = await new SignJWT(signedPayload as Record<string, unknown>)
    .setProtectedHeader({ alg: "ES256" })
    .sign(privateKey);

  const json = {
    resource: RESOURCE_ID,
    authorization_servers: ["https://other-as.example.com"],
    bearer_methods_supported: ["header"],
    resource_documentation: "https://resource.example.com/json-docs",
    signed_metadata: signedJwt,
  };

  mock.module("ky", () => ({
    default: {
      get: async () => ({
        ok: true,
        url: RESOURCE_ID,
        headers: new Headers({
          "Content-Type": "application/oauth-protected-resource+json",
        }),
        json: async () => json,
        text: async () => "",
      }),
    },
  }));

  const { OAuthDiscovery: Discovery } = await import("./OAuthDiscovery");
  const result = await Discovery.getProtectedResourceDiscovery(
    RESOURCE_ID,
    undefined,
    {
      jwt: { jwks: jwksSet },
    },
  );

  expect(result).not.toBeNull();
  if (!result) throw new Error("expected result");
  expect(result.authorization_servers).toEqual([AS_ISSUER]);
  expect(result.resource_documentation).toBe(
    "https://resource.example.com/signed-docs",
  );
});

test("resource in JWT does not match request resource identifier returns null", async () => {
  const { publicKey, privateKey } = await generateKeyPair("ES256");
  const jwks = await exportJWK(publicKey);
  const jwksSet = { keys: [{ ...jwks, alg: "ES256", use: "sig" }] };

  const payload = {
    resource: "https://other.example.com",
    authorization_servers: [AS_ISSUER],
    iss: AS_ISSUER,
  };
  const signedJwt = await new SignJWT(payload as Record<string, unknown>)
    .setProtectedHeader({ alg: "ES256" })
    .sign(privateKey);

  mock.module("ky", () => ({
    default: {
      get: async () => ({
        ok: true,
        url: RESOURCE_ID,
        headers: new Headers({
          "Content-Type": "application/oauth-protected-resource-jwt",
        }),
        text: async () => signedJwt,
        json: async () => ({}),
      }),
    },
  }));

  const { OAuthDiscovery: Discovery } = await import("./OAuthDiscovery");
  const result = await Discovery.getProtectedResourceDiscovery(
    RESOURCE_ID,
    undefined,
    {
      jwt: { jwks: jwksSet },
    },
  );

  expect(result).toBeNull();
});

test("dcr passes registrationMetadata to dynamicClientRegistration", async () => {
  const dcrFn = mock(async (_server: URL, _metadata: unknown) => {
    return {} as Configuration;
  });

  mock.module("openid-client", () => ({
    ...realOpenIdClient,
    dynamicClientRegistration: dcrFn,
  }));

  const { OAuthDiscovery: Discovery } = await import("./OAuthDiscovery");
  const metadata = {
    redirect_uris: ["https://app.example.com/cb"],
    client_name: "My App",
  };

  await Discovery.dcr(AS_ISSUER, { registrationMetadata: metadata });

  expect(dcrFn).toHaveBeenCalledTimes(1);
  const [, passedMetadata] = dcrFn.mock.calls[0] as [
    URL,
    Record<string, unknown>,
  ];
  expect(passedMetadata.redirect_uris).toEqual(["https://app.example.com/cb"]);
  expect(passedMetadata.client_name).toBe("My App");
});

test("dcr sends redirectUri as redirect_uris when registrationMetadata does not set it", async () => {
  const dcrFn = mock(async (_server: URL, _metadata: unknown) => {
    return {} as Configuration;
  });

  mock.module("openid-client", () => ({
    ...realOpenIdClient,
    dynamicClientRegistration: dcrFn,
  }));

  const { OAuthDiscovery: Discovery } = await import("./OAuthDiscovery");
  const redirectUri = "https://app.example.com/oauth/callback";

  await Discovery.dcr(AS_ISSUER, { redirectUri });

  expect(dcrFn).toHaveBeenCalledTimes(1);
  const [, passedMetadata] = dcrFn.mock.calls[0] as [
    URL,
    Record<string, unknown>,
  ];
  expect(passedMetadata.redirect_uris).toEqual([redirectUri]);
});
