import { afterEach, expect, mock, test } from "bun:test";
import * as realOpenIdClient from "openid-client";
import { MemoryStorageProvider } from "../storage/MemoryStorageProvider";

const TOKEN_URL = "https://as.example.com/token";
const AUTH_URL = "https://as.example.com/authorize";
const PLACEHOLDER_REDIRECT = "http://localhost";

async function createTestConfig(scopes: string[] = []) {
  const { OAuthConfig } = await import("../OAuthConfig");
  const config = OAuthConfig.create(
    {
      tokenUrl: TOKEN_URL,
      authorizationUrl: AUTH_URL,
    },
    "test-client-id",
    PLACEHOLDER_REDIRECT,
  );

  if (scopes.length > 0) {
    config.withScopes(scopes);
  }

  return config;
}

afterEach(() => {
  mock.restore();
});

test("requestToken merges config scopes and additionalParams and calls openid-client clientCredentialsGrant", async () => {
  const grantFn = mock(async () => ({
    access_token: "mock_token",
    expires_in: 3600,
    token_type: "Bearer",
  }));

  mock.module("openid-client", () => ({
    ...realOpenIdClient,
    clientCredentialsGrant: grantFn,
  }));

  const { OAuthConfig: Config } = await import("../OAuthConfig");

  const { ClientCredentialsGrant: CCGrant } = await import(
    "../ClientCredentialsGrant"
  );

  const config = Config.create(
    { tokenUrl: TOKEN_URL, authorizationUrl: AUTH_URL },
    "client1",
    PLACEHOLDER_REDIRECT,
  );

  config.withScopes(["scope1", "scope2"]);

  const grant = new CCGrant(config);
  const result = await grant.requestToken();

  expect(grantFn).toHaveBeenCalledTimes(1);
  const call = grantFn.mock.calls[0];
  expect(call).toBeDefined();

  const args = call as [unknown, Record<string, string>];

  expect(args[1]).toHaveProperty("scope", "scope1 scope2");
  expect(result.access_token).toBe("mock_token");
  expect(result.expires_in).toBe(3600);
});

test("requestToken passes through parameters (e.g. resource)", async () => {
  const grantFn = mock(async () => ({
    access_token: "mock_token",
    expires_in: 3600,
    token_type: "Bearer",
  }));

  mock.module("openid-client", () => ({
    ...realOpenIdClient,
    clientCredentialsGrant: grantFn,
  }));

  const { ClientCredentialsGrant: CCGrant } = await import(
    "../ClientCredentialsGrant"
  );

  const config = await createTestConfig();
  const grant = new CCGrant(config);
  await grant.requestToken({ resource: "https://api.example.com" });

  const call = grantFn.mock.calls[0];
  expect(call).toBeDefined();

  const args = call as [unknown, Record<string, string>];
  expect(args[1]).toHaveProperty("resource", "https://api.example.com");
});

test("getToken with cache: first call requests token and saves to cache, second call returns cached", async () => {
  const grantFn = mock(async () => ({
    access_token: "fresh_token",
    expires_in: 3600,
    token_type: "Bearer",
  }));

  mock.module("openid-client", () => ({
    ...realOpenIdClient,
    clientCredentialsGrant: grantFn,
  }));

  const { ClientCredentialsGrant: CCGrant } = await import(
    "../ClientCredentialsGrant"
  );

  const config = await createTestConfig(["scope1"]);
  const cache = new MemoryStorageProvider();
  const grant = new CCGrant(config, { cache });

  const first = await grant.getToken();
  expect(first.access_token).toBe("fresh_token");
  expect(grantFn).toHaveBeenCalledTimes(1);

  const second = await grant.getToken();
  expect(second.access_token).toBe("fresh_token");
  expect(grantFn).toHaveBeenCalledTimes(1);
});

test("getToken with cache uses custom cacheKey when provided", async () => {
  const grantFn = mock(async () => ({
    access_token: "tk",
    expires_in: 3600,
    token_type: "Bearer",
  }));

  mock.module("openid-client", () => ({
    ...realOpenIdClient,
    clientCredentialsGrant: grantFn,
  }));

  const { ClientCredentialsGrant: CCGrant } = await import(
    "../ClientCredentialsGrant"
  );

  const config = await createTestConfig();
  const cache = new MemoryStorageProvider();
  const customKey = "custom_cc_key";
  const grant = new CCGrant(config, { cache, cacheKey: customKey });

  await grant.getToken();
  expect(cache.get(customKey)).not.toBeNull();
});

test("getToken with cache and expired entry requests new token", async () => {
  const grantFn = mock(async () => ({
    access_token: "token",
    expires_in: 3600,
    token_type: "Bearer",
  }));

  mock.module("openid-client", () => ({
    ...realOpenIdClient,
    clientCredentialsGrant: grantFn,
  }));

  const { ClientCredentialsGrant: CCGrant } = await import(
    "../ClientCredentialsGrant"
  );

  const config = await createTestConfig();
  const expiredAt = Date.now() - 1000;

  const cached = JSON.stringify({
    access_token: "old_token",
    expires_at: expiredAt,
    token_type: "Bearer",
  });

  const cache = new MemoryStorageProvider({ oauth_cc: cached });
  const grant = new CCGrant(config, { cache, cacheKey: "oauth_cc" });

  const result = await grant.getToken();
  expect(result.access_token).toBe("token");
  expect(grantFn).toHaveBeenCalledTimes(1);
});

test("requestToken wraps openid-client ClientError as OAuthClientError", async () => {
  const ClientError = (await import("openid-client")).ClientError;

  mock.module("openid-client", () => ({
    ...realOpenIdClient,
    clientCredentialsGrant: async () => {
      throw new ClientError("token error", undefined as unknown as Error);
    },
  }));

  const { ClientCredentialsGrant: CCGrant } = await import(
    "../ClientCredentialsGrant"
  );
  const { OAuthClientError } = await import("../errors/OAuthClientError");

  const config = await createTestConfig();
  const grant = new CCGrant(config);

  await expect(grant.requestToken()).rejects.toThrow(OAuthClientError);
});
