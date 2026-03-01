import { afterEach, expect, mock, test } from "bun:test";
import * as realOpenIdClient from "openid-client";
import { OAuthClientError } from "../errors/OAuthClientError";
import { OAuthState } from "../state/OAuthState";
import type { StorageProvider } from "../storage/StorageProvider";

const TOKEN_URL = "https://as.example.com/token";
const AUTH_URL = "https://as.example.com/authorize";
const PLACEHOLDER_REDIRECT = "http://localhost";
const REDIRECT_URI = "https://app.example.com/oauth/callback";

afterEach(() => {
  mock.restore();
});

test("refreshToken(refreshToken) uses this.config", async () => {
  const refreshTokenGrantFn = mock(async () => ({
    access_token: "new_at",
    refresh_token: "new_rt",
    expires_in: 3600,
    token_type: "Bearer",
  }));

  mock.module("openid-client", () => ({
    ...realOpenIdClient,
    refreshTokenGrant: refreshTokenGrantFn,
  }));

  const { OAuthClient } = await import("../OAuthClient");
  const { OAuthConfig: Config } = await import("../OAuthConfig");
  const config = Config.create(
    { tokenUrl: TOKEN_URL, authorizationUrl: AUTH_URL },
    "client1",
    PLACEHOLDER_REDIRECT,
  );
  const state = new OAuthState();
  const client = new OAuthClient(config, state);

  await client.refreshToken("my_refresh_token");

  expect(refreshTokenGrantFn).toHaveBeenCalledTimes(1);
  const [passedConfig] = refreshTokenGrantFn.mock.calls[0] as [unknown, string];
  expect(passedConfig).toBe(config.config);
});

test("refreshToken(config, refreshToken) uses passed config", async () => {
  const refreshTokenGrantFn = mock(async () => ({
    access_token: "new_at",
    refresh_token: "new_rt",
    expires_in: 3600,
    token_type: "Bearer",
  }));

  mock.module("openid-client", () => ({
    ...realOpenIdClient,
    refreshTokenGrant: refreshTokenGrantFn,
  }));

  const { OAuthClient } = await import("../OAuthClient");
  const { OAuthConfig: Config } = await import("../OAuthConfig");
  const configA = Config.create(
    { tokenUrl: TOKEN_URL, authorizationUrl: AUTH_URL },
    "client1",
    PLACEHOLDER_REDIRECT,
  );
  const configB = Config.create(
    {
      tokenUrl: "https://other.as/token",
      authorizationUrl: "https://other.as/auth",
    },
    "client2",
    PLACEHOLDER_REDIRECT,
  );
  const state = new OAuthState();
  const client = new OAuthClient(configA, state);

  await client.refreshToken(configB, "my_refresh_token");

  expect(refreshTokenGrantFn).toHaveBeenCalledTimes(1);
  const [passedConfig] = refreshTokenGrantFn.mock.calls[0] as [unknown, string];
  expect(passedConfig).toBe(configB.config);
});

test("revokeToken(token) uses this.config", async () => {
  const tokenRevocationFn = mock(async () => {});

  mock.module("openid-client", () => ({
    ...realOpenIdClient,
    tokenRevocation: tokenRevocationFn,
  }));

  const { OAuthClient } = await import("../OAuthClient");
  const { OAuthConfig: Config } = await import("../OAuthConfig");

  const config = Config.create(
    { tokenUrl: TOKEN_URL, authorizationUrl: AUTH_URL },
    "client1",
    PLACEHOLDER_REDIRECT,
  );

  const state = new OAuthState();
  const client = new OAuthClient(config, state);

  await client.revokeToken("my_access_token");

  expect(tokenRevocationFn).toHaveBeenCalledTimes(1);
  const [passedConfig] = tokenRevocationFn.mock.calls[0] as [unknown, string];
  expect(passedConfig).toBe(config.config);
});

test("revokeToken(config, token) uses passed config", async () => {
  const tokenRevocationFn = mock(async () => {});

  mock.module("openid-client", () => ({
    ...realOpenIdClient,
    tokenRevocation: tokenRevocationFn,
  }));

  const { OAuthClient } = await import("../OAuthClient");
  const { OAuthConfig: Config } = await import("../OAuthConfig");

  const configA = Config.create(
    { tokenUrl: TOKEN_URL, authorizationUrl: AUTH_URL },
    "client1",
    PLACEHOLDER_REDIRECT,
  );

  const configB = Config.create(
    {
      tokenUrl: "https://other.as/token",
      authorizationUrl: "https://other.as/auth",
    },
    "client2",
    PLACEHOLDER_REDIRECT,
  );

  const state = new OAuthState();
  const client = new OAuthClient(configA, state);

  await client.revokeToken(configB, "my_access_token");

  expect(tokenRevocationFn).toHaveBeenCalledTimes(1);
  const [passedConfig] = tokenRevocationFn.mock.calls[0] as [unknown, string];
  expect(passedConfig).toBe(configB.config);
});

test("introspectToken(token) uses this.config", async () => {
  const tokenIntrospectionFn = mock(async () => ({ active: true }));

  mock.module("openid-client", () => ({
    ...realOpenIdClient,
    tokenIntrospection: tokenIntrospectionFn,
  }));

  const { OAuthClient } = await import("../OAuthClient");
  const { OAuthConfig: Config } = await import("../OAuthConfig");

  const config = Config.create(
    { tokenUrl: TOKEN_URL, authorizationUrl: AUTH_URL },
    "client1",
    PLACEHOLDER_REDIRECT,
  );

  const state = new OAuthState();
  const client = new OAuthClient(config, state);

  await client.introspectToken("my_access_token");

  expect(tokenIntrospectionFn).toHaveBeenCalledTimes(1);
  const [passedConfig, passedToken, passedParams] = tokenIntrospectionFn.mock
    .calls[0] as [unknown, string, Record<string, string> | undefined];

  expect(passedConfig).toBe(config.config);
  expect(passedToken).toBe("my_access_token");
  expect(passedParams).toBeUndefined();
});

test("introspectToken(token, tokenTypeHint) passes token_type_hint", async () => {
  const tokenIntrospectionFn = mock(async () => ({ active: true }));

  mock.module("openid-client", () => ({
    ...realOpenIdClient,
    tokenIntrospection: tokenIntrospectionFn,
  }));

  const { OAuthClient } = await import("../OAuthClient");
  const { OAuthConfig: Config } = await import("../OAuthConfig");

  const config = Config.create(
    { tokenUrl: TOKEN_URL, authorizationUrl: AUTH_URL },
    "client1",
    PLACEHOLDER_REDIRECT,
  );
  const state = new OAuthState();
  const client = new OAuthClient(config, state);

  await client.introspectToken("my_token", "access_token");

  expect(tokenIntrospectionFn).toHaveBeenCalledTimes(1);
  const [, , passedParams] = tokenIntrospectionFn.mock.calls[0] as [
    unknown,
    string,
    Record<string, string> | undefined,
  ];
  expect(passedParams).toEqual({ token_type_hint: "access_token" });
});

test("introspectToken(config, token) uses passed config", async () => {
  const tokenIntrospectionFn = mock(async () => ({ active: true }));

  mock.module("openid-client", () => ({
    ...realOpenIdClient,
    tokenIntrospection: tokenIntrospectionFn,
  }));

  const { OAuthClient } = await import("../OAuthClient");
  const { OAuthConfig: Config } = await import("../OAuthConfig");

  const configA = Config.create(
    { tokenUrl: TOKEN_URL, authorizationUrl: AUTH_URL },
    "client1",
    PLACEHOLDER_REDIRECT,
  );
  const configB = Config.create(
    {
      tokenUrl: "https://other.as/token",
      authorizationUrl: "https://other.as/auth",
    },
    "client2",
    PLACEHOLDER_REDIRECT,
  );
  const state = new OAuthState();
  const client = new OAuthClient(configA, state);

  await client.introspectToken(configB, "my_access_token");

  expect(tokenIntrospectionFn).toHaveBeenCalledTimes(1);
  const [passedConfig, passedToken] = tokenIntrospectionFn.mock.calls[0] as [
    unknown,
    string,
  ];
  expect(passedConfig).toBe(configB.config);
  expect(passedToken).toBe("my_access_token");
});

test("getTokensFromCodeGrant throws when callback URL does not match configured redirect_uri", async () => {
  const { OAuthClient } = await import("../OAuthClient");
  const { OAuthConfig: Config } = await import("../OAuthConfig");

  const config = Config.create(
    { tokenUrl: TOKEN_URL, authorizationUrl: AUTH_URL },
    "client1",
    REDIRECT_URI,
  );
  const state = new OAuthState();
  const client = new OAuthClient(config, state);

  const wrongCallback =
    "https://evil.example.com/oauth/callback?code=abc&state=xyz";

  const err = await client
    .getTokensFromCodeGrant(wrongCallback)
    .catch((e) => e);

  expect(err).toBeInstanceOf(OAuthClientError);
  expect((err as OAuthClientError).message).toBe(
    "Callback URL does not match configured redirect_uri",
  );
  expect((err as OAuthClientError).reason).toBe("redirect_uri_mismatch");
});

test("createAuthorizationUrl builds URL with redirect_uri, state, code_challenge, code_challenge_method and saves state when storage provided", async () => {
  const buildAuthUrlFn = mock((_config: unknown, params: URLSearchParams) => {
    return new URL(
      `https://as.example.com/authorize?${params.toString()}`,
    ) as ReturnType<typeof realOpenIdClient.buildAuthorizationUrl>;
  });

  mock.module("openid-client", () => ({
    ...realOpenIdClient,
    buildAuthorizationUrl: buildAuthUrlFn,
    calculatePKCECodeChallenge: mock(() => Promise.resolve("mock_challenge")),
  }));

  const { OAuthClient } = await import("../OAuthClient");
  const { OAuthConfig: Config } = await import("../OAuthConfig");
  const { MemoryStorageProvider } = await import(
    "../storage/MemoryStorageProvider"
  );

  const config = Config.create(
    { tokenUrl: TOKEN_URL, authorizationUrl: AUTH_URL },
    "client1",
    REDIRECT_URI,
  );

  config.withScopes(["openid"]);

  const state = new OAuthState();
  const storage = new MemoryStorageProvider();
  const client = new OAuthClient(config, state, storage);

  const url = await client.createAuthorizationUrl();

  expect(buildAuthUrlFn).toHaveBeenCalledTimes(1);

  const [, params] = buildAuthUrlFn.mock.calls[0] as [unknown, URLSearchParams];

  expect(params.get("redirect_uri")).toBe(REDIRECT_URI);
  expect(params.get("state")).toBe(state.state);
  expect(params.get("code_challenge")).toBe("mock_challenge");
  expect(params.get("code_challenge_method")).toBe("S256");
  expect(url).toContain("as.example.com");

  const saved = await storage.get(`core_oauth_state:${state.state}`);
  expect(saved).not.toBeNull();

  if (!saved) throw new Error("expected saved state");

  const parsed = JSON.parse(saved);
  expect(parsed.state).toBeDefined();
  expect(parsed.config).toBeDefined();
});

test("getTokensFromCodeGrant returns tokens when callback URL matches redirect_uri", async () => {
  const tokens = {
    access_token: "at_123",
    expires_in: 3600,
    token_type: "Bearer" as const,
  };

  const authCodeGrantFn = mock(async () => tokens);

  mock.module("openid-client", () => ({
    ...realOpenIdClient,
    authorizationCodeGrant: authCodeGrantFn,
  }));

  const { OAuthClient } = await import("../OAuthClient");
  const { OAuthConfig: Config } = await import("../OAuthConfig");

  const config = Config.create(
    { tokenUrl: TOKEN_URL, authorizationUrl: AUTH_URL },
    "client1",
    REDIRECT_URI,
  );

  const state = new OAuthState({
    state: "mystate",
    nonce: "mynonce",
    codeVerifier: "myverifier",
  });

  const client = new OAuthClient(config, state);

  const callbackUrl = `${REDIRECT_URI}?code=auth_code&state=mystate`;
  const result = await client.getTokensFromCodeGrant(callbackUrl);

  expect(result?.access_token).toBe("at_123");
  expect(String(result?.token_type)).toBe("Bearer");
  expect(authCodeGrantFn).toHaveBeenCalledTimes(1);

  const [passedConfig, passedUrl, checks] = authCodeGrantFn.mock
    .calls[0] as unknown as [
    unknown,
    URL,
    { expectedState: string; pkceCodeVerifier: string },
  ];

  expect(passedConfig).toBe(config.config);
  expect(passedUrl.toString()).toContain(REDIRECT_URI);
  expect(checks.expectedState).toBe("mystate");
  expect(checks.pkceCodeVerifier).toBe("myverifier");
});

test("fromDiscovery returns client with config from discovery", async () => {
  const serverMeta = {
    issuer: "https://as.example.com",
    token_endpoint: TOKEN_URL,
    authorization_endpoint: AUTH_URL,
  };

  const discoveredConfig = new realOpenIdClient.Configuration(
    serverMeta,
    "client1",
    {},
  );

  const discoveryFn = mock(async () => discoveredConfig);

  mock.module("openid-client", () => ({
    ...realOpenIdClient,
    discovery: discoveryFn,
  }));

  const { OAuthClient } = await import("../OAuthClient");
  const { OAuthConfig: Config } = await import("../OAuthConfig");

  const client = await OAuthClient.fromDiscovery(
    "https://as.example.com",
    {
      clientId: "client1",
      clientSecret: "secret",
      redirectUri: REDIRECT_URI,
    },
    { ConfigClass: Config },
  );

  expect(client).toBeInstanceOf(OAuthClient);
  expect(client.config.redirectUri.toString()).toBe(REDIRECT_URI);
  expect(discoveryFn).toHaveBeenCalledTimes(1);

  const [server] = discoveryFn.mock.calls[0] as unknown as [
    URL,
    string,
    string,
  ];

  expect(server.toString()).toContain("as.example.com");
});

test("fromStorage restores client from stored state and config", async () => {
  const { OAuthConfig: Config } = await import("../OAuthConfig");
  const config = Config.create(
    { tokenUrl: TOKEN_URL, authorizationUrl: AUTH_URL },
    "client1",
    REDIRECT_URI,
  );

  const state = new OAuthState({
    state: "saved_state",
    nonce: "saved_nonce",
    codeVerifier: "saved_verifier",
  });

  const store = JSON.stringify({
    state: state.toJSON(),
    config: config.toJSON(),
  });

  const getFn = mock(async (key: string) =>
    key === "core_oauth_state:mykey" ? store : null,
  );

  const storage: StorageProvider = {
    get: getFn,
    save: async () => {},
    delete: () => {},
    has: () => false,
    clear: () => {},
    keys: () => [],
  };

  const { OAuthClient } = await import("../OAuthClient");

  const client = await OAuthClient.fromStorage(
    storage,
    Config as unknown as {
      fromJSON: (j: unknown) => InstanceType<typeof Config>;
    },
    OAuthState,
    "mykey",
  );

  expect(client).toBeInstanceOf(OAuthClient);
  expect(client.config.redirectUri.toString()).toBe(REDIRECT_URI);
  expect(getFn).toHaveBeenCalledWith("core_oauth_state:mykey");
});
