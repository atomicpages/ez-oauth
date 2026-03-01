import { afterEach, expect, mock, test } from "bun:test";
import * as realOpenIdClient from "openid-client";
import { OAuthClientError } from "../errors/OAuthClientError";
import { OAuthState } from "../state/OAuthState";

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
