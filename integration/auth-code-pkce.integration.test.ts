/**
 * Integration tests: run against an in-process mock OAuth 2.0 AS.
 * Validates authorization code + PKCE flow (discovery, auth URL, callback, token exchange, refresh).
 * Execute with: bun run test:integration
 */
import { afterAll, beforeAll, expect, test } from "bun:test";
import * as openidClient from "openid-client";
import { OAuthClientError } from "../src/errors/OAuthClientError";
import { OAuthClient } from "../src/OAuthClient";
import { OAuthConfig } from "../src/OAuthConfig";
import { OAuthState } from "../src/state/OAuthState";
import { MemoryStorageProvider } from "../src/storage/MemoryStorageProvider";
import { startMockAS } from "./mock-as";

let mock: ReturnType<typeof startMockAS>;
let baseUrl: string;

const redirectUri = "http://localhost:9999/callback";
const clientId = "test-client";
const clientSecret = "test-secret";

beforeAll(() => {
  mock = startMockAS();
  baseUrl = mock.baseUrl;
});

afterAll(() => {
  mock.server.stop();
});

test("happy path: discovery → auth URL → redirect → token exchange → refresh", async () => {
  const storage = new MemoryStorageProvider();

  const client = await OAuthClient.fromDiscovery(
    baseUrl,
    {
      clientId,
      clientSecret,
      redirectUri,
      allowInsecureRequests: true,
    },
    {
      ConfigClass: OAuthConfig,
      storage,
    },
  );

  const authUrl = await client.createAuthorizationUrl();
  expect(authUrl).toContain(baseUrl);
  expect(authUrl).toContain("code_challenge=");
  expect(authUrl).toContain("state=");
  expect(authUrl).toContain("redirect_uri=");

  const authUrlParsed = new URL(authUrl);
  const state = authUrlParsed.searchParams.get("state");
  expect(state).toBeTruthy();

  const authResponse = await fetch(authUrl, { redirect: "manual" });
  expect(authResponse.status).toBe(302);

  const location = authResponse.headers.get("Location");
  expect(location).toBeTruthy();
  const callbackUrl = new URL(location as string);

  expect(callbackUrl.searchParams.get("code")).toBeTruthy();
  expect(callbackUrl.searchParams.get("state")).toBe(state);

  const clientFromStorage = await OAuthClient.fromStorage(
    storage,
    OAuthConfig,
    OAuthState,
    state as string,
  );
  openidClient.allowInsecureRequests(clientFromStorage.config.config);

  const tokens = await clientFromStorage.getTokensFromCodeGrant(
    callbackUrl.toString(),
  );
  expect(tokens).toBeDefined();
  expect(tokens?.access_token).toBeTruthy();
  expect(tokens?.refresh_token).toBeTruthy();
  expect(tokens?.token_type?.toLowerCase()).toBe("bearer");

  const refreshToken = tokens?.refresh_token;
  expect(refreshToken).toBeTruthy();
  const refreshed = await clientFromStorage.refreshToken(
    refreshToken as string,
  );
  expect(refreshed.access_token).toBeTruthy();
  expect(refreshed.access_token).not.toBe(tokens?.access_token);
});

test("getTokensFromCodeGrant throws when callback state does not match", async () => {
  const storage = new MemoryStorageProvider();

  const client = await OAuthClient.fromDiscovery(
    baseUrl,
    {
      clientId,
      clientSecret,
      redirectUri,
      allowInsecureRequests: true,
    },
    {
      ConfigClass: OAuthConfig,
      storage,
    },
  );

  const authUrl = await client.createAuthorizationUrl();
  const authUrlParsed = new URL(authUrl);
  const state = authUrlParsed.searchParams.get("state");
  expect(state).toBeTruthy();

  const authResponse = await fetch(authUrl, { redirect: "manual" });
  const location = authResponse.headers.get("Location");
  expect(location).toBeTruthy();
  const callbackUrl = new URL(location as string);

  const clientFromStorage = await OAuthClient.fromStorage(
    storage,
    OAuthConfig,
    OAuthState,
    state as string,
  );

  const wrongStateUrl = new URL(callbackUrl.toString());
  wrongStateUrl.searchParams.set("state", "wrong-state-value");

  await expect(
    clientFromStorage.getTokensFromCodeGrant(wrongStateUrl.toString()),
  ).rejects.toThrow(OAuthClientError);
});

test("getTokensFromCodeGrant throws when callback redirect_uri does not match", async () => {
  const storage = new MemoryStorageProvider();

  const client = await OAuthClient.fromDiscovery(
    baseUrl,
    {
      clientId,
      clientSecret,
      redirectUri,
      allowInsecureRequests: true,
    },
    {
      ConfigClass: OAuthConfig,
      storage,
    },
  );

  const authUrl = await client.createAuthorizationUrl();
  const authResponse = await fetch(authUrl, { redirect: "manual" });
  const location = authResponse.headers.get("Location");
  expect(location).toBeTruthy();
  const callbackUrl = new URL(location as string);

  const callbackWithWrongOrigin = new URL(callbackUrl.toString());
  callbackWithWrongOrigin.protocol = "https";
  callbackWithWrongOrigin.host = "other.example.com";

  await expect(
    client.getTokensFromCodeGrant(callbackWithWrongOrigin.toString()),
  ).rejects.toThrow(OAuthClientError);
});

test("invalid code_verifier: mock returns 400, client surfaces OAuthClientError", async () => {
  const storage = new MemoryStorageProvider();

  const client = await OAuthClient.fromDiscovery(
    baseUrl,
    {
      clientId,
      clientSecret,
      redirectUri,
      allowInsecureRequests: true,
    },
    {
      ConfigClass: OAuthConfig,
      storage,
    },
  );

  const authUrl = await client.createAuthorizationUrl();
  const authResponse = await fetch(authUrl, { redirect: "manual" });
  const location = authResponse.headers.get("Location");
  expect(location).toBeTruthy();
  const callbackUrl = new URL(location as string);
  const stateParam = callbackUrl.searchParams.get("state");
  expect(stateParam).toBeTruthy();

  const stateWrongVerifier = new OAuthState({
    state: stateParam as string,
    nonce: "n",
    codeVerifier: "wrong_verifier_that_fails_pkce",
  });
  const config = client.config;
  const clientWrongVerifier = new OAuthClient(config, stateWrongVerifier);

  await expect(
    clientWrongVerifier.getTokensFromCodeGrant(callbackUrl.toString()),
  ).rejects.toThrow(OAuthClientError);
});
