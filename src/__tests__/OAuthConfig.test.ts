import { afterEach, expect, mock, test } from "bun:test";
import * as client from "openid-client";
import { ClientAuth } from "../enum";
import { OAuthConfig } from "../OAuthConfig";

const TOKEN_URL = "https://as.example.com/token";
const AUTH_URL = "https://as.example.com/authorize";
const REDIRECT_URI = "https://app.example.com/cb";

afterEach(() => {
  mock.restore();
});

function makeConfiguration(): client.Configuration {
  return new client.Configuration(
    {
      issuer: new URL(AUTH_URL).origin,
      authorization_endpoint: AUTH_URL,
      token_endpoint: TOKEN_URL,
    },
    "test-client-id",
  );
}

test("constructor sets redirectUri and supportsPKCE from userConfig", () => {
  const userConfig = makeConfiguration();
  const config = new OAuthConfig(userConfig, REDIRECT_URI);

  expect(config.redirectUri.toString()).toBe(REDIRECT_URI);
  expect(typeof config.supportsPKCE).toBe("boolean");
  expect(config.config).toBe(userConfig);
});

test("scopes getter returns empty array initially; withScopes sets and returns this", () => {
  const config = new OAuthConfig(makeConfiguration(), REDIRECT_URI);

  expect(config.scopes).toEqual([]);

  const chained = config.withScopes(["openid", "profile"]);

  expect(chained).toBe(config);
  expect(config.scopes).toEqual(["openid", "profile"]);
});

test("additionalParams getter returns a copy", () => {
  const config = new OAuthConfig(makeConfiguration(), REDIRECT_URI);

  const a = config.additionalParams;
  const b = config.additionalParams;

  expect(a).toEqual({});
  expect(a).not.toBe(b);
});

test("withRefreshToken returns this", () => {
  const config = new OAuthConfig(makeConfiguration(), REDIRECT_URI);

  const result = config.withRefreshToken();

  expect(result).toBe(config);
});

test("toClientAuth maps each ClientAuth to openid-client constant", () => {
  expect(OAuthConfig.toClientAuth(ClientAuth.CLIENT_SECRET_JWT)).toBe(
    client.ClientSecretJwt,
  );
  expect(OAuthConfig.toClientAuth(ClientAuth.PRIVATE_KEY_JWT)).toBe(
    client.PrivateKeyJwt,
  );
  expect(OAuthConfig.toClientAuth(ClientAuth.NONE)).toBe(client.None);
  expect(OAuthConfig.toClientAuth(ClientAuth.TLS_CLIENT_AUTH)).toBe(
    client.TlsClientAuth,
  );
  expect(OAuthConfig.toClientAuth(ClientAuth.CLIENT_SECRET_POST)).toBe(
    client.ClientSecretPost,
  );
  expect(OAuthConfig.toClientAuth(ClientAuth.CLIENT_SECRET_BASIC)).toBe(
    client.ClientSecretBasic,
  );
});

test("toClientAuth throws for unsupported credential type", () => {
  expect(() => OAuthConfig.toClientAuth("unsupported" as ClientAuth)).toThrow(
    "Unsupported credential type: unsupported",
  );
});

test("toURL returns same URL for URL input", () => {
  const url = new URL(REDIRECT_URI);

  expect(OAuthConfig.toURL(url)).toBe(url);
});

test("toURL returns new URL for string input", () => {
  const result = OAuthConfig.toURL(REDIRECT_URI);

  expect(result).toBeInstanceOf(URL);
  expect(result.toString()).toBe(REDIRECT_URI);
});

test("PLACEHOLDER_REDIRECT_URI is http://localhost", () => {
  expect(OAuthConfig.PLACEHOLDER_REDIRECT_URI).toBe("http://localhost");
});

test("create builds config with tokenUrl, authorizationUrl, grantTypes, scopes, tokenAuthMethods", () => {
  const config = OAuthConfig.create(
    {
      tokenUrl: TOKEN_URL,
      authorizationUrl: AUTH_URL,
      grantTypes: ["authorization_code", "client_credentials"],
      scopes: ["openid", "email"],
      tokenAuthMethods: [ClientAuth.CLIENT_SECRET_BASIC],
    },
    "my-client",
    REDIRECT_URI,
  );

  expect(config.redirectUri.toString()).toBe(REDIRECT_URI);
  const server = config.config.serverMetadata();
  expect(server.token_endpoint).toBe(TOKEN_URL);
  expect(server.authorization_endpoint).toBe(AUTH_URL);
  const clientMeta = config.config.clientMetadata();
  expect(clientMeta.client_id).toBe("my-client");
});

test("fromDiscovery uses discovered configuration and options.redirectUri or placeholder", async () => {
  const discoveredConfig = makeConfiguration();

  mock.module("openid-client", () => ({
    ...client,
    discovery: mock(async () => discoveredConfig),
  }));

  const { OAuthConfig: Config } = await import("../OAuthConfig");

  const withRedirect = await Config.fromDiscovery("https://as.example.com", {
    clientId: "c1",
    redirectUri: REDIRECT_URI,
  });

  expect(withRedirect.redirectUri.toString()).toBe(REDIRECT_URI);
  expect(withRedirect.config).toBe(discoveredConfig);

  const withoutRedirect = await Config.fromDiscovery("https://as.example.com", {
    clientId: "c1",
  });

  expect(withoutRedirect.redirectUri.toString()).toBe(
    new URL(OAuthConfig.PLACEHOLDER_REDIRECT_URI).toString(),
  );
});

test("fromDcr uses DCR configuration and options.redirectUri or placeholder", async () => {
  const dcrConfig = makeConfiguration();

  mock.module("openid-client", () => ({
    ...client,
    dynamicClientRegistration: mock(async () => dcrConfig),
  }));

  const { OAuthConfig: Config } = await import("../OAuthConfig");

  const withRedirect = await Config.fromDcr("https://as.example.com", {
    redirectUri: REDIRECT_URI,
  });

  expect(withRedirect.redirectUri.toString()).toBe(REDIRECT_URI);
  expect(withRedirect.config).toBe(dcrConfig);

  const withRedirectUrl = await Config.fromDcr("https://as.example.com", {
    redirectUri: new URL("https://other.example.com/cb"),
  });

  expect(withRedirectUrl.redirectUri.toString()).toBe(
    "https://other.example.com/cb",
  );

  const withoutRedirect = await Config.fromDcr("https://as.example.com", {});

  expect(withoutRedirect.redirectUri.toString()).toBe(
    new URL(OAuthConfig.PLACEHOLDER_REDIRECT_URI).toString(),
  );
});

test("fromJSON and toJSON round-trip", () => {
  const original = OAuthConfig.create(
    { tokenUrl: TOKEN_URL, authorizationUrl: AUTH_URL },
    "client-id",
    REDIRECT_URI,
  );
  original.withScopes(["openid"]);

  const json = original.toJSON();
  const restored = OAuthConfig.fromJSON(json);

  expect(restored.redirectUri.toString()).toBe(original.redirectUri.toString());
  expect(restored.config.clientMetadata().client_id).toBe(
    original.config.clientMetadata().client_id,
  );
  expect(json.name).toBe("OAuthConfig");
  expect(json.scopes).toEqual(["openid"]);
  expect(json.redirectUri).toBe(REDIRECT_URI);
});

test("toJSON includes name, scopes, supportsPKCE, server, client, redirectUri", () => {
  const config = OAuthConfig.create(
    { tokenUrl: TOKEN_URL, authorizationUrl: AUTH_URL },
    "cid",
    REDIRECT_URI,
  );

  const json = config.toJSON();

  expect(json.name).toBe("OAuthConfig");
  expect(json.scopes).toEqual([]);
  expect(typeof json.supportsPKCE).toBe("boolean");
  expect(json.server).toBeDefined();
  expect(json.client).toBeDefined();
  expect(json.client.client_id).toBe("cid");
  expect(json.redirectUri).toBe(REDIRECT_URI);
});
