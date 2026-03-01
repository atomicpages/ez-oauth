import { describe, expect, it } from "bun:test";
import * as client from "openid-client";
import { SlackOAuthConfig } from "../SlackOAuthConfig";

function makeConfig(user?: boolean): client.Configuration {
  return new client.Configuration(
    {
      issuer: "https://slack.com",
      authorization_endpoint: user
        ? "https://slack.com/oauth/v2_user/authorize"
        : "https://slack.com/oauth/v2/authorize",
      token_endpoint: "https://slack.com/api/oauth.v2.access",
    },
    "testing",
  );
}

describe("SlackOAuthConfig", () => {
  it("should show user scopes and bot scopes", () => {
    const config = new SlackOAuthConfig(makeConfig(), "http://localhost")
      .withScopes(["channels:read", "channels:write", "chat:write"])
      .withBotScopes(["assistant:write", "app_mentions:read"]);

    expect(config.scopes).toEqual(["assistant:write", "app_mentions:read"]);

    expect(config.additionalParams).toEqual({
      userScopes: ["channels:read", "channels:write", "chat:write"],
    });
  });

  it("should throw an error calling withBotScopes on user config", () => {
    const config = new SlackOAuthConfig(makeConfig(true), "http://localhost");

    expect(() =>
      config.withBotScopes(["assistant:write", "app_mentions:read"]),
    ).toThrow();
  });
});
