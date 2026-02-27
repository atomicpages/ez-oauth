import { $ } from "bun";
import type { Hooks } from "ky";
import { OAuthClient } from "../src/OAuthClient";
import { OAuthConfig } from "../src/OAuthConfig";
import { OAuthState } from "../src/state/OAuthState";
import { decodeBasicAuthCredentials } from "../src/utils/auth";

class RedditOAuthConfig extends OAuthConfig {
  private static readonly REDDIT_USER_AGENT = "ez-oauth/0.0.1 (by /u/my-user)";

  protected override createHooks(): Hooks | undefined {
    return {
      beforeRequest: [
        (req) => {
          req.headers.set("User-Agent", RedditOAuthConfig.REDDIT_USER_AGENT);
          req.headers.set(
            "Authorization",
            decodeBasicAuthCredentials(req.headers.get("Authorization") || ""),
          );

          return req;
        },
      ],
    };
  }
}

const state = new OAuthState();

const config = RedditOAuthConfig.create(
  {
    authorizationUrl: "https://www.reddit.com/api/v1/authorize",
    tokenUrl: "https://www.reddit.com/api/v1/access_token",
  },
  process.env.REDDIT_CLIENT_ID!,
  `${process.env.REDIRECT_BASE_URL || "http://localhost:3005"}/mcp/oauth/callback`,
);

const client = new OAuthClient(
  config.withScopes(["identity", "read", "mysubreddits"]),
  state,
);
const url = await client.createAuthorizationUrl();

await $`open ${url}`;
