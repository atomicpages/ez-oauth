import assert from "node:assert";
import type * as client from "openid-client";
import { OAuthConfig } from "../OAuthConfig";

/**
 * Be warned. Slack has TWO different AS urls:
 * 1. User: https://slack.com/oauth/v2_user/authorize
 * 2. Bot + User: https://slack.com/oauth/v2/authorize
 * This config allows you to toggle between the two when you
 * construct the class or will auto-detect the correct query params
 * based on our authorization server URL.
 */
export class SlackOAuthConfig extends OAuthConfig {
  private botScopes: string[] = [];
  private isUserAuth = false;

  constructor(userConfig: client.Configuration, redirectUri: string | URL) {
    super(userConfig, redirectUri);

    this.isUserAuth =
      this.config
        .serverMetadata()
        ?.authorization_endpoint?.includes("v2_user") ?? false;
  }

  override withScopes(scopes: string[]): this {
    this._scopes = scopes;
    return this;
  }

  withBotScopes(scopes: string[]): this {
    assert.ok(
      !this.isUserAuth,
      "Bot scopes can only be set when using the bot+user auth URL",
    );

    this.botScopes = scopes;
    return this;
  }

  override get scopes() {
    return this.isUserAuth ? this._scopes : this.botScopes;
  }

  override get additionalParams() {
    const copy = super.additionalParams;

    if (!this.isUserAuth) {
      copy.userScopes = this._scopes.slice();
    }

    return copy;
  }
}
