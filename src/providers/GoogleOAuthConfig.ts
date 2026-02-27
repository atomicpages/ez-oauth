import { OAuthConfig } from "../OAuthConfig";

export class GoogleOAuthConfig extends OAuthConfig {
  override withRefreshToken(): this {
    this._additionalParams = {
      prompt: "consent",
      access_type: "offline",
    };

    return this;
  }
}
