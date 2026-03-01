import * as client from "openid-client";
import URLSheriff from "url-sheriff";
import type { DiscoverOptions } from "./discovery";
import { OAuthClientError } from "./errors/OAuthClientError";
import { OAuthStateError } from "./errors/OAuthStateError";
import type { OAuthConfig } from "./OAuthConfig";
import { OAuthState } from "./state/OAuthState";
import type { StorageProvider } from "./storage/StorageProvider";
import { redirectUriMatches, toURL } from "./utils/url";

type URLSheriffConfig = ConstructorParameters<typeof URLSheriff>[0];

type OAuthClientOptions = {
  sheriffConfig?: URLSheriffConfig;
};

export type OAuthConfigFactory<T extends OAuthConfig = OAuthConfig> = {
  fromJSON(json: ReturnType<OAuthConfig["toJSON"]>): T;
};

export class OAuthClient {
  private static readonly STATE_KEY = "core_oauth_state";
  protected sheriff: URLSheriff;
  protected readonly userConfig: OAuthConfig;
  protected readonly storage: StorageProvider | null = null;
  protected readonly state: OAuthState;

  constructor(
    userConfig: OAuthConfig,
    state: OAuthState,
    storage?: StorageProvider,
    protected readonly opts: OAuthClientOptions = {},
  ) {
    this.userConfig = userConfig;
    this.storage = storage || null;
    this.state = state;
    this.sheriff = new URLSheriff(opts.sheriffConfig);
  }

  get config() {
    return this.userConfig;
  }

  async createAuthorizationUrl(scopeSeparator: string = " "): Promise<string> {
    if (process.env.NODE_ENV === "production") {
      await this.sheriff.isSafeURL(this.config.redirectUri);
    }

    const params = new URLSearchParams({
      redirect_uri: this.config.redirectUri.toString(),
      scope: this.config.scopes.join(scopeSeparator),
      code_challenge: await this.state.getCodeChallenge(),
      state: this.state.state,
      code_challenge_method: OAuthState.CODE_CHALLENGE_METHOD,
      ...(this.config.additionalParams ? this.config.additionalParams : {}),
    });

    if (!this.config.supportsPKCE) {
      params.set("nonce", this.state.nonce);
    }

    await this.saveState();

    return client.buildAuthorizationUrl(this.config.config, params).toString();
  }

  private async saveState() {
    if (this.storage) {
      await this.storage.save(
        `${OAuthClient.STATE_KEY}:${this.state.state}`,
        JSON.stringify({
          state: this.state.toJSON(),
          config: this.config.toJSON(),
        }),
      );
    }
  }

  async getTokensFromCodeGrant(
    url: URL | string,
  ): Promise<
    Awaited<ReturnType<typeof client.authorizationCodeGrant>> | undefined
  > {
    const callbackUrl = toURL(url);

    if (!redirectUriMatches(callbackUrl, this.config.redirectUri)) {
      throw new OAuthClientError(
        "Callback URL does not match configured redirect_uri",
        { reason: "redirect_uri_mismatch" },
      );
    }

    try {
      const tokens = await client.authorizationCodeGrant(
        this.config.config,
        callbackUrl,
        {
          expectedState: this.state.state,
          pkceCodeVerifier: this.state.codeVerifier,
          expectedNonce: this.state.codeVerifier ? undefined : this.state.nonce,
        },
      );

      return tokens;
    } catch (e) {
      if (e instanceof client.ClientError) {
        let reason: unknown;

        const cause = e.cause as
          | { response?: { body?: { json?: () => Promise<unknown> } } }
          | undefined;

        if (cause?.response?.body?.json) {
          reason = await cause.response.body.json();
        }

        throw new OAuthClientError("Failed to get tokens from code grant", {
          cause: e,
          reason,
        });
      }
    }
  }

  /**
   * Exchange a refresh token for new tokens. If config is omitted, uses this client's
   * config (same-client case). Pass config as first argument to use a different config
   * (e.g. multi-tenant).
   */
  async refreshToken(
    refreshToken: string,
  ): Promise<Awaited<ReturnType<typeof client.refreshTokenGrant>>>;

  async refreshToken<T extends OAuthConfig = OAuthConfig>(
    config: T,
    refreshToken: string,
  ): Promise<Awaited<ReturnType<typeof client.refreshTokenGrant>>>;

  async refreshToken<T extends OAuthConfig = OAuthConfig>(
    configOrRefreshToken: T | string,
    refreshToken?: string,
  ): Promise<Awaited<ReturnType<typeof client.refreshTokenGrant>>> {
    const useThisConfig = refreshToken === undefined;
    const config = useThisConfig ? this.config : (configOrRefreshToken as T);

    const token = useThisConfig
      ? (configOrRefreshToken as string)
      : (refreshToken as string);

    const extraParams = useThisConfig
      ? this.config.additionalParams
      : (config as OAuthConfig).additionalParams;

    const tokens = await client.refreshTokenGrant(
      config.config,
      token,
      extraParams as Record<string, string>,
    );

    return tokens;
  }

  /**
   * Revoke an access or refresh token. If config is omitted, uses this client's config
   * (same-client case). Pass config as first argument to use a different config
   * (e.g. multi-tenant).
   */
  revokeToken(token: string): Promise<void>;

  revokeToken<T extends OAuthConfig = OAuthConfig>(
    config: T,
    token: string,
  ): Promise<void>;

  revokeToken<T extends OAuthConfig = OAuthConfig>(
    configOrToken: T | string,
    token?: string,
  ): Promise<void> {
    const useThisConfig = token === undefined;
    const config = useThisConfig ? this.config : (configOrToken as T);

    const tokenToRevoke = useThisConfig
      ? (configOrToken as string)
      : (token as string);

    const extraParams = useThisConfig
      ? this.config.additionalParams
      : (config as OAuthConfig).additionalParams;

    return client.tokenRevocation(
      config.config,
      tokenToRevoke,
      extraParams as Record<string, string>,
    );
  }

  /**
   * Build an OAuthClient from AS metadata discovery (one-call flow).
   * Does not cache; callers may cache the returned client's config or wrap discovery.
   */
  static async fromDiscovery<T extends OAuthConfig = OAuthConfig>(
    issuer: URL | string,
    options: DiscoverOptions,
    opts: {
      ConfigClass: OAuthConfigFactory<T>;
      storage?: StorageProvider | null;
      state?: OAuthState | null;
    },
  ): Promise<OAuthClient> {
    const config = await (
      opts.ConfigClass as unknown as typeof OAuthConfig
    ).fromDiscovery(issuer, options);

    const state = opts.state ?? new OAuthState();

    return new OAuthClient(config, state, opts.storage ?? undefined);
  }

  static async fromStorage<T extends OAuthConfig = OAuthConfig>(
    storage: StorageProvider,
    ConfigClass: OAuthConfigFactory<T>,
    StateClass: typeof OAuthState = OAuthState,
    key: string,
  ): Promise<OAuthClient> {
    try {
      const store = await storage.get(`${OAuthClient.STATE_KEY}:${key}`);

      if (!store) {
        throw new OAuthStateError(`State ${key} not found`);
      }

      const json = JSON.parse(store);

      if (!json) {
        throw new OAuthStateError(`State ${key} not found`);
      }

      if (!("state" in json) && !("config" in json)) {
        throw new OAuthStateError(`State ${key} is invalid`);
      }

      const state = StateClass.fromJSON(json.state);
      const config = ConfigClass.fromJSON(json.config);

      return new OAuthClient(config, state, storage);
    } catch (e) {
      if (e instanceof SyntaxError) {
        throw new Error("Invalid state entry", { cause: e });
      }

      throw e;
    }
  }
}
