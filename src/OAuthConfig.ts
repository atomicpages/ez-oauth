import type { BodyInit } from "bun";
import ky, { type Hooks } from "ky";
import * as client from "openid-client";
import type { DcrOptions, DiscoverOptions } from "./discovery";
import { OAuthDiscovery } from "./discovery";
import { ClientAuth, type GrantType } from "./enum";
import { toURL } from "./utils/url";

/**
 * Base OAuth configuration wrapper
 * Wraps openid-client Configuration with custom HTTP behavior via ky
 *
 * Subclass this to customize HTTP behavior for specific providers
 */
export class OAuthConfig {
  protected _additionalParams: Record<string, string> = {};
  protected _scopes: string[] = [];
  readonly supportsPKCE: boolean = false;
  readonly redirectUri: URL;

  constructor(
    protected readonly userConfig: client.Configuration,
    redirectUri: string | URL,
  ) {
    userConfig[client.customFetch] = this.createCustomFetch();
    this.supportsPKCE = userConfig.serverMetadata().supportsPKCE();
    this.redirectUri = toURL(redirectUri);

    if (this._additionalParams) {
      for (const [key, value] of Object.entries(this._additionalParams)) {
        this.redirectUri.searchParams.set(key, value);
      }
    }
  }

  get scopes() {
    return this._scopes.slice();
  }

  get additionalParams() {
    return Object.assign({}, this._additionalParams);
  }

  /**
   * Create a custom fetch function with ky
   * Override this method to customize HTTP behavior
   */
  protected createCustomFetch(): client.CustomFetch {
    return (...args) => {
      return ky(args[0], {
        ...args[1],
        body: args[1].body as BodyInit,
        hooks: this.createHooks(),
      });
    };
  }

  withRefreshToken(): this {
    return this;
  }

  withScopes(scopes: string[]): this {
    this._scopes = scopes;
    return this;
  }

  /**
   * Create ky hooks for customizing HTTP requests
   * Override this in subclasses to add provider-specific behavior
   */
  protected createHooks(): Hooks | undefined {
    return undefined;
  }

  /**
   * Get the underlying openid-client Configuration
   */
  get config() {
    return this.userConfig;
  }

  static toClientAuth(type: ClientAuth) {
    switch (type) {
      case ClientAuth.CLIENT_SECRET_JWT:
        return client.ClientSecretJwt;
      case ClientAuth.PRIVATE_KEY_JWT:
        return client.PrivateKeyJwt;
      case ClientAuth.NONE:
        return client.None;
      case ClientAuth.TLS_CLIENT_AUTH:
        return client.TlsClientAuth;
      case ClientAuth.CLIENT_SECRET_POST:
        return client.ClientSecretPost;
      case ClientAuth.CLIENT_SECRET_BASIC:
        return client.ClientSecretBasic;
      default:
        throw new Error(`Unsupported credential type: ${type}`);
    }
  }

  /**
   * Build config from AS metadata discovery. Does not cache; callers may cache.
   */
  static async fromDiscovery<T extends OAuthConfig = OAuthConfig>(
    this: new (
      userConfig: client.Configuration,
      redirectUri: string | URL,
    ) => T,
    issuer: URL | string,
    options: DiscoverOptions,
  ): Promise<T> {
    const configuration = await OAuthDiscovery.discover(issuer, options);

    return new OAuthConfig(configuration, options.redirectUri) as T;
  }

  /**
   * Build config from Dynamic Client Registration. Does not cache; callers may cache.
   */
  static async fromDcr<T extends OAuthConfig = OAuthConfig>(
    this: new (
      userConfig: client.Configuration,
      redirectUri: string | URL,
    ) => T,
    issuer: URL | string,
    options: DcrOptions,
  ): Promise<T> {
    const configuration = await OAuthDiscovery.dcr(issuer, options);
    const redirectUri =
      options.redirectUri instanceof URL
        ? options.redirectUri
        : new URL(options.redirectUri);
    return new OAuthConfig(configuration, redirectUri) as T;
  }

  static toURL(url: URL | string): URL {
    if (url instanceof URL) {
      return url;
    }
    return new URL(url);
  }

  static create<T extends OAuthConfig = OAuthConfig>(
    this: new (
      userConfig: client.Configuration,
      redirectUri: string | URL,
    ) => T,
    config: {
      tokenUrl: string;
      authorizationUrl: string;
      grantTypes?: [GrantType, ...GrantType[]];
      scopes?: [string, ...string[]];
      tokenAuthMethods?: [ClientAuth, ...ClientAuth[]];
    },
    clientId: string,
    redirectUri: string | URL,
  ): T {
    const clientConfig = new client.Configuration(
      {
        issuer: OAuthConfig.toURL(config.authorizationUrl).origin,
        token_endpoint: config.tokenUrl,
        authorization_endpoint: config.authorizationUrl,
        grant_types_supported: config.grantTypes,
        scopes_supported: config.scopes,
        token_endpoint_auth_methods_supported: config.tokenAuthMethods,
      },
      clientId,
    );

    return new OAuthConfig(clientConfig, redirectUri) as T;
  }

  static fromJSON(json: ReturnType<OAuthConfig["toJSON"]>): OAuthConfig {
    return new OAuthConfig(
      new client.Configuration(json.server, json.client.client_id, json.client),
      json.redirectUri,
    );
  }

  /**
   * Serialize config to JSON for logging/debugging
   */
  toJSON() {
    return {
      name: this.constructor.name,
      scopes: this.scopes,
      supportsPKCE: this.supportsPKCE,
      server: this.config.serverMetadata(),
      client: this.config.clientMetadata(),
      redirectUri: this.redirectUri.toString(),
    };
  }

  /**
   * A stringified JSON representation of the config. You will NOT
   * see `[object Object]` as the output 🫠
   */
  toString(): string {
    return JSON.stringify(this.toJSON());
  }
}
