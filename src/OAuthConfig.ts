import assert from "node:assert";
import type { BodyInit } from "bun";
import ky, { type Hooks } from "ky";
import { LRUCache } from "lru-cache";
import * as client from "openid-client";
import { ClientAuth } from "./enum";

const PROTECTED_RESOURCE_DISCOVERY_JWT_MEDIA_TYPE =
	"application/oauth-protected-resource-jwt";
const PROTECTED_RESOURCE_DISCOVERY_JSON_MEDIA_TYPE =
	"application/oauth-protected-resource+json";

/**
 * Base OAuth configuration wrapper
 * Wraps openid-client Configuration with custom HTTP behavior via ky
 *
 * Subclass this to customize HTTP behavior for specific providers
 */
export class OAuthConfig {
	private static readonly cache = new LRUCache<string, any>({
		max: 500,
		ttl: 1000 * 60 * 60 * 24 * 7, // 7 days
	});

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
		this.redirectUri = OAuthConfig.toURL(redirectUri);

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

	private static async getProtectedResourceDiscovery(issuer: URL | string) {
		if (OAuthConfig.cache.has(issuer.toString())) {
			return OAuthConfig.cache.get(issuer.toString());
		}

		const url = OAuthConfig.toURL(issuer);
		url.pathname = ".well-known/oauth-protected-resource";

		const res = await ky.get(url.toString(), {
			headers: {
				Accept: PROTECTED_RESOURCE_DISCOVERY_JSON_MEDIA_TYPE,
			},
		});

		if (res.ok) {
			if (
				res.headers
					.get("Content-Type")
					?.includes(PROTECTED_RESOURCE_DISCOVERY_JWT_MEDIA_TYPE)
			) {
				throw new Error(
					`${PROTECTED_RESOURCE_DISCOVERY_JWT_MEDIA_TYPE} is not supported`,
				);
			}

			try {
				const json = await res.json<{
					authorization_servers: [string, ...string[]];
					bearer_methods_supported: [string, ...string[]];
					resource_endpoints?: [string, ...string[]];
					resource_signing_alg_values_supported: [string, ...string[]];
					resource: string;
					resource_documentation: string;
				}>();

				OAuthConfig.cache.set(issuer.toString(), json);

				return json;
			} catch (error) {
				throw new Error(`Invalid protected resource discovery: ${res}`);
			}
		}

		return null;
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

	static async dcr(
		this: new (
			userConfig: client.Configuration,
			redirectUri: string | URL,
		) => OAuthConfig,
		issuer: URL | string,
		options: {
			algorithm?: "oidc" | "oauth2" | "protected-resource";
			redirectUri: string | URL;
		},
	): Promise<OAuthConfig> {
		let url = OAuthConfig.toURL(issuer);

		if (options.algorithm === "protected-resource") {
			const discovery = await OAuthConfig.getProtectedResourceDiscovery(issuer);

			if (discovery) {
				assert.ok(
					discovery.authorization_servers.length > 0,
					"No authorization servers found",
				);

				url = new URL(discovery.authorization_servers[0]);
			}
		}

		const config = await client.dynamicClientRegistration(url, {});

		return new OAuthConfig(config, options.redirectUri);
	}

	static cimd(...args: Parameters<typeof client.dynamicClientRegistration>) {
		return client.dynamicClientRegistration(...args);
	}

	static async discover<T extends OAuthConfig = OAuthConfig>(
		this: new (
			userConfig: client.Configuration,
			redirectUri: string | URL,
		) => T,
		issuer: URL | string,
		options: {
			clientId: string;
			clientSecret?: string;
			redirectUri: string;
			/**
			 * The algorithm to use for the discovery.
			 * @default "oidc"
			 */
			algorithm?: "oidc" | "oauth2" | "protected-resource";
		},
	): Promise<T> {
		let url = OAuthConfig.toURL(issuer);

		if (options.algorithm === "protected-resource") {
			const discovery = await OAuthConfig.getProtectedResourceDiscovery(issuer);

			if (discovery) {
				assert.ok(
					discovery.authorization_servers.length > 0,
					"No authorization servers found",
				);

				url = new URL(discovery.authorization_servers[0]);
			}
		}

		return new OAuthConfig(
			await client.discovery(
				url,
				options.clientId,
				options.clientSecret,
				undefined,
				{
					algorithm:
						options.algorithm === "protected-resource"
							? "oauth2"
							: options.algorithm,
				},
			),
			options.redirectUri,
		);
	}

	static toURL(url: URL | string): URL {
		if (url instanceof URL) {
			return url;
		}

		return new URL(url);
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
