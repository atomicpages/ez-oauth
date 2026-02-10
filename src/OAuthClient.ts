import { HTTPError } from "ky";
import * as client from "openid-client";
import URLSheriff from "url-sheriff";
import { OAuthClientError } from "./errors/OAuthClientError";
import { OAuthStateError } from "./errors/OAuthStateError";
import { OAuthConfig } from "./OAuthConfig";
import { OAuthState } from "./state/OAuthState";
import type { StorageProvider } from "./storage/StorageProvider";

type URLSheriffConfig = ConstructorParameters<typeof URLSheriff>[0];

type OAuthClientOptions = {
	sheriffConfig?: URLSheriffConfig;
};

type OAuthConfigFactory<T extends OAuthConfig = OAuthConfig> = {
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
			this.storage.save(
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
		try {
			const tokens = await client.authorizationCodeGrant(
				this.config.config,
				OAuthConfig.toURL(url),
				{
					expectedState: this.state.state,
					pkceCodeVerifier: this.state.codeVerifier,
					expectedNonce: this.state.nonce,
				},
			);

			return tokens;
		} catch (e) {
			if (e instanceof client.ClientError) {
				let reason: any;

				if (e.cause instanceof HTTPError) {
					reason = await e.cause?.response.body?.json();
				}

				throw new OAuthClientError("Failed to get tokens from code grant", {
					cause: e,
					reason,
				});
			}
		}
	}

	async refreshToken<T extends OAuthConfig = OAuthConfig>(
		config: T,
		refreshToken: string,
	): Promise<Awaited<ReturnType<typeof client.refreshTokenGrant>>> {
		const tokens = await client.refreshTokenGrant(
			config.config,
			refreshToken,
			this.config.additionalParams,
		);

		return tokens;
	}

	revokeToken<T extends OAuthConfig = OAuthConfig>(
		config: T,
		token: string,
	): Promise<void> {
		return client.tokenRevocation(
			config.config,
			token,
			this.config.additionalParams,
		);
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
