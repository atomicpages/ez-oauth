import assert from "node:assert";
import { OAuthClient } from "../src/OAuthClient";
import { GoogleOAuthConfig } from "../src/providers/GoogleOAuthConfig";
import { OAuthState } from "../src/state/OAuthState";
import { MemoryStorageProvider } from "../src/storage/MemoryStorageProvider";

const storage = new MemoryStorageProvider();

async function google(): Promise<Response> {
	const defaultBaseUrl = `http://${server.hostname}:${server.port}`;

	const config = (
		await GoogleOAuthConfig.discover("https://accounts.google.com", {
			clientId: Bun.env.GOOGLE_CLIENT_ID!,
			clientSecret: Bun.env.GOOGLE_CLIENT_SECRET!,
			redirectUri: `${Bun.env.REDIRECT_BASE_URL || defaultBaseUrl}mcp/oauth/callback`,
		})
	)
		.withRefreshToken()
		.withScopes([
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		]);

	const state = new OAuthState();
	const client = new OAuthClient(config, state, storage);
	const url = await client.createAuthorizationUrl();

	return new Response(url);
}

const server = Bun.serve({
	port: 3005,
	development: true,
	routes: {
		"/health": () => new Response("OK"),
		"/oauth/authorize/:provider": async (req) => {
			assert.ok(req.params.provider, "Provider is required");
			const provider = req.params.provider.toLowerCase();

			switch (provider) {
				case "google": {
					return await google();
				}
				case "atlassian":
					return new Response("Slack");
				case "audioscrape":
					return new Response("AudioScrape");
				default:
					return new Response("Provider not supported", { status: 400 });
			}
		},
		"/mcp/oauth/callback": async (req) => {
			const url = new URL(req.url);
			const state = url.searchParams.get("state");
			assert.ok(state, "State is required");
			assert.ok(url.searchParams.get("code"), "Code is required");

			const client = await OAuthClient.fromStorage(
				storage,
				GoogleOAuthConfig,
				OAuthState,
				state,
			);

			if (
				process.env.NODE_ENV === "development" &&
				url.hostname !== server.hostname
			) {
				url.protocol = "https";
			}

			const tokens = await client.getTokensFromCodeGrant(url);

			return new Response(JSON.stringify(tokens, null, 2), {
				headers: {
					"Content-Type": "application/json",
				},
			});
		},
	},
});

console.log(`Server is running on ${server.url}`);
