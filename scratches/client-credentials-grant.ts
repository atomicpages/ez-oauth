/**
 * Example: client credentials (M2M) flow using the library.
 * redirectUri is NOT required for this flow — omit it in discovery options.
 *
 * Run: bun run scratches/client-credentials-grant.ts
 */

import {
  ClientCredentialsGrant,
  MemoryStorageProvider,
  OAuthConfig,
} from "../src/index";

async function exampleNoCache() {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  if (!clientId || !clientSecret) return;

  const config = await OAuthConfig.fromDiscovery(
    "https://accounts.google.com",
    {
      clientId,
      clientSecret,
      // redirectUri omitted — not used for client credentials grant
    },
  );
  config.withScopes(["https://www.googleapis.com/auth/cloud-platform"]);

  const grant = new ClientCredentialsGrant(config);
  const tokens = await grant.getToken();
  console.log(
    "access_token (first 20 chars):",
    tokens.access_token.slice(0, 20) + "...",
  );
  console.log("expires_in:", tokens.expires_in);
}

async function exampleWithCache() {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  if (!clientId || !clientSecret) return;

  const cache = new MemoryStorageProvider();

  const config = await OAuthConfig.fromDiscovery(
    "https://accounts.google.com",
    {
      clientId,
      clientSecret,
    },
  );
  config.withScopes(["https://www.googleapis.com/auth/cloud-platform"]);

  const grant = new ClientCredentialsGrant(config, { cache });

  const t1 = await grant.getToken();
  const t2 = await grant.getToken();
  console.log("Same token (cached):", t1.access_token === t2.access_token);
}

const main = async () => {
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
    console.log(
      "Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to run the example.",
    );
    console.log("Scratch: scratches/client-credentials-grant.ts");
    return;
  }
  await exampleNoCache();
  await exampleWithCache();
};

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
