/**
 * In-process mock OAuth 2.0 authorization server for integration tests.
 * Serves discovery, authorize (redirect with code/state), and token (code + PKCE, refresh).
 * Test-only; not part of the published package.
 */

type PendingAuth = {
  state: string;
  code_challenge: string;
  code_challenge_method: string;
  redirect_uri: string;
};

/** RFC 7636: verify code_verifier against code_challenge (S256). */
async function verifyPKCE(
  codeVerifier: string,
  codeChallenge: string,
): Promise<boolean> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(codeVerifier),
  );

  const base64 = Buffer.from(digest).toString("base64");
  const base64url = base64
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  return base64url === codeChallenge;
}

export type MockASResult = {
  server: ReturnType<typeof Bun.serve>;
  baseUrl: string;
};

/** Start the mock AS on a random port. Call server.stop() when done. */
export function startMockAS(): MockASResult {
  const pendingByCode = new Map<string, PendingAuth>();
  const validRefreshTokens = new Set<string>();

  const server = Bun.serve({
    port: 0,
    async fetch(req) {
      const url = new URL(req.url);
      const base = `${url.protocol}//${url.host}`;

      // GET /.well-known/openid-configuration
      if (
        url.pathname === "/.well-known/openid-configuration" &&
        req.method === "GET"
      ) {
        const body = JSON.stringify({
          issuer: base,
          authorization_endpoint: `${base}/authorize`,
          token_endpoint: `${base}/token`,
          code_challenge_methods_supported: ["S256"],
          token_endpoint_auth_methods_supported: [
            "client_secret_basic",
            "client_secret_post",
          ],
          response_types_supported: ["code"],
          grant_types_supported: ["authorization_code", "refresh_token"],
          scopes_supported: ["openid", "profile"],
        });
        return new Response(body, {
          headers: { "Content-Type": "application/json" },
        });
      }

      // GET /authorize
      if (url.pathname === "/authorize" && req.method === "GET") {
        const state = url.searchParams.get("state");
        const redirect_uri = url.searchParams.get("redirect_uri");
        const code_challenge = url.searchParams.get("code_challenge");

        const code_challenge_method =
          url.searchParams.get("code_challenge_method") ?? "S256";

        if (!state || !redirect_uri || !code_challenge) {
          return new Response(
            "Missing state, redirect_uri, or code_challenge",
            {
              status: 400,
            },
          );
        }

        const code = `code_${Date.now()}_${Math.random().toString(36).slice(2)}`;

        pendingByCode.set(code, {
          state,
          code_challenge,
          code_challenge_method,
          redirect_uri,
        });

        const redirect = new URL(redirect_uri);
        redirect.searchParams.set("code", code);
        redirect.searchParams.set("state", state);
        return Response.redirect(redirect.toString(), 302);
      }

      // POST /token
      if (url.pathname === "/token" && req.method === "POST") {
        const contentType = req.headers.get("Content-Type") ?? "";
        const body: Record<string, string> = {};

        if (contentType.includes("application/x-www-form-urlencoded")) {
          const text = await req.text();
          for (const pair of new URLSearchParams(text)) {
            body[pair[0]] = pair[1];
          }
        }

        const auth = req.headers.get("Authorization");

        if (auth?.startsWith("Basic ")) {
          const decoded = atob(auth.slice(6));
          const i = decoded.indexOf(":");

          if (i >= 0) {
            body.client_id = body.client_id ?? decoded.slice(0, i);
            body.client_secret = body.client_secret ?? decoded.slice(i + 1);
          }
        }

        const grant_type = body.grant_type;

        if (grant_type === "authorization_code") {
          const code = body.code;
          const code_verifier = body.code_verifier;
          const redirect_uri = body.redirect_uri;

          if (!code || !code_verifier) {
            return new Response(
              JSON.stringify({
                error: "invalid_request",
                error_description: "Missing code or code_verifier",
              }),
              { status: 400, headers: { "Content-Type": "application/json" } },
            );
          }

          const pending = pendingByCode.get(code);

          if (!pending) {
            return new Response(
              JSON.stringify({
                error: "invalid_grant",
                error_description: "Code not found or already used",
              }),
              { status: 400, headers: { "Content-Type": "application/json" } },
            );
          }

          if (pending.redirect_uri !== redirect_uri) {
            return new Response(
              JSON.stringify({
                error: "invalid_grant",
                error_description: "redirect_uri mismatch",
              }),
              { status: 400, headers: { "Content-Type": "application/json" } },
            );
          }

          const valid = await verifyPKCE(code_verifier, pending.code_challenge);

          if (!valid) {
            return new Response(
              JSON.stringify({
                error: "invalid_grant",
                error_description: "PKCE verification failed",
              }),
              { status: 400, headers: { "Content-Type": "application/json" } },
            );
          }

          pendingByCode.delete(code);

          const access_token = `at_${Date.now()}_${Math.random().toString(36).slice(2)}`;
          const refresh_token = `rt_${Date.now()}_${Math.random().toString(36).slice(2)}`;
          validRefreshTokens.add(refresh_token);

          return new Response(
            JSON.stringify({
              access_token,
              refresh_token,
              expires_in: 3600,
              token_type: "Bearer",
            }),
            {
              status: 200,
              headers: { "Content-Type": "application/json" },
            },
          );
        }

        if (grant_type === "refresh_token") {
          const refresh_token = body.refresh_token;

          if (!refresh_token || !validRefreshTokens.has(refresh_token)) {
            return new Response(
              JSON.stringify({
                error: "invalid_grant",
                error_description: "Invalid refresh token",
              }),
              { status: 400, headers: { "Content-Type": "application/json" } },
            );
          }

          const access_token = `at_${Date.now()}_${Math.random().toString(36).slice(2)}`;

          return new Response(
            JSON.stringify({
              access_token,
              expires_in: 3600,
              token_type: "Bearer",
            }),
            {
              status: 200,
              headers: { "Content-Type": "application/json" },
            },
          );
        }

        return new Response(
          JSON.stringify({
            error: "unsupported_grant_type",
            error_description: `Grant type: ${grant_type}`,
          }),
          { status: 400, headers: { "Content-Type": "application/json" } },
        );
      }

      return new Response("Not Found", { status: 404 });
    },
  });

  const baseUrl = `http://127.0.0.1:${server.port}`;

  return { server, baseUrl };
}
