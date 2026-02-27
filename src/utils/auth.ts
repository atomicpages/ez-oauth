function safeDecode(s: string, part: string) {
  try {
    return decodeURIComponent(s);
  } catch (error) {
    console.error(
      `Failed to URL decode OAuth credential ${part}: ${error instanceof Error ? error.message : "Unknown error"}`,
    );

    return s;
  }
}

/**
 * Fixes URL-encoded credentials in Basic Auth headers.
 * The openid-client library URL-encodes client credentials when creating Basic Auth headers,
 * but some OAuth providers (like Reddit) reject URL-encoded credentials.
 *
 * @param authHeader - The Authorization header value (e.g., "Basic base64string")
 * @returns The fixed Authorization header with URL-decoded credentials
 */
export function decodeBasicAuthCredentials(authHeader: string): string {
  if (!authHeader.startsWith("Basic ")) {
    return authHeader;
  }

  try {
    const encoded = authHeader.slice(6).trim(); // drop "Basic "
    const raw = Buffer.from(encoded, "base64").toString("utf8");

    // Security: Validate credential length to prevent memory exhaustion
    // OAuth credentials are typically under 150 chars total, 512 is a safe upper bound
    // https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
    if (raw.length > 512) {
      console.error(
        "OAuth Basic Auth credentials exceed size limit, skipping decode",
      );

      return authHeader; // Reject suspiciously large credentials
    }

    const sep = raw.indexOf(":");

    if (sep > -1) {
      const idPart = raw.slice(0, sep);
      const secretPart = raw.slice(sep + 1);
      const fixed = `${safeDecode(idPart, "client_id")}:${safeDecode(secretPart, "client_secret")}`;
      const fixedAuthHeader = `Basic ${Buffer.from(fixed, "utf8").toString("base64")}`;

      return fixedAuthHeader;
    }

    // Malformed header; leave as-is
    console.error(
      "OAuth Basic Auth header missing colon separator, leaving unchanged",
    );

    return authHeader;
  } catch (error) {
    // If any decoding fails, keep original header
    console.error(
      `Failed to process OAuth Basic Auth header: ${error instanceof Error ? error.message : "Unknown error"}`,
    );
  }

  return authHeader;
}
