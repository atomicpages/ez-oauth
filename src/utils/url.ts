export function toURL(url: URL | string): URL {
  if (url instanceof URL) {
    return url;
  }

  return new URL(url);
}

function defaultPort(protocol: string): string {
  if (protocol === "https:") {
    return "443";
  }

  if (protocol === "http:") {
    return "80";
  }

  return "";
}

/**
 * Returns true if callback has the same scheme, host, port, and path as expected.
 * Query and fragment are ignored (callback will have code, state, etc.).
 * Used to validate OAuth callback URL against configured redirect_uri (RFC 6819).
 */
export function redirectUriMatches(callback: URL, expected: URL): boolean {
  if (callback.protocol !== expected.protocol) {
    return false;
  }

  if (callback.hostname !== expected.hostname) {
    return false;
  }

  const defaultP = defaultPort(callback.protocol);
  const callbackPort = callback.port || defaultP;
  const expectedPort = expected.port || defaultP;

  if (callbackPort !== expectedPort) {
    return false;
  }

  return callback.pathname === expected.pathname;
}
