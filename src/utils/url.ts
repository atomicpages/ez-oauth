export function toURL(url: URL | string): URL {
  if (url instanceof URL) {
    return url;
  }

  return new URL(url);
}
