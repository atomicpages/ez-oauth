import { describe, expect, it } from "bun:test";
import { redirectUriMatches, toURL } from "../url";

describe("toURL", () => {
  it("should convert a string to a URL", () => {
    expect(toURL("https://example.com")).toBeInstanceOf(URL);
  });

  it("should return the same URL instance", () => {
    const u = new URL("https://example.com");
    expect(toURL(u)).toBe(u);
  });
});

describe("redirectUriMatches", () => {
  const expected = new URL("https://app.example.com/callback");

  it("returns true when scheme, host, port, and path match (callback has query)", () => {
    const callback = new URL(
      "https://app.example.com/callback?code=abc&state=xyz",
    );
    expect(redirectUriMatches(callback, expected)).toBe(true);
  });

  it("returns true when callback has fragment", () => {
    const callback = new URL("https://app.example.com/callback#frag");
    expect(redirectUriMatches(callback, expected)).toBe(true);
  });

  it("returns true for default https port (no port in URL)", () => {
    const expectedNoPort = new URL("https://app.example.com/callback");
    const callbackExplicit = new URL("https://app.example.com:443/callback");
    expect(redirectUriMatches(callbackExplicit, expectedNoPort)).toBe(true);
    expect(redirectUriMatches(expectedNoPort, callbackExplicit)).toBe(true);
  });

  it("returns true for default http port", () => {
    const expectedHttp = new URL("http://app.example.com/cb");
    const callbackHttp = new URL("http://app.example.com:80/cb?code=x");
    expect(redirectUriMatches(callbackHttp, expectedHttp)).toBe(true);
  });

  it("returns false when host differs", () => {
    const callback = new URL("https://evil.example.com/callback?code=abc");
    expect(redirectUriMatches(callback, expected)).toBe(false);
  });

  it("returns false when path differs", () => {
    const callback = new URL("https://app.example.com/other?code=abc");
    expect(redirectUriMatches(callback, expected)).toBe(false);
  });

  it("returns false when scheme differs", () => {
    const callback = new URL("http://app.example.com/callback?code=abc");
    expect(redirectUriMatches(callback, expected)).toBe(false);
  });

  it("returns false when port differs", () => {
    const callback = new URL("https://app.example.com:8443/callback");
    expect(redirectUriMatches(callback, expected)).toBe(false);
  });
});
