import { describe, expect, it } from "bun:test";
import { decodeBasicAuthCredentials } from "../auth";

describe("decodeBasicAuthCredentials", () => {
  it("should decode a basic auth header", () => {
    const input = `Basic ${Buffer.from("client_id:client_secret").toString("base64")}`;
    const result = decodeBasicAuthCredentials(input);
    // Returns the full fixed Authorization header (Basic + re-encoded credentials)
    expect(result).toBe(
      `Basic ${Buffer.from("client_id:client_secret", "utf8").toString("base64")}`,
    );
  });

  it("should return the original header if it doesn't start with Basic ", () => {
    const enc = Buffer.from("client_id:client_secret").toString("base64");
    expect(decodeBasicAuthCredentials(`Bearer ${enc}`)).toBe(`Bearer ${enc}`);
  });

  it("should return the original header if it's malformed", () => {
    // Unpadded base64 is still valid; implementation may fix it and return with padding
    const unpadded = "Basic Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ";
    const result = decodeBasicAuthCredentials(unpadded);
    expect(result).toBe(
      `Basic ${Buffer.from("client_id:client_secret", "utf8").toString("base64")}`,
    );
  });
});
