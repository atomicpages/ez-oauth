import { afterEach, expect, mock, test } from "bun:test";
import * as realOpenIdClient from "openid-client";
import { OAuthState } from "../OAuthState";

afterEach(() => {
  mock.restore();
});

test("OAuthState constructor with options exposes passed state, nonce, codeVerifier, and pkce", () => {
  const options = {
    state: "my_state",
    nonce: "my_nonce",
    codeVerifier: "my_verifier",
    pkce: "my_pkce",
  };
  const s = new OAuthState(options);

  expect(s.state).toBe("my_state");
  expect(s.nonce).toBe("my_nonce");
  expect(s.codeVerifier).toBe("my_verifier");
  expect(s.pkce).toBe("my_pkce");
});

test("OAuthState constructor without options generates non-empty state, nonce, codeVerifier; pkce undefined until getCodeChallenge", () => {
  const s = new OAuthState();

  expect(s.state).toBeTruthy();
  expect(s.state.length).toBeGreaterThan(0);
  expect(s.nonce).toBeTruthy();
  expect(s.nonce.length).toBeGreaterThan(0);
  expect(s.codeVerifier).toBeTruthy();
  expect(s.codeVerifier.length).toBeGreaterThan(0);
  expect(s.pkce).toBeUndefined();
});

test("getCodeChallenge returns pre-set pkce without calling openid-client", async () => {
  const calculateFn = mock(() => Promise.resolve("should_not_be_used"));

  mock.module("openid-client", () => ({
    ...realOpenIdClient,
    calculatePKCECodeChallenge: calculateFn,
  }));

  const { OAuthState: State } = await import("../OAuthState");
  const s = new State({
    state: "x",
    nonce: "y",
    codeVerifier: "v",
    pkce: "precomputed",
  });

  const challenge = await s.getCodeChallenge();

  expect(challenge).toBe("precomputed");
  expect(calculateFn).toHaveBeenCalledTimes(0);
});

test("getCodeChallenge calls calculatePKCECodeChallenge when pkce not provided and returns result", async () => {
  const calculateFn = mock(() => Promise.resolve("mocked_challenge"));

  mock.module("openid-client", () => ({
    ...realOpenIdClient,
    calculatePKCECodeChallenge: calculateFn,
  }));

  const { OAuthState: State } = await import("../OAuthState");
  const s = new State({ state: "x", nonce: "y", codeVerifier: "my_verifier" });

  const challenge = await s.getCodeChallenge();

  expect(challenge).toBe("mocked_challenge");
  expect(calculateFn).toHaveBeenCalledTimes(1);
  expect(calculateFn).toHaveBeenCalledWith("my_verifier");
});

test("fromJSON round-trip restores state, nonce, codeVerifier and getCodeChallenge behaves", async () => {
  mock.module("openid-client", () => ({
    ...realOpenIdClient,
    calculatePKCECodeChallenge: mock((verifier: string) =>
      Promise.resolve(`challenge_for_${verifier}`),
    ),
  }));

  const { OAuthState: State } = await import("../OAuthState");
  const original = new State({
    state: "s1",
    nonce: "n1",
    codeVerifier: "v1",
  });
  const json = original.toJSON();
  const restored = State.fromJSON(json);

  expect(restored.state).toBe(original.state);
  expect(restored.nonce).toBe(original.nonce);
  expect(restored.codeVerifier).toBe(original.codeVerifier);

  const challenge = await restored.getCodeChallenge();
  expect(challenge).toBe("challenge_for_v1");
});

test("toJSON includes name, state, nonce, pkce, codeVerifier", () => {
  const s = new OAuthState({
    state: "s",
    nonce: "n",
    codeVerifier: "v",
    pkce: "p",
  });
  const json = s.toJSON();

  expect(json.name).toBe("OAuthState");
  expect(json.state).toBe("s");
  expect(json.nonce).toBe("n");
  expect(json.codeVerifier).toBe("v");
  expect(json.pkce).toBe("p");
});
