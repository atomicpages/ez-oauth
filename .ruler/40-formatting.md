# Code Formatting

Let your code breathe.

- ALWAYS follow 1tbs (one true brace style), zero exceptions.
- Insert a new line before all control structures `if`, `switch`, `for`,
  `while`, `do`, etc., except:
  - when at the start of a function
  - when the only statement in a function is the control
- Insert a new line above all `return` except for where `return` is the only
  statement
- Add new lines between all multi-line statements

## Example

```ts
// valid
function greet(name: string) {
  return `Hello ${name}`;
}

// valid
const greet = (name: string) => `Hello ${name}`;

// valid
function allow(age: number, cb: VoidFunction) {
  if (age < 18) {
    throw new Error("18 is the minimum allowed age");
  } else {
    cb();
  }
}

// valid
test("getToken with cache and expired entry requests new token", async () => {
  const grantFn = mock(async () => ({
    // multi-line statements have a new line
    access_token: "token",
    expires_in: 3600,
    token_type: "Bearer",
  }));

  mock.module("openid-client", () => ({
    // same here, new line above and below the ML stmt
    ...realOpenIdClient,
    clientCredentialsGrant: grantFn,
  }));

  const { ClientCredentialsGrant: CCGrant } =
    await import("../ClientCredentialsGrant");

  const config = await createTestConfig(); // no new line is fine here
  const expiredAt = Date.now() - 1000;

  const cached = JSON.stringify({
    // new line, good
    access_token: "old_token",
    expires_at: expiredAt,
    token_type: "Bearer",
  });

  const cache = new MemoryStorageProvider({ oauth_cc: cached }); // also good
  const grant = new CCGrant(config, { cache, cacheKey: "oauth_cc" });

  const result = await grant.getToken(); // adding extra line for readability
  expect(result.access_token).toBe("token");
  expect(grantFn).toHaveBeenCalledTimes(1);
});
```
