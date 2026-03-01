import { expect, test } from "bun:test";
import { MemoryStorageProvider } from "../MemoryStorageProvider";

test("constructor with initialState populates cache", () => {
  const store = new MemoryStorageProvider({ a: "1", b: "2" });

  expect(store.get("a")).toBe("1");
  expect(store.get("b")).toBe("2");
  expect(store.keys()).toEqual(["a", "b"]);
});

test("constructor with empty object has empty cache", () => {
  const store = new MemoryStorageProvider();

  expect(store.keys()).toEqual([]);
  expect(store.get("any")).toBeNull();
});

test("save sets value and get retrieves it", () => {
  const store = new MemoryStorageProvider();

  store.save("k", "v");

  expect(store.get("k")).toBe("v");
});

test("get returns null when key is missing", () => {
  const store = new MemoryStorageProvider();

  expect(store.get("missing")).toBeNull();
});

test("delete removes key", () => {
  const store = new MemoryStorageProvider({ x: "y" });

  expect(store.get("x")).toBe("y");

  store.delete("x");

  expect(store.get("x")).toBeNull();
  expect(store.has("x")).toBe(false);
});

test("has returns true when key exists, false when not", () => {
  const store = new MemoryStorageProvider({ foo: "bar" });

  expect(store.has("foo")).toBe(true);
  expect(store.has("missing")).toBe(false);
});

test("clear empties cache", () => {
  const store = new MemoryStorageProvider({ a: "1", b: "2" });

  store.clear();

  expect(store.keys()).toEqual([]);
  expect(store.get("a")).toBeNull();
  expect(store.get("b")).toBeNull();
  expect(store.has("a")).toBe(false);
});

test("keys returns all keys", () => {
  const store = new MemoryStorageProvider({ k1: "v1", k2: "v2" });

  const keyList = store.keys();

  expect(keyList).toContain("k1");
  expect(keyList).toContain("k2");
  expect(keyList).toHaveLength(2);
});
