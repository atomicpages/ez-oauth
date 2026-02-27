import assert from "node:assert";
import type { RedisClient as BunRedisClient } from "bun";
import type { createClient } from "redis";
import type { StorageProvider } from "./StorageProvider";

type RedisClient = ReturnType<typeof createClient> | BunRedisClient;

type RedisStorageProviderOptions = {
  /**
   * The prefix to use for the keys in the Redis database.
   * @default "ez-oauth"
   */
  prefix?: string;
  /**
   * The delimiter to use between the prefix and the key.
   * @default ":"
   */
  delimiter?: string;
};

export class RedisStorageProvider implements StorageProvider {
  constructor(
    protected readonly redis: RedisClient,
    protected readonly options: RedisStorageProviderOptions = {
      prefix: "ez-oauth",
      delimiter: ":",
    },
  ) {
    assert(options.prefix, "prefix is required");
    assert(options.delimiter, "delimiter is required");
    assert(
      options.delimiter.length === 1,
      "delimiter must be a single character",
    );
  }

  protected createKey(key: string): string {
    return `${this.options.prefix}${this.options.delimiter}${key}`;
  }

  /**
   * Checks if a key exists in the Redis database.
   * @param key
   * @returns True if the key exists, false otherwise.
   * @example
   * ```ts
   * const exists = await storage.has("user:123");
   * console.log(exists); // true
   * ```
   */
  async has(key: string): Promise<boolean> {
    const exists = await this.redis.exists(this.createKey(key));

    if (typeof exists === "number") {
      return exists > 0;
    }

    return exists;
  }

  async delete(key: string): Promise<void> {
    await this.redis.del(this.createKey(key));
  }

  async clear(): Promise<void> {
    await this.redis.del(`${this.options.prefix}*`);
  }

  async keys(): Promise<string[]> {
    return this.redis.keys(`${this.options.prefix}*`);
  }

  async save(key: string, value: string): Promise<void> {
    await this.redis.set(this.createKey(key), value);
  }

  async get(key: string): Promise<string | null> {
    return await this.redis.get(this.createKey(key));
  }
}
