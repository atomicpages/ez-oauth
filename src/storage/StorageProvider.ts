type MaybePromise<T> = T | Promise<T>;

export interface StorageProvider {
  save(key: string, value: string): MaybePromise<void>;
  get(key: string): MaybePromise<string | null>;
  delete(key: string): MaybePromise<void>;
  clear(): MaybePromise<void>;
  has(key: string): MaybePromise<boolean>;
  keys(): MaybePromise<string[]>;
}
