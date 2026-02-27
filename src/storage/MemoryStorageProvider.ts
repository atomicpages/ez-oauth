import type { StorageProvider } from "./StorageProvider";

export class MemoryStorageProvider implements StorageProvider {
  protected cache: Map<string, string> = new Map();

  constructor(protected readonly initialState: Record<string, string> = {}) {
    for (const [key, value] of Object.entries(initialState)) {
      this.cache.set(key, value);
    }
  }

  delete(key: string): void {
    this.cache.delete(key);
  }

  has(key: string): boolean {
    return this.cache.has(key);
  }

  clear(): void {
    this.cache.clear();
  }

  keys(): string[] {
    return Array.from(this.cache.keys());
  }

  save(key: string, value: string): void {
    this.cache.set(key, value);
  }

  get(key: string): string | null {
    return this.cache.get(key) || null;
  }
}
