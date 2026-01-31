declare module "lru" {
  export default class LRU<T> {
    constructor(options: { max: number; maxAge?: number } | number);
    get(key: string): T | undefined;
    peek(key: string): T | undefined;
    set(key: string, value: T): void;
    remove(key: string): void;
    clear(): void;
    length: number;
    keys(): string[];
    on(
      key: "evict",
      callback: (value: { key: string; value: T }) => void
    ): void;
  }
}
