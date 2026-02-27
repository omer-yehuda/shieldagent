import type { Scanner } from './types.js';

export class ScannerRegistry {
  private scanners = new Map<string, Scanner>();

  register(scanner: Scanner): void {
    if (this.scanners.has(scanner.id)) {
      throw new Error(`Scanner "${scanner.id}" is already registered`);
    }
    this.scanners.set(scanner.id, scanner);
  }

  get(id: string): Scanner | undefined {
    return this.scanners.get(id);
  }

  getAll(): Scanner[] {
    return Array.from(this.scanners.values());
  }

  getEnabled(enabledIds?: string[]): Scanner[] {
    if (!enabledIds) return this.getAll();
    return this.getAll().filter((s) => enabledIds.includes(s.id));
  }

  has(id: string): boolean {
    return this.scanners.has(id);
  }

  get size(): number {
    return this.scanners.size;
  }
}
