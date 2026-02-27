import { describe, it, expect } from 'vitest';
import { ScannerRegistry } from './scanner-registry.js';
import type { Scanner, Finding, ScanTarget } from './types.js';

const createMockScanner = (id: string): Scanner => ({
  id,
  name: `Mock ${id}`,
  category: 'pattern',
  rules: [],
  scan: async () => [],
});

describe('ScannerRegistry', () => {
  it('should register and retrieve a scanner', () => {
    const registry = new ScannerRegistry();
    const scanner = createMockScanner('test');
    registry.register(scanner);

    expect(registry.get('test')).toBe(scanner);
    expect(registry.has('test')).toBe(true);
    expect(registry.size).toBe(1);
  });

  it('should throw on duplicate registration', () => {
    const registry = new ScannerRegistry();
    registry.register(createMockScanner('test'));

    expect(() => registry.register(createMockScanner('test'))).toThrow(
      'Scanner "test" is already registered',
    );
  });

  it('should return undefined for unknown scanner', () => {
    const registry = new ScannerRegistry();
    expect(registry.get('unknown')).toBeUndefined();
  });

  it('should return all scanners', () => {
    const registry = new ScannerRegistry();
    registry.register(createMockScanner('a'));
    registry.register(createMockScanner('b'));

    expect(registry.getAll()).toHaveLength(2);
  });

  it('should filter enabled scanners', () => {
    const registry = new ScannerRegistry();
    registry.register(createMockScanner('a'));
    registry.register(createMockScanner('b'));
    registry.register(createMockScanner('c'));

    const enabled = registry.getEnabled(['a', 'c']);
    expect(enabled).toHaveLength(2);
    expect(enabled.map((s) => s.id)).toEqual(['a', 'c']);
  });

  it('should return all scanners when no filter provided', () => {
    const registry = new ScannerRegistry();
    registry.register(createMockScanner('a'));
    registry.register(createMockScanner('b'));

    expect(registry.getEnabled()).toHaveLength(2);
  });
});
