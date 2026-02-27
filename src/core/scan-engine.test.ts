import { describe, it, expect } from 'vitest';
import { ScanEngine } from './scan-engine.js';
import { ScannerRegistry } from './scanner-registry.js';
import type { Scanner, Finding, ScanTarget } from './types.js';

const createTarget = (): ScanTarget => ({
  path: '/test/path',
  tools: [],
  sourceFiles: [],
});

const createScanner = (id: string, findings: Finding[] = []): Scanner => ({
  id,
  name: `Scanner ${id}`,
  category: 'pattern',
  rules: [],
  scan: async () => findings,
});

const createFinding = (severity: 'critical' | 'high' | 'medium' | 'low'): Finding => ({
  ruleId: 'TEST001',
  severity,
  message: `Test ${severity} finding`,
  location: { file: '/test' },
});

describe('ScanEngine', () => {
  it('should run all registered scanners', async () => {
    const registry = new ScannerRegistry();
    registry.register(createScanner('a', [createFinding('high')]));
    registry.register(createScanner('b', [createFinding('low')]));

    const engine = new ScanEngine(registry);
    const result = await engine.scan(createTarget());

    expect(result.findings).toHaveLength(2);
    expect(result.scanners).toHaveLength(2);
    expect(result.target).toBe('/test/path');
    expect(result.duration).toBeGreaterThanOrEqual(0);
  });

  it('should sort findings by severity', async () => {
    const registry = new ScannerRegistry();
    registry.register(
      createScanner('a', [createFinding('low'), createFinding('critical'), createFinding('medium')]),
    );

    const engine = new ScanEngine(registry);
    const result = await engine.scan(createTarget());

    expect(result.findings[0]!.severity).toBe('critical');
    expect(result.findings[1]!.severity).toBe('medium');
    expect(result.findings[2]!.severity).toBe('low');
  });

  it('should handle scanner errors gracefully', async () => {
    const registry = new ScannerRegistry();
    const errorScanner: Scanner = {
      id: 'error',
      name: 'Error Scanner',
      category: 'pattern',
      rules: [],
      scan: async () => {
        throw new Error('Scanner failed');
      },
    };
    registry.register(errorScanner);
    registry.register(createScanner('ok', [createFinding('high')]));

    const engine = new ScanEngine(registry);
    const result = await engine.scan(createTarget());

    expect(result.findings).toHaveLength(1);
    expect(result.scanners).toHaveLength(2);
    expect(result.scanners.find((s) => s.scannerId === 'error')?.error).toBe('Scanner failed');
  });

  it('should throw when no scanners are enabled', async () => {
    const registry = new ScannerRegistry();
    registry.register(createScanner('a'));

    const engine = new ScanEngine(registry);
    await expect(engine.scan(createTarget(), { scanners: ['nonexistent'] })).rejects.toThrow(
      'No scanners enabled',
    );
  });

  it('should filter to specified scanners', async () => {
    const registry = new ScannerRegistry();
    registry.register(createScanner('a', [createFinding('high')]));
    registry.register(createScanner('b', [createFinding('low')]));

    const engine = new ScanEngine(registry);
    const result = await engine.scan(createTarget(), { scanners: ['a'] });

    expect(result.scanners).toHaveLength(1);
    expect(result.scanners[0]!.scannerId).toBe('a');
  });
});
