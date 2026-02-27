import { describe, it, expect } from 'vitest';
import { resolve } from 'path';
import { ScanEngine } from '../../src/core/scan-engine.js';
import { createDefaultRegistry } from '../../src/scanners/index.js';
import { loadMCPServer } from '../../src/loaders/index.js';

const FIXTURES_DIR = resolve(import.meta.dirname, '../fixtures/servers');

describe('Integration: Scan Pipeline', () => {
  it('should detect vulnerabilities in vulnerable server', async () => {
    const registry = createDefaultRegistry();
    const engine = new ScanEngine(registry);
    const target = await loadMCPServer(resolve(FIXTURES_DIR, 'vulnerable-server'));

    const result = await engine.scan(target);

    expect(result.findings.length).toBeGreaterThan(0);

    const ruleIds = result.findings.map((f) => f.ruleId);

    // Tool poisoning
    expect(ruleIds.some((id) => id.startsWith('TP'))).toBe(true);
    // Command injection
    expect(ruleIds.some((id) => id.startsWith('CI'))).toBe(true);
    // Data exfiltration
    expect(ruleIds.some((id) => id.startsWith('DE'))).toBe(true);
    // Auth/transport
    expect(ruleIds.some((id) => id.startsWith('AT'))).toBe(true);
    // Supply chain
    expect(ruleIds.some((id) => id.startsWith('SC'))).toBe(true);
    // Over-permission
    expect(ruleIds.some((id) => id.startsWith('OP'))).toBe(true);

    // Verify severity ordering
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    for (let i = 1; i < result.findings.length; i++) {
      const prev = severityOrder[result.findings[i - 1]!.severity];
      const curr = severityOrder[result.findings[i]!.severity];
      expect(curr).toBeGreaterThanOrEqual(prev);
    }
  }, 30000);

  it('should produce minimal findings for clean server', async () => {
    const registry = createDefaultRegistry();
    const engine = new ScanEngine(registry);
    const target = await loadMCPServer(resolve(FIXTURES_DIR, 'clean-server'));

    const result = await engine.scan(target);

    // Clean server should have very few findings
    // May still have some like missing auth or rate limiting since it's a minimal example
    const criticalFindings = result.findings.filter((f) => f.severity === 'critical');
    expect(criticalFindings).toHaveLength(0);

    // No tool poisoning or injection findings
    expect(result.findings.filter((f) => f.ruleId.startsWith('TP'))).toHaveLength(0);
    expect(result.findings.filter((f) => f.ruleId.startsWith('PI'))).toHaveLength(0);
    expect(result.findings.filter((f) => f.ruleId.startsWith('CI'))).toHaveLength(0);
    expect(result.findings.filter((f) => f.ruleId.startsWith('DE'))).toHaveLength(0);
  }, 30000);

  it('should report all scanners ran successfully', async () => {
    const registry = createDefaultRegistry();
    const engine = new ScanEngine(registry);
    const target = await loadMCPServer(resolve(FIXTURES_DIR, 'vulnerable-server'));

    const result = await engine.scan(target);

    expect(result.scanners).toHaveLength(8);
    for (const scanner of result.scanners) {
      expect(scanner.error).toBeUndefined();
      expect(scanner.duration).toBeGreaterThanOrEqual(0);
    }
  });

  it('should run only specified scanners', async () => {
    const registry = createDefaultRegistry();
    const engine = new ScanEngine(registry);
    const target = await loadMCPServer(resolve(FIXTURES_DIR, 'vulnerable-server'));

    const result = await engine.scan(target, { scanners: ['tool-poisoning', 'command-injection'] });

    expect(result.scanners).toHaveLength(2);
    expect(result.scanners.map((s) => s.scannerId).sort()).toEqual([
      'command-injection',
      'tool-poisoning',
    ]);
  });
});
