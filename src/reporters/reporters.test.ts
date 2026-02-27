import { describe, it, expect } from 'vitest';
import { formatJson, formatSarif, formatTable } from './index.js';
import type { ScanResult } from '../core/types.js';

const createResult = (findingsCount: number): ScanResult => ({
  target: '/test/path',
  findings: Array.from({ length: findingsCount }, (_, i) => ({
    ruleId: `TEST${String(i + 1).padStart(3, '0')}`,
    severity: (['critical', 'high', 'medium', 'low'] as const)[i % 4],
    message: `Finding ${i + 1}`,
    location: { file: '/test/file.ts', line: i + 1 },
    fingerprint: `fp${i}`,
  })),
  scanners: [
    {
      scannerId: 'test-scanner',
      scannerName: 'Test Scanner',
      findings: [],
      duration: 10,
    },
  ],
  duration: 50,
  timestamp: '2026-01-01T00:00:00.000Z',
});

describe('JSON Reporter', () => {
  it('should output valid JSON', () => {
    const result = createResult(2);
    const output = formatJson(result);
    const parsed = JSON.parse(output);

    expect(parsed.target).toBe('/test/path');
    expect(parsed.findings).toHaveLength(2);
  });

  it('should handle empty findings', () => {
    const output = formatJson(createResult(0));
    const parsed = JSON.parse(output);
    expect(parsed.findings).toHaveLength(0);
  });
});

describe('SARIF Reporter', () => {
  it('should produce valid SARIF structure', () => {
    const output = formatSarif(createResult(2));
    const sarif = JSON.parse(output);

    expect(sarif.$schema).toContain('sarif');
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe('ShieldAgent');
    expect(sarif.runs[0].results).toHaveLength(2);
  });

  it('should map severity to SARIF levels', () => {
    const output = formatSarif(createResult(4));
    const sarif = JSON.parse(output);
    const levels = sarif.runs[0].results.map((r: { level: string }) => r.level);

    expect(levels).toContain('error');
    expect(levels).toContain('warning');
    expect(levels).toContain('note');
  });

  it('should include fingerprints', () => {
    const output = formatSarif(createResult(1));
    const sarif = JSON.parse(output);

    expect(sarif.runs[0].results[0].fingerprints).toBeDefined();
    expect(sarif.runs[0].results[0].fingerprints['shieldagent/v1']).toBe('fp0');
  });
});

describe('Table Reporter', () => {
  it('should include scan target in output', () => {
    const output = formatTable(createResult(1));
    expect(output).toContain('/test/path');
  });

  it('should show "no findings" message for clean scan', () => {
    const output = formatTable(createResult(0));
    expect(output).toContain('No security findings');
  });

  it('should include finding count', () => {
    const output = formatTable(createResult(3));
    expect(output).toContain('3 findings');
  });
});
