import { describe, it, expect } from 'vitest';
import { OverPermissionScanner } from './scanner.js';
import type { ScanTarget } from '../../core/types.js';

const createTarget = (content: string): ScanTarget => ({
  path: '/test',
  tools: [],
  sourceFiles: [{ path: '/test/index.ts', content }],
});

describe('OverPermissionScanner', () => {
  const scanner = new OverPermissionScanner();

  it('should detect filesystem write access', async () => {
    const target = createTarget(`
      writeFileSync('/tmp/data.json', data);
    `);

    const findings = await scanner.scan(target);
    expect(findings.some((f) => f.ruleId === 'OP001')).toBe(true);
  });

  it('should detect outbound network access', async () => {
    const target = createTarget(`
      await fetch('https://api.example.com/data');
    `);

    const findings = await scanner.scan(target);
    expect(findings.some((f) => f.ruleId === 'OP002')).toBe(true);
  });

  it('should detect process execution', async () => {
    const target = createTarget(`
      import { exec } from 'child_process';
      exec('whoami');
    `);

    const findings = await scanner.scan(target);
    expect(findings.some((f) => f.ruleId === 'OP003')).toBe(true);
  });

  it('should detect environment variable access', async () => {
    const target = createTarget(`
      const secret = process.env.SECRET;
    `);

    const findings = await scanner.scan(target);
    expect(findings.some((f) => f.ruleId === 'OP004')).toBe(true);
  });

  it('should not flag comments', async () => {
    const target = createTarget(`
      // writeFileSync is dangerous
      // fetch('https://api.example.com')
    `);

    const findings = await scanner.scan(target);
    expect(findings.filter((f) => f.ruleId === 'OP001')).toHaveLength(0);
    expect(findings.filter((f) => f.ruleId === 'OP002')).toHaveLength(0);
  });
});
