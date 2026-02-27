import { describe, it, expect } from 'vitest';
import { CommandInjectionScanner } from './scanner.js';
import type { ScanTarget } from '../../core/types.js';

const createTarget = (content: string): ScanTarget => ({
  path: '/test',
  tools: [],
  sourceFiles: [{ path: '/test/index.ts', content }],
});

describe('CommandInjectionScanner', () => {
  const scanner = new CommandInjectionScanner();

  it('should detect eval usage', async () => {
    const target = createTarget(`
      const result = eval(userInput);
    `);

    const findings = await scanner.scan(target);
    expect(findings.some((f) => f.ruleId === 'CI002')).toBe(true);
  });

  it('should detect new Function constructor', async () => {
    const target = createTarget(`
      const fn = new Function(code);
    `);

    const findings = await scanner.scan(target);
    expect(findings.some((f) => f.ruleId === 'CI002')).toBe(true);
  });

  it('should detect template literal in exec', async () => {
    const target = createTarget(`
      import { exec } from 'child_process';
      exec(\`ls -la \${userInput}\`);
    `);

    const findings = await scanner.scan(target);
    expect(findings.some((f) => f.ruleId === 'CI004')).toBe(true);
  });

  it('should detect string concat in exec', async () => {
    const target = createTarget(`
      import { exec } from 'child_process';
      exec("echo " + userInput);
    `);

    const findings = await scanner.scan(target);
    expect(findings.some((f) => f.ruleId === 'CI005')).toBe(true);
  });

  it('should not flag static string exec', async () => {
    const target = createTarget(`
      console.log("hello world");
    `);

    const findings = await scanner.scan(target);
    expect(findings.filter((f) => f.ruleId.startsWith('CI'))).toHaveLength(0);
  });
});
