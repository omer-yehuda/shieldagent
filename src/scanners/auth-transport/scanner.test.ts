import { describe, it, expect } from 'vitest';
import { AuthTransportScanner } from './scanner.js';
import type { ScanTarget } from '../../core/types.js';

const createTarget = (content: string, path = '/test/index.ts'): ScanTarget => ({
  path: '/test',
  tools: [],
  sourceFiles: [{ path, content }],
});

describe('AuthTransportScanner', () => {
  const scanner = new AuthTransportScanner();

  it('should detect hardcoded API keys', async () => {
    const target = createTarget(`
      const API_KEY = "sk-1234567890abcdef1234567890abcdef";
    `);

    const findings = await scanner.scan(target);
    expect(findings.some((f) => f.ruleId === 'AT003')).toBe(true);
  });

  it('should detect hardcoded passwords', async () => {
    const target = createTarget(`
      const password = "supersecretpassword123";
    `);

    const findings = await scanner.scan(target);
    expect(findings.some((f) => f.ruleId === 'AT003')).toBe(true);
  });

  it('should not flag env variable references', async () => {
    const target = createTarget(`
      const apiKey = process.env.API_KEY;
    `);

    const findings = await scanner.scan(target);
    expect(findings.filter((f) => f.ruleId === 'AT003')).toHaveLength(0);
  });

  it('should detect insecure HTTP transport', async () => {
    const target = createTarget(`
      const endpoint = "http://api.production.com/data";
      const server = createServer();
      server.listen(3000);
    `);

    const findings = await scanner.scan(target);
    expect(findings.some((f) => f.ruleId === 'AT002')).toBe(true);
  });

  it('should allow localhost HTTP', async () => {
    const target = createTarget(`
      const endpoint = "http://localhost:3000/api";
    `);

    const findings = await scanner.scan(target);
    expect(findings.filter((f) => f.ruleId === 'AT002')).toHaveLength(0);
  });

  it('should detect missing authentication', async () => {
    const target = createTarget(`
      const app = express();
      app.get('/api/data', (req, res) => res.json({}));
    `);

    const findings = await scanner.scan(target);
    expect(findings.some((f) => f.ruleId === 'AT001')).toBe(true);
  });

  it('should not flag missing auth when auth middleware exists', async () => {
    const target = createTarget(`
      import { verifyToken } from './auth';
      const app = express();
      app.use(authenticate);
    `);

    const findings = await scanner.scan(target);
    expect(findings.filter((f) => f.ruleId === 'AT001')).toHaveLength(0);
  });
});
