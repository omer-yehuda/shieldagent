import { describe, it, expect } from 'vitest';
import { SecretDetectionScanner } from './scanner.js';
import type { ScanTarget } from '../../core/types.js';

const createTarget = (
  tools: ScanTarget['tools'] = [],
  sourceFiles: ScanTarget['sourceFiles'] = [],
): ScanTarget => ({
  path: '/test',
  tools,
  sourceFiles,
});

describe('SecretDetectionScanner', () => {
  const scanner = new SecretDetectionScanner();

  describe('SD001 - hardcoded-api-key', () => {
    it('should detect OpenAI API key', async () => {
      const target = createTarget([], [
        { path: 'config.ts', content: 'const key = "sk-proj-abc123def456ghi789jkl012mno345";' },
      ]);
      const findings = await scanner.scan(target);
      expect(findings.some((f) => f.ruleId === 'SD001')).toBe(true);
      expect(findings.some((f) => f.message.includes('OpenAI'))).toBe(true);
    });

    it('should detect Anthropic API key', async () => {
      const target = createTarget([], [
        { path: 'config.ts', content: 'const key = "sk-ant-api03-abc123def456ghi789jkl012mno345pqr678";' },
      ]);
      const findings = await scanner.scan(target);
      expect(findings.some((f) => f.ruleId === 'SD001')).toBe(true);
      expect(findings.some((f) => f.message.includes('Anthropic'))).toBe(true);
    });

    it('should detect GitHub PAT', async () => {
      const target = createTarget([], [
        { path: 'config.ts', content: 'const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";' },
      ]);
      const findings = await scanner.scan(target);
      expect(findings.some((f) => f.ruleId === 'SD001')).toBe(true);
      expect(findings.some((f) => f.message.includes('GitHub PAT'))).toBe(true);
    });

    it('should detect AWS access key', async () => {
      const target = createTarget([], [
        { path: 'config.ts', content: 'const key = "AKIAIOSFODNN7EXAMPLE";' },
      ]);
      const findings = await scanner.scan(target);
      expect(findings.some((f) => f.ruleId === 'SD001')).toBe(true);
      expect(findings.some((f) => f.message.includes('AWS'))).toBe(true);
    });

    it('should detect Stripe key', async () => {
      // Build key at runtime to avoid GitHub push protection false positive
      const prefix = ['sk', 'live'].join('_') + '_';
      const target = createTarget([], [
        { path: 'billing.ts', content: `const stripe = "${prefix}abcdefghijklmnopqrstuvwx";` },
      ]);
      const findings = await scanner.scan(target);
      expect(findings.some((f) => f.ruleId === 'SD001')).toBe(true);
      expect(findings.some((f) => f.message.includes('Stripe'))).toBe(true);
    });

    it('should detect Slack bot token', async () => {
      const target = createTarget([], [
        { path: 'slack.ts', content: 'const token = "xoxb-1234567890-abcdefghij";' },
      ]);
      const findings = await scanner.scan(target);
      expect(findings.some((f) => f.ruleId === 'SD001')).toBe(true);
      expect(findings.some((f) => f.message.includes('Slack'))).toBe(true);
    });
  });

  describe('SD002 - hardcoded-generic-secret', () => {
    it('should detect password assignment', async () => {
      const target = createTarget([], [
        { path: 'db.ts', content: 'const password = "SuperSecr3t!Pass";' },
      ]);
      const findings = await scanner.scan(target);
      expect(findings.some((f) => f.ruleId === 'SD002')).toBe(true);
    });

    it('should detect secret assignment', async () => {
      const target = createTarget([], [
        { path: 'auth.ts', content: "const secret = 'my-jwt-secret-value';" },
      ]);
      const findings = await scanner.scan(target);
      expect(findings.some((f) => f.ruleId === 'SD002')).toBe(true);
    });

    it('should detect api_key assignment', async () => {
      const target = createTarget([], [
        { path: 'api.ts', content: 'const api_key = "real-api-key-value-here";' },
      ]);
      const findings = await scanner.scan(target);
      expect(findings.some((f) => f.ruleId === 'SD002')).toBe(true);
    });

    it('should not flag placeholder values', async () => {
      const target = createTarget([], [
        { path: 'config.ts', content: 'const password = "your_password_here";' },
      ]);
      const findings = await scanner.scan(target);
      expect(findings.filter((f) => f.ruleId === 'SD002')).toHaveLength(0);
    });

    it('should not flag "changeme" values', async () => {
      const target = createTarget([], [
        { path: 'config.ts', content: 'const password = "changeme-password";' },
      ]);
      const findings = await scanner.scan(target);
      expect(findings.filter((f) => f.ruleId === 'SD002')).toHaveLength(0);
    });
  });

  describe('SD003 - high-entropy-string', () => {
    it('should detect high-entropy secret variable', async () => {
      const target = createTarget([], [
        { path: 'config.ts', content: 'const secret = "aB3$kL9m!xQ2wR7nP4vZjY8hG5tU1eD6";' },
      ]);
      const findings = await scanner.scan(target);
      expect(findings.some((f) => f.ruleId === 'SD003')).toBe(true);
    });

    it('should not flag low-entropy strings', async () => {
      const target = createTarget([], [
        { path: 'config.ts', content: 'const secret = "aaaaaaaaaaaabbbbbbbbbb";' },
      ]);
      const findings = await scanner.scan(target);
      expect(findings.filter((f) => f.ruleId === 'SD003')).toHaveLength(0);
    });

    it('should not flag short strings', async () => {
      const target = createTarget([], [
        { path: 'config.ts', content: 'const secret = "short";' },
      ]);
      const findings = await scanner.scan(target);
      expect(findings.filter((f) => f.ruleId === 'SD003')).toHaveLength(0);
    });
  });

  describe('SD004 - secret-in-tool-definition', () => {
    it('should detect API key in inputSchema default', async () => {
      const target = createTarget([
        {
          name: 'query_api',
          description: 'Queries an API',
          inputSchema: {
            type: 'object',
            properties: {
              apiKey: {
                type: 'string',
                default: 'sk-proj-abc123def456ghi789jkl012mno345',
              },
            },
          },
        },
      ]);
      const findings = await scanner.scan(target);
      expect(findings.some((f) => f.ruleId === 'SD004')).toBe(true);
      expect(findings.some((f) => f.message.includes('inputSchema default'))).toBe(true);
    });

    it('should detect API key in tool description', async () => {
      const target = createTarget([
        {
          name: 'slack_post',
          description: 'Posts to Slack. Use token xoxb-1234567890-abcdefghij for auth.',
        },
      ]);
      const findings = await scanner.scan(target);
      expect(findings.some((f) => f.ruleId === 'SD004')).toBe(true);
      expect(findings.some((f) => f.message.includes('description'))).toBe(true);
    });

    it('should not flag tools without secrets', async () => {
      const target = createTarget([
        {
          name: 'get_weather',
          description: 'Returns weather data for a city',
          inputSchema: {
            type: 'object',
            properties: {
              city: { type: 'string', default: 'London' },
            },
          },
        },
      ]);
      const findings = await scanner.scan(target);
      expect(findings.filter((f) => f.ruleId === 'SD004')).toHaveLength(0);
    });
  });

  describe('clean targets', () => {
    it('should return no findings for clean source files', async () => {
      const target = createTarget(
        [
          {
            name: 'calculator',
            description: 'Performs basic math operations',
            inputSchema: {
              type: 'object',
              properties: {
                operation: { type: 'string', default: 'add' },
                a: { type: 'number' },
                b: { type: 'number' },
              },
            },
          },
        ],
        [
          {
            path: 'index.ts',
            content: [
              'import { createServer } from "http";',
              'const port = process.env.PORT ?? 3000;',
              'const apiKey = process.env.API_KEY;',
              'console.log("Server started");',
            ].join('\n'),
          },
        ],
      );
      const findings = await scanner.scan(target);
      expect(findings).toHaveLength(0);
    });

    it('should have correct metadata', () => {
      expect(scanner.id).toBe('secret-detection');
      expect(scanner.name).toBe('Secret Detection Scanner');
      expect(scanner.category).toBe('pattern');
      expect(scanner.rules).toHaveLength(4);
    });
  });
});
