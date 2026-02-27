import { describe, it, expect } from 'vitest';
import { InputValidationScanner } from './scanner.js';
import type { ScanTarget } from '../../core/types.js';

const createTarget = (tools: ScanTarget['tools']): ScanTarget => ({
  path: '/test',
  tools,
  sourceFiles: [],
});

describe('InputValidationScanner', () => {
  const scanner = new InputValidationScanner();

  it('should detect missing input schema', async () => {
    const target = createTarget([
      { name: 'no_schema_tool', description: 'A tool without schema' },
    ]);

    const findings = await scanner.scan(target);
    expect(findings.some((f) => f.ruleId === 'IV001')).toBe(true);
  });

  it('should detect missing required fields', async () => {
    const target = createTarget([
      {
        name: 'no_required',
        description: 'Tool',
        inputSchema: {
          type: 'object',
          properties: { name: { type: 'string', description: 'Name' } },
        },
      },
    ]);

    const findings = await scanner.scan(target);
    expect(findings.some((f) => f.ruleId === 'IV003')).toBe(true);
  });

  it('should detect missing type constraint', async () => {
    const target = createTarget([
      {
        name: 'no_type',
        description: 'Tool',
        inputSchema: {
          type: 'object',
          properties: { data: {} },
          required: ['data'],
        },
      },
    ]);

    const findings = await scanner.scan(target);
    expect(findings.some((f) => f.ruleId === 'IV002')).toBe(true);
  });

  it('should detect missing string bounds', async () => {
    const target = createTarget([
      {
        name: 'no_bounds',
        description: 'Tool',
        inputSchema: {
          type: 'object',
          properties: { name: { type: 'string', description: 'Name' } },
          required: ['name'],
        },
      },
    ]);

    const findings = await scanner.scan(target);
    expect(findings.some((f) => f.ruleId === 'IV004')).toBe(true);
  });

  it('should detect missing number bounds', async () => {
    const target = createTarget([
      {
        name: 'no_num_bounds',
        description: 'Tool',
        inputSchema: {
          type: 'object',
          properties: { count: { type: 'number', description: 'Count' } },
          required: ['count'],
        },
      },
    ]);

    const findings = await scanner.scan(target);
    expect(findings.some((f) => f.ruleId === 'IV005')).toBe(true);
  });

  it('should detect missing parameter description', async () => {
    const target = createTarget([
      {
        name: 'no_desc',
        description: 'Tool',
        inputSchema: {
          type: 'object',
          properties: { name: { type: 'string', maxLength: 100 } },
          required: ['name'],
        },
      },
    ]);

    const findings = await scanner.scan(target);
    expect(findings.some((f) => f.ruleId === 'IV006')).toBe(true);
  });

  it('should pass for well-defined schema', async () => {
    const target = createTarget([
      {
        name: 'good_tool',
        description: 'A well-defined tool',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'The name',
              maxLength: 100,
            },
          },
          required: ['name'],
        },
      },
    ]);

    const findings = await scanner.scan(target);
    expect(findings).toHaveLength(0);
  });
});
