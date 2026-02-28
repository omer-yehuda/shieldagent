import type { ShieldAgentConfig } from '../core/types.js';

export const DEFAULT_CONFIG: ShieldAgentConfig = {
  scanners: {
    'input-validation': { enabled: true },
    'tool-poisoning': { enabled: true },
    'prompt-injection': { enabled: true },
    'auth-transport': { enabled: true },
    'supply-chain': { enabled: true },
    'command-injection': { enabled: true },
    'over-permission': { enabled: true },
    'data-exfiltration': { enabled: true },
  },
  exclude: ['node_modules/**', 'dist/**', '.git/**', 'tests/fixtures/**', '**/*.test.ts', '**/*.spec.ts'],
  format: 'table',
  ci: false,
};
