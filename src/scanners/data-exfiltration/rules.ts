import type { Rule } from '../../core/types.js';

export const DATA_EXFILTRATION_RULES: Rule[] = [
  {
    id: 'DE001',
    name: 'sensitive-data-read-with-network',
    description: 'Code reads sensitive data and has outbound network access in same scope',
    severity: 'critical',
    category: 'ast',
    frameworks: [
      { framework: 'OWASP Agentic Top 10', id: 'AT-05', name: 'Data Exfiltration' },
      { framework: 'Adversa MCP Top 25', id: 'MCP-06', name: 'Data Exfiltration via Tool' },
    ],
  },
  {
    id: 'DE002',
    name: 'env-secret-access',
    description: 'Code accesses environment variables containing secrets/keys/tokens',
    severity: 'high',
    category: 'ast',
    frameworks: [
      { framework: 'OWASP Agentic Top 10', id: 'AT-05', name: 'Data Exfiltration' },
    ],
  },
  {
    id: 'DE003',
    name: 'sensitive-file-read',
    description: 'Code reads files that commonly contain secrets or sensitive data',
    severity: 'high',
    category: 'ast',
    frameworks: [
      { framework: 'Adversa MCP Top 25', id: 'MCP-06', name: 'Data Exfiltration via Tool' },
    ],
  },
  {
    id: 'DE004',
    name: 'base64-encoding-of-data',
    description: 'Data is base64 encoded before network transmission (obfuscation)',
    severity: 'medium',
    category: 'ast',
  },
  {
    id: 'DE005',
    name: 'dns-exfiltration-pattern',
    description: 'Data encoded in DNS queries for exfiltration',
    severity: 'high',
    category: 'ast',
  },
];
