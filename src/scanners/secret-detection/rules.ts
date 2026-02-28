import type { Rule } from '../../core/types.js';

export const SECRET_DETECTION_RULES: Rule[] = [
  {
    id: 'SD001',
    name: 'hardcoded-api-key',
    description: 'Source code contains a hardcoded API key matching a known provider format',
    severity: 'critical',
    category: 'pattern',
    frameworks: [
      { framework: 'OWASP Agentic Top 10', id: 'AT-08', name: 'Credential Exposure' },
    ],
  },
  {
    id: 'SD002',
    name: 'hardcoded-generic-secret',
    description: 'Source code contains a hardcoded password, secret, token, or API key assignment',
    severity: 'high',
    category: 'pattern',
    frameworks: [
      { framework: 'OWASP Agentic Top 10', id: 'AT-08', name: 'Credential Exposure' },
    ],
  },
  {
    id: 'SD003',
    name: 'high-entropy-string',
    description: 'High-entropy string assigned to a secret-suggestive variable name',
    severity: 'medium',
    category: 'pattern',
    frameworks: [
      { framework: 'OWASP Agentic Top 10', id: 'AT-08', name: 'Credential Exposure' },
    ],
  },
  {
    id: 'SD004',
    name: 'secret-in-tool-definition',
    description: 'Secret or credential found in tool inputSchema defaults or description',
    severity: 'critical',
    category: 'pattern',
    frameworks: [
      { framework: 'OWASP Agentic Top 10', id: 'AT-08', name: 'Credential Exposure' },
      { framework: 'Adversa MCP Top 25', id: 'MCP-07', name: 'Credential Leakage in Tool Definitions' },
    ],
  },
];
