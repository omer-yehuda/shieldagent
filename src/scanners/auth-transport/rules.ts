import type { Rule } from '../../core/types.js';

export const AUTH_TRANSPORT_RULES: Rule[] = [
  {
    id: 'AT001',
    name: 'missing-authentication',
    description: 'MCP server has no authentication mechanism configured',
    severity: 'high',
    category: 'pattern',
    frameworks: [
      { framework: 'OWASP Agentic Top 10', id: 'AT-07', name: 'Missing Authentication' },
      { framework: 'Adversa MCP Top 25', id: 'MCP-08', name: 'Lack of Authentication' },
    ],
  },
  {
    id: 'AT002',
    name: 'insecure-transport',
    description: 'Server uses HTTP instead of HTTPS for transport',
    severity: 'high',
    category: 'pattern',
    frameworks: [
      { framework: 'Adversa MCP Top 25', id: 'MCP-09', name: 'Insecure Transport' },
    ],
  },
  {
    id: 'AT003',
    name: 'hardcoded-credentials',
    description: 'Source code contains hardcoded API keys, passwords, or tokens',
    severity: 'critical',
    category: 'pattern',
    frameworks: [
      { framework: 'OWASP Agentic Top 10', id: 'AT-08', name: 'Credential Exposure' },
    ],
  },
  {
    id: 'AT004',
    name: 'missing-cors-config',
    description: 'HTTP transport has no CORS restrictions configured',
    severity: 'medium',
    category: 'pattern',
  },
  {
    id: 'AT005',
    name: 'missing-rate-limiting',
    description: 'No rate limiting detected on server endpoints',
    severity: 'medium',
    category: 'pattern',
  },
];
