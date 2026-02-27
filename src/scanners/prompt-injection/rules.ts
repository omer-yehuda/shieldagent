import type { Rule } from '../../core/types.js';

export const PROMPT_INJECTION_RULES: Rule[] = [
  {
    id: 'PI001',
    name: 'injection-in-parameter-description',
    description: 'Parameter description contains prompt injection attempt',
    severity: 'critical',
    category: 'pattern',
    frameworks: [
      { framework: 'OWASP Agentic Top 10', id: 'AT-02', name: 'Prompt Injection' },
      { framework: 'Adversa MCP Top 25', id: 'MCP-04', name: 'Prompt Injection via Tool Description' },
    ],
  },
  {
    id: 'PI002',
    name: 'injection-in-default-value',
    description: 'Default parameter value contains injection payload',
    severity: 'high',
    category: 'pattern',
    frameworks: [
      { framework: 'OWASP Agentic Top 10', id: 'AT-02', name: 'Prompt Injection' },
    ],
  },
  {
    id: 'PI003',
    name: 'injection-in-enum-value',
    description: 'Enum value contains injection payload',
    severity: 'high',
    category: 'pattern',
  },
  {
    id: 'PI004',
    name: 'injection-in-error-message',
    description: 'Error message template contains injection patterns',
    severity: 'medium',
    category: 'pattern',
  },
];
