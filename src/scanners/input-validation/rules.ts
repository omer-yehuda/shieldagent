import type { Rule } from '../../core/types.js';

export const INPUT_VALIDATION_RULES: Rule[] = [
  {
    id: 'IV001',
    name: 'missing-input-schema',
    description: 'Tool has no input schema defined, allowing arbitrary input',
    severity: 'high',
    category: 'schema',
    frameworks: [
      { framework: 'OWASP Agentic Top 10', id: 'AT-06', name: 'Improper Input Validation' },
      { framework: 'Adversa MCP Top 25', id: 'MCP-14', name: 'Missing Input Validation' },
    ],
  },
  {
    id: 'IV002',
    name: 'missing-type-constraint',
    description: 'Parameter lacks type constraint, allowing type confusion attacks',
    severity: 'medium',
    category: 'schema',
    frameworks: [
      { framework: 'OWASP Agentic Top 10', id: 'AT-06', name: 'Improper Input Validation' },
    ],
  },
  {
    id: 'IV003',
    name: 'missing-required-field',
    description: 'Schema has no required fields specified, all parameters are optional',
    severity: 'medium',
    category: 'schema',
  },
  {
    id: 'IV004',
    name: 'missing-string-bounds',
    description: 'String parameter has no maxLength constraint, allowing oversized input',
    severity: 'low',
    category: 'schema',
  },
  {
    id: 'IV005',
    name: 'missing-number-bounds',
    description: 'Number parameter has no min/max constraints',
    severity: 'low',
    category: 'schema',
  },
  {
    id: 'IV006',
    name: 'missing-parameter-description',
    description: 'Parameter has no description, making security review harder',
    severity: 'info',
    category: 'schema',
  },
];
