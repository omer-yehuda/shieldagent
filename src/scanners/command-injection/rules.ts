import type { Rule } from '../../core/types.js';

export const COMMAND_INJECTION_RULES: Rule[] = [
  {
    id: 'CI001',
    name: 'exec-with-unsanitized-input',
    description: 'exec/execSync called with string that includes unsanitized input',
    severity: 'critical',
    category: 'ast',
    frameworks: [
      { framework: 'OWASP Agentic Top 10', id: 'AT-03', name: 'Command Injection' },
      { framework: 'Adversa MCP Top 25', id: 'MCP-05', name: 'Command Injection via Tool Input' },
    ],
  },
  {
    id: 'CI002',
    name: 'eval-usage',
    description: 'eval() or Function() constructor used, enabling arbitrary code execution',
    severity: 'critical',
    category: 'ast',
    frameworks: [
      { framework: 'OWASP Agentic Top 10', id: 'AT-03', name: 'Command Injection' },
    ],
  },
  {
    id: 'CI003',
    name: 'spawn-shell-option',
    description: 'spawn/spawnSync used with shell: true, enabling shell injection',
    severity: 'high',
    category: 'ast',
    frameworks: [
      { framework: 'Adversa MCP Top 25', id: 'MCP-05', name: 'Command Injection via Tool Input' },
    ],
  },
  {
    id: 'CI004',
    name: 'template-literal-in-exec',
    description: 'Template literal with variables used in shell command',
    severity: 'high',
    category: 'ast',
  },
  {
    id: 'CI005',
    name: 'string-concat-in-exec',
    description: 'String concatenation used to build shell command',
    severity: 'high',
    category: 'ast',
  },
];
