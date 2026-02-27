import type { Rule } from '../../core/types.js';

export const OVER_PERMISSION_RULES: Rule[] = [
  {
    id: 'OP001',
    name: 'filesystem-write-access',
    description: 'Tool has filesystem write access without clear justification',
    severity: 'high',
    category: 'ast',
    frameworks: [
      { framework: 'OWASP Agentic Top 10', id: 'AT-04', name: 'Over-Permission' },
      { framework: 'Adversa MCP Top 25', id: 'MCP-10', name: 'Excessive Permissions' },
    ],
  },
  {
    id: 'OP002',
    name: 'network-access',
    description: 'Tool makes outbound network requests beyond its described purpose',
    severity: 'high',
    category: 'ast',
    frameworks: [
      { framework: 'OWASP Agentic Top 10', id: 'AT-04', name: 'Over-Permission' },
    ],
  },
  {
    id: 'OP003',
    name: 'process-execution',
    description: 'Tool can execute system processes/commands',
    severity: 'high',
    category: 'ast',
    frameworks: [
      { framework: 'Adversa MCP Top 25', id: 'MCP-10', name: 'Excessive Permissions' },
    ],
  },
  {
    id: 'OP004',
    name: 'environment-access',
    description: 'Tool accesses environment variables which may contain secrets',
    severity: 'medium',
    category: 'ast',
  },
  {
    id: 'OP005',
    name: 'database-access',
    description: 'Tool has direct database access capabilities',
    severity: 'medium',
    category: 'ast',
  },
];
