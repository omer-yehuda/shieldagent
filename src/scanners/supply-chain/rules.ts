import type { Rule } from '../../core/types.js';

export const SUPPLY_CHAIN_RULES: Rule[] = [
  {
    id: 'SC001',
    name: 'install-script-detected',
    description: 'Package has install/postinstall scripts that execute arbitrary code',
    severity: 'high',
    category: 'pattern',
    frameworks: [
      { framework: 'OWASP Agentic Top 10', id: 'AT-09', name: 'Supply Chain Compromise' },
      { framework: 'Adversa MCP Top 25', id: 'MCP-20', name: 'Malicious npm Package' },
    ],
  },
  {
    id: 'SC002',
    name: 'typosquatting-risk',
    description: 'Dependency name is suspiciously similar to a popular package',
    severity: 'high',
    category: 'pattern',
    frameworks: [
      { framework: 'Adversa MCP Top 25', id: 'MCP-21', name: 'Typosquatting Attack' },
    ],
  },
  {
    id: 'SC003',
    name: 'unpinned-dependency',
    description: 'Dependency version uses range that could pull in malicious updates',
    severity: 'medium',
    category: 'pattern',
  },
  {
    id: 'SC004',
    name: 'suspicious-dependency',
    description: 'Dependency name contains suspicious patterns',
    severity: 'medium',
    category: 'pattern',
  },
  {
    id: 'SC005',
    name: 'no-lockfile',
    description: 'No lockfile found, dependencies are not reproducible',
    severity: 'medium',
    category: 'pattern',
  },
];
