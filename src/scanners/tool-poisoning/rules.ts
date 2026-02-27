import type { Rule } from '../../core/types.js';

export const TOOL_POISONING_RULES: Rule[] = [
  {
    id: 'TP001',
    name: 'hidden-instruction-in-description',
    description: 'Tool description contains hidden instructions that could manipulate AI agent behavior',
    severity: 'critical',
    category: 'pattern',
    frameworks: [
      { framework: 'OWASP Agentic Top 10', id: 'AT-01', name: 'Tool Poisoning' },
      { framework: 'Adversa MCP Top 25', id: 'MCP-01', name: 'Tool Poisoning Attack' },
    ],
  },
  {
    id: 'TP002',
    name: 'privilege-escalation-instruction',
    description: 'Tool description contains instructions to escalate privileges or override safety',
    severity: 'critical',
    category: 'pattern',
    frameworks: [
      { framework: 'OWASP Agentic Top 10', id: 'AT-01', name: 'Tool Poisoning' },
    ],
  },
  {
    id: 'TP003',
    name: 'data-exfil-instruction',
    description: 'Tool description instructs agent to send data to external endpoints',
    severity: 'critical',
    category: 'pattern',
    frameworks: [
      { framework: 'Adversa MCP Top 25', id: 'MCP-02', name: 'Rug Pull via Tool Modification' },
    ],
  },
  {
    id: 'TP004',
    name: 'tool-shadowing',
    description: 'Tool name mimics a common/trusted tool to intercept calls',
    severity: 'high',
    category: 'pattern',
    frameworks: [
      { framework: 'Adversa MCP Top 25', id: 'MCP-03', name: 'Tool Shadowing' },
    ],
  },
  {
    id: 'TP005',
    name: 'cross-tool-manipulation',
    description: 'Tool description references or instructs about other tools',
    severity: 'high',
    category: 'pattern',
  },
];
