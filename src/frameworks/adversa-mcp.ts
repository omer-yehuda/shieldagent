import type { FrameworkItem } from './owasp-agentic.js';

export const ADVERSA_MCP_TOP_25: FrameworkItem[] = [
  {
    id: 'MCP-01',
    name: 'Tool Poisoning Attack',
    description: 'Hidden malicious instructions in tool descriptions',
    relatedRules: ['TP001'],
  },
  {
    id: 'MCP-02',
    name: 'Rug Pull via Tool Modification',
    description: 'Tools that change behavior after initial trust is established',
    relatedRules: ['TP003'],
  },
  {
    id: 'MCP-03',
    name: 'Tool Shadowing',
    description: 'Malicious tools that mimic trusted tool names',
    relatedRules: ['TP004'],
  },
  {
    id: 'MCP-04',
    name: 'Prompt Injection via Tool Description',
    description: 'Injection payloads in parameter metadata',
    relatedRules: ['PI001'],
  },
  {
    id: 'MCP-05',
    name: 'Command Injection via Tool Input',
    description: 'Unsanitized input in shell commands',
    relatedRules: ['CI001', 'CI003'],
  },
  {
    id: 'MCP-06',
    name: 'Data Exfiltration via Tool',
    description: 'Sensitive data accessed and sent externally',
    relatedRules: ['DE001', 'DE003'],
  },
  {
    id: 'MCP-08',
    name: 'Lack of Authentication',
    description: 'MCP server has no auth mechanism',
    relatedRules: ['AT001'],
  },
  {
    id: 'MCP-09',
    name: 'Insecure Transport',
    description: 'HTTP used instead of HTTPS',
    relatedRules: ['AT002'],
  },
  {
    id: 'MCP-10',
    name: 'Excessive Permissions',
    description: 'Tool capabilities exceed description',
    relatedRules: ['OP001', 'OP003'],
  },
  {
    id: 'MCP-14',
    name: 'Missing Input Validation',
    description: 'No schema or type checking on inputs',
    relatedRules: ['IV001'],
  },
  {
    id: 'MCP-20',
    name: 'Malicious npm Package',
    description: 'Dangerous install scripts in dependencies',
    relatedRules: ['SC001'],
  },
  {
    id: 'MCP-21',
    name: 'Typosquatting Attack',
    description: 'Dependencies with names similar to popular packages',
    relatedRules: ['SC002'],
  },
];
