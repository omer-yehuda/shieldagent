export interface FrameworkItem {
  id: string;
  name: string;
  description: string;
  relatedRules: string[];
}

export const OWASP_AGENTIC_TOP_10: FrameworkItem[] = [
  {
    id: 'AT-01',
    name: 'Tool Poisoning',
    description: 'Malicious tool descriptions that manipulate AI agent behavior',
    relatedRules: ['TP001', 'TP002', 'TP003', 'TP004', 'TP005'],
  },
  {
    id: 'AT-02',
    name: 'Prompt Injection',
    description: 'Injection of malicious instructions via tool metadata or parameters',
    relatedRules: ['PI001', 'PI002', 'PI003', 'PI004'],
  },
  {
    id: 'AT-03',
    name: 'Command Injection',
    description: 'Unsanitized input passed to system commands via tool implementations',
    relatedRules: ['CI001', 'CI002', 'CI003', 'CI004', 'CI005'],
  },
  {
    id: 'AT-04',
    name: 'Over-Permission',
    description: 'Tools with excessive capabilities beyond their stated purpose',
    relatedRules: ['OP001', 'OP002', 'OP003', 'OP004', 'OP005'],
  },
  {
    id: 'AT-05',
    name: 'Data Exfiltration',
    description: 'Tools that read sensitive data and transmit it externally',
    relatedRules: ['DE001', 'DE002', 'DE003', 'DE004', 'DE005'],
  },
  {
    id: 'AT-06',
    name: 'Improper Input Validation',
    description: 'Missing or inadequate validation of tool input parameters',
    relatedRules: ['IV001', 'IV002', 'IV003', 'IV004', 'IV005', 'IV006'],
  },
  {
    id: 'AT-07',
    name: 'Missing Authentication',
    description: 'MCP server endpoints without authentication mechanisms',
    relatedRules: ['AT001'],
  },
  {
    id: 'AT-08',
    name: 'Credential Exposure',
    description: 'Hardcoded secrets, tokens, or credentials in source code',
    relatedRules: ['AT003'],
  },
  {
    id: 'AT-09',
    name: 'Supply Chain Compromise',
    description: 'Malicious dependencies, typosquatting, or install script attacks',
    relatedRules: ['SC001', 'SC002', 'SC003', 'SC004', 'SC005'],
  },
  {
    id: 'AT-10',
    name: 'Insecure Transport',
    description: 'Unencrypted communication channels for tool data',
    relatedRules: ['AT002', 'AT004'],
  },
];
