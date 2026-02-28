import { BaseScanner } from '../base-scanner.js';
import type { Finding, Rule, ScanTarget } from '../../core/types.js';
import { SECRET_DETECTION_RULES } from './rules.js';

const API_KEY_PATTERNS: { name: string; pattern: RegExp }[] = [
  { name: 'OpenAI', pattern: /sk-proj-[A-Za-z0-9_-]{20,}/ },
  { name: 'OpenAI (legacy)', pattern: /sk-[A-Za-z0-9]{32,}/ },
  { name: 'Anthropic', pattern: /sk-ant-[A-Za-z0-9_-]{20,}/ },
  { name: 'GitHub PAT', pattern: /ghp_[A-Za-z0-9]{36}/ },
  { name: 'GitHub OAuth', pattern: /gho_[A-Za-z0-9]{36}/ },
  { name: 'GitHub App', pattern: /ghs_[A-Za-z0-9]{36}/ },
  { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/ },
  { name: 'Stripe Live', pattern: /sk_live_[A-Za-z0-9]{24,}/ },
  { name: 'Stripe Test', pattern: /sk_test_[A-Za-z0-9]{24,}/ },
  { name: 'Slack Bot', pattern: /xoxb-[0-9]{10,}-[A-Za-z0-9-]+/ },
  { name: 'Slack User', pattern: /xoxp-[0-9]{10,}-[A-Za-z0-9-]+/ },
  { name: 'Slack Webhook', pattern: /xoxs-[0-9]{10,}-[A-Za-z0-9-]+/ },
  { name: 'Twilio', pattern: /SK[0-9a-fA-F]{32}/ },
  { name: 'SendGrid', pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/ },
];

const GENERIC_SECRET_PATTERN =
  /(?:password|passwd|secret|token|api[_-]?key|apikey|auth[_-]?token|access[_-]?token)\s*[:=]\s*["'`]([^"'`]{8,})["'`]/i;

const SECRET_VAR_NAMES =
  /(?:secret|password|passwd|token|api[_-]?key|apikey|credential|auth[_-]?key|private[_-]?key|access[_-]?key)\s*[:=]\s*["'`]([^"'`]{20,})["'`]/i;

const ENTROPY_THRESHOLD = 4.5;
const MIN_ENTROPY_LENGTH = 20;

const calculateShannonEntropy = (str: string): number => {
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
};

const extractDefaults = (schema: Record<string, unknown>, path = ''): { path: string; value: string }[] => {
  const results: { path: string; value: string }[] = [];

  if (typeof schema['default'] === 'string') {
    results.push({ path: path || 'default', value: schema['default'] });
  }

  const properties = schema['properties'] as Record<string, Record<string, unknown>> | undefined;
  if (properties && typeof properties === 'object') {
    for (const [key, prop] of Object.entries(properties)) {
      if (prop && typeof prop === 'object') {
        results.push(...extractDefaults(prop, path ? `${path}.${key}` : key));
      }
    }
  }

  return results;
};

export class SecretDetectionScanner extends BaseScanner {
  readonly id = 'secret-detection';
  readonly name = 'Secret Detection Scanner';
  readonly category = 'pattern' as const;
  readonly rules: Rule[] = SECRET_DETECTION_RULES;

  async scan(target: ScanTarget): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const tool of target.tools) {
      findings.push(...this.checkToolDefinition(tool, target.path));
    }

    for (const file of target.sourceFiles) {
      findings.push(...this.checkSourceFile(file.path, file.content));
    }

    return findings;
  }

  private checkToolDefinition(
    tool: ScanTarget['tools'][number],
    targetPath: string,
  ): Finding[] {
    const findings: Finding[] = [];
    const rule = this.getRule('SD004')!;
    const textsToCheck: string[] = [];

    if (tool.inputSchema) {
      for (const { path, value } of extractDefaults(tool.inputSchema)) {
        textsToCheck.push(value);
        if (this.looksLikeSecret(value)) {
          findings.push(
            this.createFinding(
              rule,
              `Tool "${tool.name}" has a secret in inputSchema default at "${path}"`,
              { file: targetPath, toolName: tool.name },
            ),
          );
        }
      }
    }

    const desc = tool.description ?? '';
    for (const { name, pattern } of API_KEY_PATTERNS) {
      if (pattern.test(desc)) {
        findings.push(
          this.createFinding(
            rule,
            `Tool "${tool.name}" description contains a ${name} API key`,
            { file: targetPath, toolName: tool.name },
          ),
        );
      }
    }

    return findings;
  }

  private checkSourceFile(filePath: string, content: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      findings.push(...this.checkApiKeys(line, filePath, lineNum));
      findings.push(...this.checkGenericSecrets(line, filePath, lineNum));
      findings.push(...this.checkHighEntropy(line, filePath, lineNum));
    }

    return findings;
  }

  private checkApiKeys(line: string, filePath: string, lineNum: number): Finding[] {
    const rule = this.getRule('SD001')!;
    const findings: Finding[] = [];

    for (const { name, pattern } of API_KEY_PATTERNS) {
      if (pattern.test(line)) {
        findings.push(
          this.createFinding(
            rule,
            `${name} API key detected in source code`,
            { file: filePath, line: lineNum },
          ),
        );
      }
    }

    return findings;
  }

  private checkGenericSecrets(line: string, filePath: string, lineNum: number): Finding[] {
    const match = GENERIC_SECRET_PATTERN.exec(line);
    if (!match) return [];

    const value = match[1];
    if (this.isPlaceholder(value)) return [];

    const rule = this.getRule('SD002')!;
    return [
      this.createFinding(
        rule,
        `Hardcoded credential assignment detected`,
        { file: filePath, line: lineNum },
      ),
    ];
  }

  private checkHighEntropy(line: string, filePath: string, lineNum: number): Finding[] {
    const match = SECRET_VAR_NAMES.exec(line);
    if (!match) return [];

    const value = match[1];
    if (value.length < MIN_ENTROPY_LENGTH || this.isPlaceholder(value)) return [];

    const entropy = calculateShannonEntropy(value);
    if (entropy <= ENTROPY_THRESHOLD) return [];

    const rule = this.getRule('SD003')!;
    return [
      this.createFinding(
        rule,
        `High-entropy string (entropy: ${entropy.toFixed(2)}) assigned to secret variable`,
        { file: filePath, line: lineNum },
      ),
    ];
  }

  private looksLikeSecret(value: string): boolean {
    for (const { pattern } of API_KEY_PATTERNS) {
      if (pattern.test(value)) return true;
    }
    if (GENERIC_SECRET_PATTERN.test(`secret="${value}"`)) {
      if (!this.isPlaceholder(value)) return true;
    }
    if (value.length >= MIN_ENTROPY_LENGTH && calculateShannonEntropy(value) > ENTROPY_THRESHOLD) {
      return true;
    }
    return false;
  }

  private isPlaceholder(value: string): boolean {
    const lower = value.toLowerCase();
    return (
      lower.includes('xxx') ||
      lower.includes('your_') ||
      lower.includes('your-') ||
      lower.includes('replace') ||
      lower.includes('changeme') ||
      lower.includes('example') ||
      lower.includes('placeholder') ||
      lower.includes('todo') ||
      lower === 'password' ||
      lower === 'secret' ||
      /^\*+$/.test(value) ||
      /^\.{3,}$/.test(value)
    );
  }
}
