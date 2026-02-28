import { BaseScanner } from '../base-scanner.js';
import type { Finding, Rule, ScanTarget } from '../../core/types.js';
import { PROMPT_INJECTION_RULES } from './rules.js';

const INJECTION_PATTERNS = [
  /(?:ignore|forget|disregard)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|rules?|context)/i,
  /(?:you are|you're)\s+(?:now|actually)\s+(?:a|an)\s+/i,
  /(?:new|updated|revised)\s+(?:instructions?|system\s+prompt|rules?)\s*:/i,
  /(?:IMPORTANT|CRITICAL|URGENT)\s*:\s*(?:ignore|override|disregard)/i,
  /(?:role|persona|character)\s*:\s*["']/i,
  /```(?:system|instruction|prompt)/i,
  /\[\[(?:SYSTEM|ADMIN|ROOT)\]\]/i,
  /(?:jailbreak|DAN|do anything now)/i,
  /(?:pretend|imagine|act as if)\s+(?:you|there)\s+(?:are|is|have)/i,
];

const ERROR_INJECTION_PATTERNS = [
  /(?:if\s+(?:error|fail|invalid))\s*[,:]?\s*(?:tell|say|respond|output)/i,
  /(?:error|exception|failure)\s+message\s*[:=]\s*["'`].*(?:ignore|override|system)/i,
];

export class PromptInjectionScanner extends BaseScanner {
  readonly id = 'prompt-injection';
  readonly name = 'Prompt Injection Scanner';
  readonly category = 'pattern' as const;
  readonly rules: Rule[] = PROMPT_INJECTION_RULES;

  async scan(target: ScanTarget): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const tool of target.tools) {
      findings.push(...this.checkParameterDescriptions(tool, target.path));
      findings.push(...this.checkDefaultValues(tool, target.path));
      findings.push(...this.checkEnumValues(tool, target.path));
    }

    for (const file of target.sourceFiles) {
      findings.push(...this.checkErrorMessages(file.content, file.path));
    }

    return findings;
  }

  private checkParameterDescriptions(
    tool: { name: string; inputSchema?: Record<string, unknown> },
    path: string,
  ): Finding[] {
    const findings: Finding[] = [];
    const properties = tool.inputSchema?.['properties'] as Record<string, Record<string, unknown>> | undefined;
    if (!properties) return findings;

    const rule = this.getRule('PI001');

    for (const [paramName, schema] of Object.entries(properties)) {
      const desc = schema['description'] as string | undefined;
      if (!desc) continue;

      for (const pattern of INJECTION_PATTERNS) {
        if (pattern.test(desc)) {
          findings.push(
            this.createFinding(
              rule,
              `Parameter "${paramName}" in tool "${tool.name}" contains injection: "${desc.match(pattern)?.[0]}"`,
              { file: path, toolName: tool.name },
            ),
          );
          break;
        }
      }
    }

    return findings;
  }

  private checkDefaultValues(
    tool: { name: string; inputSchema?: Record<string, unknown> },
    path: string,
  ): Finding[] {
    const findings: Finding[] = [];
    const properties = tool.inputSchema?.['properties'] as Record<string, Record<string, unknown>> | undefined;
    if (!properties) return findings;

    const rule = this.getRule('PI002');

    for (const [paramName, schema] of Object.entries(properties)) {
      const defaultVal = schema['default'];
      if (typeof defaultVal !== 'string') continue;

      for (const pattern of INJECTION_PATTERNS) {
        if (pattern.test(defaultVal)) {
          findings.push(
            this.createFinding(
              rule,
              `Default value of "${paramName}" in tool "${tool.name}" contains injection payload`,
              { file: path, toolName: tool.name },
            ),
          );
          break;
        }
      }
    }

    return findings;
  }

  private checkEnumValues(
    tool: { name: string; inputSchema?: Record<string, unknown> },
    path: string,
  ): Finding[] {
    const findings: Finding[] = [];
    const properties = tool.inputSchema?.['properties'] as Record<string, Record<string, unknown>> | undefined;
    if (!properties) return findings;

    const rule = this.getRule('PI003');

    for (const [paramName, schema] of Object.entries(properties)) {
      const enumValues = schema['enum'] as unknown[] | undefined;
      if (!enumValues) continue;

      for (const val of enumValues) {
        if (typeof val !== 'string') continue;
        for (const pattern of INJECTION_PATTERNS) {
          if (pattern.test(val)) {
            findings.push(
              this.createFinding(
                rule,
                `Enum value in "${paramName}" of tool "${tool.name}" contains injection`,
                { file: path, toolName: tool.name },
              ),
            );
            break;
          }
        }
      }
    }

    return findings;
  }

  private checkErrorMessages(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const rule = this.getRule('PI004');
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      for (const pattern of ERROR_INJECTION_PATTERNS) {
        if (pattern.test(lines[i]!)) {
          findings.push(
            this.createFinding(
              rule,
              `Error message template contains injection pattern`,
              { file: filePath, line: i + 1 },
            ),
          );
        }
      }
    }

    return findings;
  }
}
