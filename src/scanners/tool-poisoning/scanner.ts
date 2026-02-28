import { BaseScanner } from '../base-scanner.js';
import type { Finding, Rule, ScanTarget } from '../../core/types.js';
import { TOOL_POISONING_RULES } from './rules.js';

const HIDDEN_INSTRUCTION_PATTERNS = [
  /(?:you must|you should|always|never|ignore previous|disregard|override|bypass)\s/i,
  /(?:do not|don'?t)\s+(?:tell|inform|show|reveal|mention)/i,
  /(?:secretly|silently|quietly|without\s+(?:telling|informing|notifying))/i,
  /(?:before|after|instead)\s+(?:calling|using|executing|running)\s+(?:this|the)\s+tool/i,
  /(?:system prompt|system message|instructions?)\s*:/i,
  /<\/?(?:system|instruction|hidden|secret|internal)>/i,
  /\[(?:SYSTEM|HIDDEN|INTERNAL|SECRET)\]/i,
];

const PRIVILEGE_ESCALATION_PATTERNS = [
  /(?:admin|root|sudo|superuser|elevated)\s+(?:access|privilege|permission|role)/i,
  /(?:disable|turn off|skip|bypass)\s+(?:auth|authentication|authorization|security|validation|check)/i,
  /(?:override|ignore|skip)\s+(?:safety|security|permission|access)\s+(?:check|control|restriction)/i,
  /(?:grant|give|allow)\s+(?:all|full|unrestricted)\s+(?:access|permission)/i,
];

const DATA_EXFIL_PATTERNS = [
  /(?:send|post|transmit|forward|upload)\s+(?:data|info|content|result|response)\s+to/i,
  /(?:https?:\/\/|wss?:\/\/)\S+/i,
  /(?:webhook|callback|endpoint|server)\s*(?:url|uri)?\s*[:=]/i,
  /(?:exfiltrate|extract|steal|harvest|collect)\s+(?:data|credentials|tokens|keys)/i,
];

const TRUSTED_TOOL_NAMES = new Set([
  'read_file', 'write_file', 'list_directory', 'search', 'execute',
  'bash', 'shell', 'terminal', 'code', 'edit', 'delete', 'move',
  'copy', 'rename', 'mkdir', 'rmdir', 'fetch', 'request', 'query',
]);

const CROSS_TOOL_PATTERNS = [
  /(?:call|use|invoke|execute|run)\s+(?:the\s+)?["'`]?\w+["'`]?\s+tool/i,
  /(?:after|before)\s+this\s+tool\s*,?\s*(?:call|use|invoke|run)/i,
  /(?:first|then|next|also)\s+(?:call|use|invoke|run)/i,
];

export class ToolPoisoningScanner extends BaseScanner {
  readonly id = 'tool-poisoning';
  readonly name = 'Tool Poisoning Scanner';
  readonly category = 'pattern' as const;
  readonly rules: Rule[] = TOOL_POISONING_RULES;

  async scan(target: ScanTarget): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const tool of target.tools) {
      const desc = tool.description ?? '';
      findings.push(...this.checkHiddenInstructions(desc, tool.name, target.path));
      findings.push(...this.checkPrivilegeEscalation(desc, tool.name, target.path));
      findings.push(...this.checkDataExfil(desc, tool.name, target.path));
      findings.push(...this.checkToolShadowing(tool.name, target.path));
      findings.push(...this.checkCrossToolManipulation(desc, tool.name, target.path));
    }

    return findings;
  }

  private checkHiddenInstructions(desc: string, toolName: string, path: string): Finding[] {
    const rule = this.getRule('TP001');
    return HIDDEN_INSTRUCTION_PATTERNS
      .filter((p) => p.test(desc))
      .map((p) =>
        this.createFinding(rule, `Tool "${toolName}" contains hidden instruction: "${desc.match(p)?.[0]}"`, {
          file: path,
          toolName,
        }),
      );
  }

  private checkPrivilegeEscalation(desc: string, toolName: string, path: string): Finding[] {
    const rule = this.getRule('TP002');
    return PRIVILEGE_ESCALATION_PATTERNS
      .filter((p) => p.test(desc))
      .map((p) =>
        this.createFinding(
          rule,
          `Tool "${toolName}" contains privilege escalation instruction: "${desc.match(p)?.[0]}"`,
          { file: path, toolName },
        ),
      );
  }

  private checkDataExfil(desc: string, toolName: string, path: string): Finding[] {
    const rule = this.getRule('TP003');
    return DATA_EXFIL_PATTERNS
      .filter((p) => p.test(desc))
      .map((p) =>
        this.createFinding(
          rule,
          `Tool "${toolName}" contains data exfiltration instruction: "${desc.match(p)?.[0]}"`,
          { file: path, toolName },
        ),
      );
  }

  private checkToolShadowing(toolName: string, path: string): Finding[] {
    const normalizedName = toolName.toLowerCase().replace(/[-_\s]/g, '');
    for (const trusted of TRUSTED_TOOL_NAMES) {
      const normalizedTrusted = trusted.replace(/[-_\s]/g, '');
      if (normalizedName === normalizedTrusted && toolName !== trusted) {
        const rule = this.getRule('TP004');
        return [
          this.createFinding(rule, `Tool "${toolName}" mimics trusted tool "${trusted}"`, {
            file: path,
            toolName,
          }),
        ];
      }
    }
    return [];
  }

  private checkCrossToolManipulation(desc: string, toolName: string, path: string): Finding[] {
    const rule = this.getRule('TP005');
    return CROSS_TOOL_PATTERNS
      .filter((p) => p.test(desc))
      .map((p) =>
        this.createFinding(
          rule,
          `Tool "${toolName}" references other tools: "${desc.match(p)?.[0]}"`,
          { file: path, toolName },
        ),
      );
  }
}
