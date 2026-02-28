import { BaseScanner } from '../base-scanner.js';
import type { Finding, Rule, ScanTarget } from '../../core/types.js';
import { COMMAND_INJECTION_RULES } from './rules.js';

const EXEC_FUNCTIONS = [
  'exec', 'execSync', 'execFile', 'execFileSync',
  'spawn', 'spawnSync', 'fork',
];

const EXEC_PATTERN = new RegExp(
  `(?:child_process|cp|require\\(\\s*['"\`]child_process['"\`]\\s*\\))[\\s\\S]*?(?:${EXEC_FUNCTIONS.join('|')})\\s*\\(`,
  'g',
);

const DIRECT_EXEC_PATTERN = new RegExp(
  `(?:${EXEC_FUNCTIONS.join('|')})\\s*\\(`,
  'g',
);

const EVAL_PATTERNS = [
  /\beval\s*\(/g,
  /\bnew\s+Function\s*\(/g,
  /\bsetTimeout\s*\(\s*["'`]/g,
  /\bsetInterval\s*\(\s*["'`]/g,
];

const SHELL_TRUE_PATTERN = /(?:shell\s*:\s*true)/g;
const TEMPLATE_IN_EXEC_PATTERN = /(?:exec|execSync|spawn|spawnSync)\s*\(\s*`[^`]*\$\{/g;
const CONCAT_IN_EXEC_PATTERN = /(?:exec|execSync|spawn|spawnSync)\s*\([^)]*\+\s*(?:\w+|["'`])/g;

export class CommandInjectionScanner extends BaseScanner {
  readonly id = 'command-injection';
  readonly name = 'Command Injection Scanner';
  readonly category = 'ast' as const;
  readonly rules: Rule[] = COMMAND_INJECTION_RULES;

  async scan(target: ScanTarget): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const file of target.sourceFiles) {
      findings.push(...this.scanFile(file.content, file.path));
    }

    return findings;
  }

  private scanFile(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      const lineNum = i + 1;

      // Skip comments
      const trimmed = line.trimStart();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue;

      findings.push(...this.checkExecUsage(line, filePath, lineNum, content));
      findings.push(...this.checkEvalUsage(line, filePath, lineNum));
      findings.push(...this.checkShellOption(line, filePath, lineNum, lines, i));
      findings.push(...this.checkTemplateLiteral(line, filePath, lineNum));
      findings.push(...this.checkStringConcat(line, filePath, lineNum));
    }

    return findings;
  }

  private checkExecUsage(line: string, filePath: string, lineNum: number, fullContent: string): Finding[] {
    const hasImport = /child_process|require\s*\(\s*['"`]child_process['"`]\s*\)/.test(fullContent);
    if (!hasImport) return [];

    DIRECT_EXEC_PATTERN.lastIndex = 0;
    if (DIRECT_EXEC_PATTERN.test(line)) {
      // Check if the argument contains a variable (not a string literal)
      const argStart = line.indexOf('(');
      if (argStart === -1) return [];
      const afterParen = line.slice(argStart + 1).trim();
      if (afterParen.startsWith("'") || afterParen.startsWith('"')) return [];
      if (afterParen.startsWith('`')) {
        // Template literal - handled separately
        return [];
      }

      const rule = this.getRule('CI001');
      return [
        this.createFinding(rule, `Potentially unsanitized input in shell command`, {
          file: filePath,
          line: lineNum,
        }),
      ];
    }

    return [];
  }

  private checkEvalUsage(line: string, filePath: string, lineNum: number): Finding[] {
    const rule = this.getRule('CI002');
    const findings: Finding[] = [];

    for (const pattern of EVAL_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(line)) {
        findings.push(
          this.createFinding(rule, `eval() or dynamic code execution detected`, {
            file: filePath,
            line: lineNum,
          }),
        );
        break;
      }
    }

    return findings;
  }

  private checkShellOption(
    line: string,
    filePath: string,
    lineNum: number,
    lines: string[],
    lineIdx: number,
  ): Finding[] {
    SHELL_TRUE_PATTERN.lastIndex = 0;
    if (!SHELL_TRUE_PATTERN.test(line)) return [];

    // Check if this is near a spawn call (within 5 lines)
    const context = lines.slice(Math.max(0, lineIdx - 5), lineIdx + 5).join('\n');
    if (/spawn|spawnSync/.test(context)) {
      const rule = this.getRule('CI003');
      return [
        this.createFinding(rule, `spawn used with shell: true enables shell injection`, {
          file: filePath,
          line: lineNum,
        }),
      ];
    }

    return [];
  }

  private checkTemplateLiteral(line: string, filePath: string, lineNum: number): Finding[] {
    TEMPLATE_IN_EXEC_PATTERN.lastIndex = 0;
    if (TEMPLATE_IN_EXEC_PATTERN.test(line)) {
      const rule = this.getRule('CI004');
      return [
        this.createFinding(rule, `Template literal with variables in shell command`, {
          file: filePath,
          line: lineNum,
        }),
      ];
    }
    return [];
  }

  private checkStringConcat(line: string, filePath: string, lineNum: number): Finding[] {
    CONCAT_IN_EXEC_PATTERN.lastIndex = 0;
    if (CONCAT_IN_EXEC_PATTERN.test(line)) {
      const rule = this.getRule('CI005');
      return [
        this.createFinding(rule, `String concatenation used to build shell command`, {
          file: filePath,
          line: lineNum,
        }),
      ];
    }
    return [];
  }
}
