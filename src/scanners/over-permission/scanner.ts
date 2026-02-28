import { BaseScanner } from '../base-scanner.js';
import type { Finding, Rule, ScanTarget } from '../../core/types.js';
import { OVER_PERMISSION_RULES } from './rules.js';

const FS_WRITE_PATTERNS = [
  /(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)/,
  /(?:fs\.(?:write|append|mkdir|rmdir|unlink|rename|chmod|chown))/,
  /(?:fs\/promises.*(?:write|append|mkdir|rmdir|unlink|rename))/,
];

const NETWORK_PATTERNS = [
  /(?:fetch|axios|got|request|superagent|node-fetch|undici)\s*\(/,
  /(?:https?|net|tls|dgram)\.(?:request|get|createServer|connect|createConnection)/,
  /new\s+(?:WebSocket|EventSource)\s*\(/,
  /\.(?:get|post|put|patch|delete)\s*\(\s*['"`]https?/,
];

const PROCESS_PATTERNS = [
  /child_process/,
  /(?:exec|execSync|spawn|spawnSync|fork)\s*\(/,
  /process\.kill/,
  /require\s*\(\s*['"`]child_process['"`]\s*\)/,
];

const ENV_PATTERNS = [
  /process\.env\[/,
  /process\.env\.\w+/,
  /import\.meta\.env/,
];

const DB_PATTERNS = [
  /(?:mongoose|sequelize|prisma|knex|typeorm|drizzle)/,
  /(?:mongodb|pg|mysql|sqlite|redis|memcached)/,
  /\.(?:query|execute|find|findOne|findMany|create|update|delete)\s*\(/,
  /(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\s+/,
];

export class OverPermissionScanner extends BaseScanner {
  readonly id = 'over-permission';
  readonly name = 'Over-Permission Scanner';
  readonly category = 'ast' as const;
  readonly rules: Rule[] = OVER_PERMISSION_RULES;

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

      const trimmed = line.trimStart();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

      findings.push(...this.checkFsWrite(line, filePath, lineNum));
      findings.push(...this.checkNetwork(line, filePath, lineNum));
      findings.push(...this.checkProcess(line, filePath, lineNum));
      findings.push(...this.checkEnvAccess(line, filePath, lineNum));
      findings.push(...this.checkDbAccess(line, filePath, lineNum));
    }

    return findings;
  }

  private checkFsWrite(line: string, filePath: string, lineNum: number): Finding[] {
    for (const pattern of FS_WRITE_PATTERNS) {
      if (pattern.test(line)) {
        const rule = this.getRule('OP001');
        return [
          this.createFinding(rule, `Filesystem write operation detected`, {
            file: filePath,
            line: lineNum,
          }),
        ];
      }
    }
    return [];
  }

  private checkNetwork(line: string, filePath: string, lineNum: number): Finding[] {
    for (const pattern of NETWORK_PATTERNS) {
      if (pattern.test(line)) {
        const rule = this.getRule('OP002');
        return [
          this.createFinding(rule, `Outbound network access detected`, {
            file: filePath,
            line: lineNum,
          }),
        ];
      }
    }
    return [];
  }

  private checkProcess(line: string, filePath: string, lineNum: number): Finding[] {
    for (const pattern of PROCESS_PATTERNS) {
      if (pattern.test(line)) {
        const rule = this.getRule('OP003');
        return [
          this.createFinding(rule, `Process execution capability detected`, {
            file: filePath,
            line: lineNum,
          }),
        ];
      }
    }
    return [];
  }

  private checkEnvAccess(line: string, filePath: string, lineNum: number): Finding[] {
    for (const pattern of ENV_PATTERNS) {
      if (pattern.test(line)) {
        const rule = this.getRule('OP004');
        return [
          this.createFinding(rule, `Environment variable access detected`, {
            file: filePath,
            line: lineNum,
          }),
        ];
      }
    }
    return [];
  }

  private checkDbAccess(line: string, filePath: string, lineNum: number): Finding[] {
    for (const pattern of DB_PATTERNS) {
      if (pattern.test(line)) {
        // Skip import statements (just importing isn't a finding)
        if (/^import\s/.test(line.trimStart())) return [];
        const rule = this.getRule('OP005');
        return [
          this.createFinding(rule, `Database access capability detected`, {
            file: filePath,
            line: lineNum,
          }),
        ];
      }
    }
    return [];
  }
}
