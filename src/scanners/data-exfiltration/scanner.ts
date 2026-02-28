import { BaseScanner } from '../base-scanner.js';
import type { Finding, Rule, ScanTarget } from '../../core/types.js';
import { DATA_EXFILTRATION_RULES } from './rules.js';

const SENSITIVE_ENV_PATTERNS = [
  /process\.env\.\w*(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL|AUTH|PRIVATE)/i,
  /process\.env\.\w*(?:API_KEY|ACCESS_KEY|SESSION|JWT)/i,
  /process\.env\[['"`]\w*(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL|AUTH)['"`]\]/i,
];

const SENSITIVE_FILE_PATTERNS = [
  /(?:readFile|readFileSync|createReadStream)\s*\([^)]*(?:\.env|\.pem|\.key|id_rsa|\.ssh|credentials|secret|\.p12)/i,
  /(?:readFile|readFileSync|createReadStream)\s*\([^)]*(?:\/etc\/(?:passwd|shadow|hosts)|~\/\.ssh|~\/\.aws)/i,
  /(?:readFile|readFileSync)\s*\([^)]*(?:config|settings)\.\w+/i,
];

const NETWORK_SEND_PATTERNS = [
  /(?:fetch|axios\.post|axios\.put|got\.post|request\.post)\s*\(/,
  /\.(?:post|put|patch)\s*\(\s*['"`]https?/,
  /(?:net|dgram|tls)\.(?:connect|createConnection|send)/,
  /new\s+WebSocket\s*\(/,
];

const BASE64_ENCODE_PATTERNS = [
  /Buffer\.from\([^)]+\)\.toString\s*\(\s*['"`]base64['"`]\s*\)/,
  /btoa\s*\(/,
  /\.toString\s*\(\s*['"`]base64['"`]\s*\)/,
];

const DNS_EXFIL_PATTERNS = [
  /dns\.(?:resolve|lookup|query)\s*\(/,
  /(?:resolve|lookup)\s*\(\s*(?:`[^`]*\$\{|[^)]+\+)/,
];

export class DataExfiltrationScanner extends BaseScanner {
  readonly id = 'data-exfiltration';
  readonly name = 'Data Exfiltration Scanner';
  readonly category = 'ast' as const;
  readonly rules: Rule[] = DATA_EXFILTRATION_RULES;

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

    const hasSensitiveRead = this.hasSensitiveDataAccess(content);
    const hasNetworkSend = this.hasNetworkSending(content);

    if (hasSensitiveRead && hasNetworkSend) {
      const rule = this.getRule('DE001');
      findings.push(
        this.createFinding(
          rule,
          'File reads sensitive data and has outbound network access',
          { file: filePath },
        ),
      );
    }

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      const lineNum = i + 1;

      const trimmed = line.trimStart();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

      findings.push(...this.checkEnvSecrets(line, filePath, lineNum));
      findings.push(...this.checkSensitiveFiles(line, filePath, lineNum));
      findings.push(...this.checkBase64Encoding(line, filePath, lineNum, content));
      findings.push(...this.checkDnsExfil(line, filePath, lineNum));
    }

    return findings;
  }

  private hasSensitiveDataAccess(content: string): boolean {
    return (
      SENSITIVE_ENV_PATTERNS.some((p) => p.test(content)) ||
      SENSITIVE_FILE_PATTERNS.some((p) => p.test(content))
    );
  }

  private hasNetworkSending(content: string): boolean {
    return NETWORK_SEND_PATTERNS.some((p) => p.test(content));
  }

  private checkEnvSecrets(line: string, filePath: string, lineNum: number): Finding[] {
    for (const pattern of SENSITIVE_ENV_PATTERNS) {
      if (pattern.test(line)) {
        const rule = this.getRule('DE002');
        return [
          this.createFinding(rule, `Access to sensitive environment variable detected`, {
            file: filePath,
            line: lineNum,
          }),
        ];
      }
    }
    return [];
  }

  private checkSensitiveFiles(line: string, filePath: string, lineNum: number): Finding[] {
    for (const pattern of SENSITIVE_FILE_PATTERNS) {
      if (pattern.test(line)) {
        const rule = this.getRule('DE003');
        return [
          this.createFinding(rule, `Read access to sensitive file detected`, {
            file: filePath,
            line: lineNum,
          }),
        ];
      }
    }
    return [];
  }

  private checkBase64Encoding(
    line: string,
    filePath: string,
    lineNum: number,
    fullContent: string,
  ): Finding[] {
    for (const pattern of BASE64_ENCODE_PATTERNS) {
      if (pattern.test(line)) {
        // Only flag if file also has network access
        if (this.hasNetworkSending(fullContent)) {
          const rule = this.getRule('DE004');
          return [
            this.createFinding(rule, `Base64 encoding detected with network access in file`, {
              file: filePath,
              line: lineNum,
            }),
          ];
        }
      }
    }
    return [];
  }

  private checkDnsExfil(line: string, filePath: string, lineNum: number): Finding[] {
    for (const pattern of DNS_EXFIL_PATTERNS) {
      if (pattern.test(line)) {
        const rule = this.getRule('DE005');
        return [
          this.createFinding(rule, `Potential DNS exfiltration pattern detected`, {
            file: filePath,
            line: lineNum,
          }),
        ];
      }
    }
    return [];
  }
}
