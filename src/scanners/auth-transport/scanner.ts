import { BaseScanner } from '../base-scanner.js';
import type { Finding, Rule, ScanTarget } from '../../core/types.js';
import { AUTH_TRANSPORT_RULES } from './rules.js';

const CREDENTIAL_PATTERNS = [
  { pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*["'`]([a-zA-Z0-9_\-]{20,})["'`]/gi, type: 'API key' },
  { pattern: /(?:password|passwd|pwd)\s*[:=]\s*["'`]([^"'`]{4,})["'`]/gi, type: 'password' },
  { pattern: /(?:secret|token)\s*[:=]\s*["'`]([a-zA-Z0-9_\-]{16,})["'`]/gi, type: 'secret/token' },
  { pattern: /(?:sk-[a-zA-Z0-9]{20,}|sk_live_[a-zA-Z0-9]+)/g, type: 'API key (Stripe/OpenAI format)' },
  { pattern: /(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]+)/g, type: 'GitHub token' },
  { pattern: /(?:AKIA[0-9A-Z]{16})/g, type: 'AWS access key' },
];

const AUTH_INDICATORS = [
  /(?:authenticate|authorization|auth\s*middleware)/i,
  /(?:bearer|jwt|oauth|api[_-]?key)\s+/i,
  /(?:verifyToken|checkAuth|requireAuth|isAuthenticated)/i,
  /(?:passport|express-jwt|jsonwebtoken)/i,
];

const HTTP_PATTERNS = [
  /http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/i,
  /createServer\(\s*\)/,
  /\.listen\(\s*\d+/,
];

const CORS_INDICATORS = [
  /cors\(/i,
  /Access-Control-Allow-Origin/i,
  /(?:cors|CORS)\s*[:=]/i,
];

const RATE_LIMIT_INDICATORS = [
  /(?:rate[_-]?limit|rateLimit|throttle)/i,
  /(?:express-rate-limit|bottleneck|p-limit)/i,
];

export class AuthTransportScanner extends BaseScanner {
  readonly id = 'auth-transport';
  readonly name = 'Auth & Transport Scanner';
  readonly category = 'pattern' as const;
  readonly rules: Rule[] = AUTH_TRANSPORT_RULES;

  async scan(target: ScanTarget): Promise<Finding[]> {
    const findings: Finding[] = [];
    let hasAuth = false;
    let hasCors = false;
    let hasRateLimit = false;
    let hasHttpTransport = false;

    for (const file of target.sourceFiles) {
      findings.push(...this.checkHardcodedCredentials(file.content, file.path));

      if (AUTH_INDICATORS.some((p) => p.test(file.content))) hasAuth = true;
      if (CORS_INDICATORS.some((p) => p.test(file.content))) hasCors = true;
      if (RATE_LIMIT_INDICATORS.some((p) => p.test(file.content))) hasRateLimit = true;
      if (HTTP_PATTERNS.some((p) => p.test(file.content))) hasHttpTransport = true;
    }

    if (!hasAuth && target.sourceFiles.length > 0) {
      const rule = this.getRule('AT001')!;
      findings.push(
        this.createFinding(rule, 'No authentication mechanism detected in MCP server', {
          file: target.path,
        }),
      );
    }

    if (hasHttpTransport) {
      findings.push(...this.checkInsecureTransport(target));
    }

    if (hasHttpTransport && !hasCors) {
      const rule = this.getRule('AT004')!;
      findings.push(
        this.createFinding(rule, 'HTTP transport detected without CORS configuration', {
          file: target.path,
        }),
      );
    }

    if (!hasRateLimit && target.sourceFiles.length > 0) {
      const rule = this.getRule('AT005')!;
      findings.push(
        this.createFinding(rule, 'No rate limiting detected on server endpoints', {
          file: target.path,
        }),
      );
    }

    return findings;
  }

  private checkHardcodedCredentials(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const rule = this.getRule('AT003')!;
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      // Skip comments and test files
      if (line.trimStart().startsWith('//') || line.trimStart().startsWith('*')) continue;
      if (filePath.includes('.test.') || filePath.includes('.spec.') || filePath.includes('__test__')) continue;

      for (const { pattern, type } of CREDENTIAL_PATTERNS) {
        const regex = new RegExp(pattern.source, pattern.flags);
        if (regex.test(line)) {
          // Skip env references
          if (/process\.env|import\.meta\.env|ENV\[/i.test(line)) continue;

          findings.push(
            this.createFinding(rule, `Hardcoded ${type} found`, {
              file: filePath,
              line: i + 1,
            }),
          );
        }
      }
    }

    return findings;
  }

  private checkInsecureTransport(target: ScanTarget): Finding[] {
    const findings: Finding[] = [];
    const rule = this.getRule('AT002')!;

    for (const file of target.sourceFiles) {
      const lines = file.content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (/http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/i.test(lines[i]!)) {
          findings.push(
            this.createFinding(rule, 'Insecure HTTP transport detected (use HTTPS)', {
              file: file.path,
              line: i + 1,
            }),
          );
        }
      }
    }

    return findings;
  }
}
