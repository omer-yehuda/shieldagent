import { access } from 'fs/promises';
import { join } from 'path';
import { BaseScanner } from '../base-scanner.js';
import type { Finding, Rule, ScanTarget, PackageManifest } from '../../core/types.js';
import { SUPPLY_CHAIN_RULES } from './rules.js';

const DANGEROUS_SCRIPTS = ['preinstall', 'install', 'postinstall', 'preuninstall', 'postuninstall'];

const POPULAR_PACKAGES = new Set([
  'express', 'react', 'lodash', 'axios', 'moment', 'webpack', 'typescript',
  'commander', 'chalk', 'debug', 'dotenv', 'cors', 'helmet', 'jsonwebtoken',
  'bcrypt', 'mongoose', 'sequelize', 'prisma', 'next', 'vue', 'angular',
  'fastify', 'koa', 'zod', 'yup', 'joi', 'uuid', 'dayjs', 'date-fns',
]);

const SUSPICIOUS_NAME_PATTERNS = [
  /[-_]?(?:backdoor|malware|exploit|hack|steal|keylog)/i,
  /^(?:get|load|fetch|grab)[-_]?(?:env|config|secret|cred|token|key)/i,
];

const LOCKFILES = [
  'pnpm-lock.yaml', 'package-lock.json', 'yarn.lock', 'bun.lockb',
];

export class SupplyChainScanner extends BaseScanner {
  readonly id = 'supply-chain';
  readonly name = 'Supply Chain Scanner';
  readonly category = 'pattern' as const;
  readonly rules: Rule[] = SUPPLY_CHAIN_RULES;

  async scan(target: ScanTarget): Promise<Finding[]> {
    const findings: Finding[] = [];

    if (target.manifest) {
      findings.push(...this.checkInstallScripts(target.manifest, target.path));
      findings.push(...this.checkDependencies(target.manifest, target.path));
    }

    findings.push(...(await this.checkLockfile(target.path)));

    return findings;
  }

  private checkInstallScripts(manifest: PackageManifest, path: string): Finding[] {
    const findings: Finding[] = [];
    const rule = this.getRule('SC001')!;
    const scripts = manifest.scripts ?? {};

    for (const scriptName of DANGEROUS_SCRIPTS) {
      if (scripts[scriptName]) {
        findings.push(
          this.createFinding(
            rule,
            `Package has "${scriptName}" script: "${scripts[scriptName]}"`,
            { file: join(path, 'package.json') },
          ),
        );
      }
    }

    return findings;
  }

  private checkDependencies(manifest: PackageManifest, path: string): Finding[] {
    const findings: Finding[] = [];
    const allDeps = {
      ...manifest.dependencies,
      ...manifest.devDependencies,
    };

    for (const [name, version] of Object.entries(allDeps)) {
      findings.push(...this.checkTyposquatting(name, path));
      findings.push(...this.checkSuspiciousName(name, path));
      findings.push(...this.checkVersionPinning(name, version, path));
    }

    return findings;
  }

  private checkTyposquatting(depName: string, path: string): Finding[] {
    const rule = this.getRule('SC002')!;

    for (const popular of POPULAR_PACKAGES) {
      if (depName === popular) continue;
      if (this.levenshteinDistance(depName, popular) === 1) {
        return [
          this.createFinding(
            rule,
            `Dependency "${depName}" is suspiciously similar to popular package "${popular}"`,
            { file: join(path, 'package.json') },
          ),
        ];
      }
    }

    return [];
  }

  private checkSuspiciousName(depName: string, path: string): Finding[] {
    const rule = this.getRule('SC004')!;

    for (const pattern of SUSPICIOUS_NAME_PATTERNS) {
      if (pattern.test(depName)) {
        return [
          this.createFinding(
            rule,
            `Dependency "${depName}" has suspicious name pattern`,
            { file: join(path, 'package.json') },
          ),
        ];
      }
    }

    return [];
  }

  private checkVersionPinning(depName: string, version: string, path: string): Finding[] {
    if (version.startsWith('*') || version === 'latest' || version.startsWith('>')) {
      const rule = this.getRule('SC003')!;
      return [
        this.createFinding(
          rule,
          `Dependency "${depName}" uses unpinned version "${version}"`,
          { file: join(path, 'package.json') },
        ),
      ];
    }
    return [];
  }

  private async checkLockfile(path: string): Promise<Finding[]> {
    for (const lockfile of LOCKFILES) {
      try {
        await access(join(path, lockfile));
        return [];
      } catch {
        continue;
      }
    }

    const rule = this.getRule('SC005')!;
    return [
      this.createFinding(rule, 'No lockfile found in project', { file: path }),
    ];
  }

  private levenshteinDistance(a: string, b: string): number {
    const matrix: number[][] = [];

    for (let i = 0; i <= a.length; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= b.length; j++) {
      matrix[0]![j] = j;
    }

    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        matrix[i]![j] = Math.min(
          matrix[i - 1]![j]! + 1,
          matrix[i]![j - 1]! + 1,
          matrix[i - 1]![j - 1]! + cost,
        );
      }
    }

    return matrix[a.length]![b.length]!;
  }
}
