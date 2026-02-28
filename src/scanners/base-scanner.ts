import { createHash } from 'node:crypto';

import type { Finding, Rule, ScanTarget, Scanner, ScannerCategory } from '../core/types.js';

export abstract class BaseScanner implements Scanner {
  abstract readonly id: string;
  abstract readonly name: string;
  abstract readonly category: ScannerCategory;
  abstract readonly rules: Rule[];

  abstract scan(target: ScanTarget): Promise<Finding[]>;

  protected createFinding(
    rule: Rule,
    message: string,
    location: Finding['location'],
    metadata?: Record<string, unknown>,
  ): Finding {
    return {
      ruleId: rule.id,
      severity: rule.severity,
      message,
      location,
      metadata,
      frameworks: rule.frameworks,
      fingerprint: this.generateFingerprint(rule.id, location),
    };
  }

  private generateFingerprint(ruleId: string, location: Finding['location']): string {
    const raw = `${ruleId}:${location.file}:${location.line ?? 0}:${location.toolName ?? ''}`;
    return createHash('sha256').update(raw).digest('hex');
  }

  protected getRule(ruleId: string): Rule | undefined {
    return this.rules.find((r) => r.id === ruleId);
  }
}
