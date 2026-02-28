import type { Finding, ScanOptions, ScanResult, ScannerResult, ScanTarget } from './types.js';
import type { ScannerRegistry } from './scanner-registry.js';

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export class ScanEngine {
  constructor(private readonly registry: ScannerRegistry) {}

  async scan(target: ScanTarget, options: ScanOptions = {}): Promise<ScanResult> {
    const startTime = Date.now();
    const scanners = this.registry.getEnabled(options.scanners);

    if (scanners.length === 0) {
      throw new Error('No scanners enabled. Check your configuration.');
    }

    const results = await Promise.allSettled(
      scanners.map(async (scanner): Promise<ScannerResult> => {
        const scannerStart = Date.now();
        try {
          const findings = await scanner.scan(target);
          return {
            scannerId: scanner.id,
            scannerName: scanner.name,
            findings,
            duration: Date.now() - scannerStart,
          };
        } catch (error) {
          return {
            scannerId: scanner.id,
            scannerName: scanner.name,
            findings: [],
            duration: Date.now() - scannerStart,
            error: error instanceof Error ? error.message : String(error),
          };
        }
      }),
    );

    const scannerResults = results.map((r) =>
      r.status === 'fulfilled'
        ? r.value
        : {
            scannerId: 'unknown',
            scannerName: 'unknown',
            findings: [],
            duration: 0,
            error: r.reason instanceof Error ? r.reason.message : String(r.reason),
          },
    );

    const allFindings: Finding[] = scannerResults.flatMap((r) => r.findings);

    return {
      target: target.path,
      findings: this.sortFindings(allFindings),
      scanners: scannerResults,
      duration: Date.now() - startTime,
      timestamp: new Date().toISOString(),
    };
  }

  private sortFindings(findings: Finding[]): Finding[] {
    return findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  }
}
