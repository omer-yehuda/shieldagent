import type { ScanResult, Finding, Severity } from '../core/types.js';

interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: { driver: SarifDriver };
  results: SarifResult[];
}

interface SarifDriver {
  name: string;
  version: string;
  informationUri: string;
  rules: SarifRule[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: string };
  properties?: { tags: string[] };
}

interface SarifResult {
  ruleId: string;
  level: string;
  message: { text: string };
  locations: SarifLocation[];
  fingerprints?: Record<string, string>;
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string };
    region?: { startLine: number; startColumn?: number };
  };
}

const SEVERITY_TO_SARIF_LEVEL: Record<Severity, string> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

export const formatSarif = (result: ScanResult): string => {
  const ruleSet = new Map<string, SarifRule>();

  for (const finding of result.findings) {
    if (!ruleSet.has(finding.ruleId)) {
      ruleSet.set(finding.ruleId, {
        id: finding.ruleId,
        name: finding.ruleId,
        shortDescription: { text: finding.message },
        defaultConfiguration: { level: SEVERITY_TO_SARIF_LEVEL[finding.severity] },
        properties: finding.frameworks
          ? { tags: finding.frameworks.map((f) => `${f.framework}/${f.id}`) }
          : undefined,
      });
    }
  }

  const sarifLog: SarifLog = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'ShieldAgent',
            version: '0.1.0',
            informationUri: 'https://github.com/omer-yehuda/shieldagent',
            rules: Array.from(ruleSet.values()),
          },
        },
        results: result.findings.map(toSarifResult),
      },
    ],
  };

  return JSON.stringify(sarifLog, null, 2);
};

const toSarifResult = (finding: Finding): SarifResult => ({
  ruleId: finding.ruleId,
  level: SEVERITY_TO_SARIF_LEVEL[finding.severity],
  message: { text: finding.message },
  locations: [
    {
      physicalLocation: {
        artifactLocation: { uri: finding.location.file },
        region: finding.location.line
          ? {
              startLine: finding.location.line,
              startColumn: finding.location.column,
            }
          : undefined,
      },
    },
  ],
  fingerprints: finding.fingerprint ? { 'shieldagent/v1': finding.fingerprint } : undefined,
});
