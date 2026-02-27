import Table from 'cli-table3';
import chalk from 'chalk';
import type { ScanResult, Finding, Severity } from '../core/types.js';

const SEVERITY_COLORS: Record<Severity, (text: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow,
  low: chalk.blue,
  info: chalk.gray,
};

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: 'X',
  high: '!',
  medium: '~',
  low: '-',
  info: 'i',
};

export const formatTable = (result: ScanResult): string => {
  const lines: string[] = [];

  lines.push('');
  lines.push(chalk.bold(`  ShieldAgent Security Scan Results`));
  lines.push(chalk.gray(`  Target: ${result.target}`));
  lines.push(chalk.gray(`  Duration: ${result.duration}ms`));
  lines.push('');

  if (result.findings.length === 0) {
    lines.push(chalk.green('  No security findings detected. Your MCP server looks clean!'));
    lines.push('');
    return lines.join('\n');
  }

  const summary = getSeveritySummary(result.findings);
  lines.push(formatSummaryLine(summary));
  lines.push('');

  const table = new Table({
    head: ['', 'Rule', 'Severity', 'Message', 'Location'],
    colWidths: [3, 10, 10, 50, 30],
    wordWrap: true,
    style: { head: ['cyan'] },
  });

  for (const finding of result.findings) {
    const colorFn = SEVERITY_COLORS[finding.severity];
    const icon = SEVERITY_ICONS[finding.severity];

    table.push([
      colorFn(icon),
      finding.ruleId,
      colorFn(finding.severity),
      finding.message,
      formatLocation(finding),
    ]);
  }

  lines.push(table.toString());
  lines.push('');

  // Scanner summary
  const scannerTable = new Table({
    head: ['Scanner', 'Findings', 'Duration', 'Status'],
    style: { head: ['cyan'] },
  });

  for (const scanner of result.scanners) {
    scannerTable.push([
      scanner.scannerName,
      String(scanner.findings.length),
      `${scanner.duration}ms`,
      scanner.error ? chalk.red('error') : chalk.green('ok'),
    ]);
  }

  lines.push(chalk.bold('  Scanner Summary'));
  lines.push(scannerTable.toString());
  lines.push('');

  return lines.join('\n');
};

const getSeveritySummary = (findings: Finding[]): Record<Severity, number> => {
  const summary: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    summary[f.severity]++;
  }
  return summary;
};

const formatSummaryLine = (summary: Record<Severity, number>): string => {
  const total = Object.values(summary).reduce((a, b) => a + b, 0);
  const parts = [
    `  ${chalk.bold(`${total} findings:`)}`,
    summary.critical > 0 ? chalk.bgRed.white.bold(` ${summary.critical} critical `) : null,
    summary.high > 0 ? chalk.red.bold(`${summary.high} high`) : null,
    summary.medium > 0 ? chalk.yellow(`${summary.medium} medium`) : null,
    summary.low > 0 ? chalk.blue(`${summary.low} low`) : null,
    summary.info > 0 ? chalk.gray(`${summary.info} info`) : null,
  ].filter(Boolean);

  return parts.join(' | ');
};

const formatLocation = (finding: Finding): string => {
  const parts: string[] = [];
  if (finding.location.file) {
    const shortPath = finding.location.file.split(/[/\\]/).slice(-2).join('/');
    parts.push(shortPath);
  }
  if (finding.location.line) parts.push(`:${finding.location.line}`);
  if (finding.location.toolName) parts.push(` [${finding.location.toolName}]`);
  return parts.join('');
};
