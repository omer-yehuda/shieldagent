import { Command } from 'commander';
import { resolve } from 'path';
import { ScanEngine } from '../../core/scan-engine.js';
import { createDefaultRegistry } from '../../scanners/index.js';
import { loadMCPServer } from '../../loaders/index.js';
import { loadConfig } from '../../config/index.js';
import { formatOutput } from '../../reporters/index.js';
import type { OutputFormat } from '../../core/types.js';

export const scanCommand = new Command('scan')
  .description('Scan an MCP server for security vulnerabilities')
  .argument('<path>', 'Path to the MCP server to scan')
  .option('-f, --format <format>', 'Output format: table, json, sarif', 'table')
  .option('--ci', 'CI mode: exit with code 1 if findings detected', false)
  .option('-s, --scanners <scanners...>', 'Specific scanners to run')
  .option('-c, --config <path>', 'Path to config file')
  .option('-v, --verbose', 'Verbose output', false)
  .action(async (targetPath: string, options: {
    format: string;
    ci: boolean;
    scanners?: string[];
    config?: string;
    verbose: boolean;
  }) => {
    try {
      const resolvedPath = resolve(targetPath);
      const config = await loadConfig(resolvedPath, options.config);

      const format = (options.format as OutputFormat) ?? config.format;

      if (format === 'table') {
        process.stderr.write('\n  Scanning for vulnerabilities...\n\n');
      }

      const registry = createDefaultRegistry();
      const engine = new ScanEngine(registry);
      const target = await loadMCPServer(resolvedPath);

      const enabledScanners = options.scanners ??
        Object.entries(config.scanners)
          .filter(([_, cfg]) => cfg.enabled !== false)
          .map(([id]) => id);

      const result = await engine.scan(target, {
        scanners: enabledScanners,
        format,
        ci: options.ci ?? config.ci,
        verbose: options.verbose,
      });

      const output = formatOutput(result, format);
      process.stdout.write(output);

      if ((options.ci || config.ci) && result.findings.length > 0) {
        process.exit(1);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      process.stderr.write(`\n  Error: ${message}\n\n`);
      process.exit(2);
    }
  });
