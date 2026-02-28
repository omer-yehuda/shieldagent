import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { Command } from 'commander';
import { scanCommand } from './commands/scan.js';
import { reportCommand } from './commands/report.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(
  readFileSync(resolve(__dirname, '..', '..', 'package.json'), 'utf-8'),
) as { version: string };

const program = new Command();

program
  .name('shieldagent')
  .description('AI Agent Security Scanner - Scan MCP servers for vulnerabilities')
  .version(pkg.version);

program.addCommand(scanCommand);
program.addCommand(reportCommand);

program.parse();
