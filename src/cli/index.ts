import { Command } from 'commander';
import { scanCommand } from './commands/scan.js';
import { reportCommand } from './commands/report.js';

const program = new Command();

program
  .name('shieldagent')
  .description('AI Agent Security Scanner - Scan MCP servers for vulnerabilities')
  .version('0.1.0');

program.addCommand(scanCommand);
program.addCommand(reportCommand);

program.parse();
