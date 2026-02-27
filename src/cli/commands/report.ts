import { Command } from 'commander';
import chalk from 'chalk';
import Table from 'cli-table3';
import { OWASP_AGENTIC_TOP_10, ADVERSA_MCP_TOP_25 } from '../../frameworks/index.js';
import type { FrameworkItem } from '../../frameworks/index.js';

export const reportCommand = new Command('report')
  .description('Generate compliance reports against security frameworks')
  .option('--framework <name>', 'Framework: owasp-agentic, adversa-mcp', 'owasp-agentic')
  .action((options: { framework: string }) => {
    const framework = options.framework === 'adversa-mcp' ? ADVERSA_MCP_TOP_25 : OWASP_AGENTIC_TOP_10;
    const name = options.framework === 'adversa-mcp' ? 'Adversa MCP Top 25' : 'OWASP Agentic Top 10';

    process.stdout.write('\n');
    process.stdout.write(chalk.bold(`  ${name} Coverage Report\n`));
    process.stdout.write('\n');

    const table = new Table({
      head: ['ID', 'Name', 'Description', 'Rules'],
      colWidths: [10, 30, 45, 20],
      wordWrap: true,
      style: { head: ['cyan'] },
    });

    for (const item of framework) {
      table.push([
        item.id,
        item.name,
        item.description,
        item.relatedRules.join(', '),
      ]);
    }

    process.stdout.write(table.toString());
    process.stdout.write('\n\n');
    process.stdout.write(chalk.gray(`  Total items: ${framework.length}\n`));
    process.stdout.write(chalk.gray(`  Rules covered: ${countUniqueRules(framework)}\n`));
    process.stdout.write('\n');
  });

const countUniqueRules = (items: FrameworkItem[]): number => {
  const rules = new Set<string>();
  for (const item of items) {
    for (const rule of item.relatedRules) {
      rules.add(rule);
    }
  }
  return rules.size;
};
