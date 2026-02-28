# ShieldAgent

**AI Agent Security Scanner** - The first tool focused on securing what AI agents **DO** (tool calls, actions), not just what they SAY.

[![npm version](https://img.shields.io/npm/v/shieldagent.svg)](https://www.npmjs.com/package/shieldagent)
[![CI](https://github.com/omer-yehuda/shieldagent/actions/workflows/ci.yml/badge.svg)](https://github.com/omer-yehuda/shieldagent/actions/workflows/ci.yml)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-blue.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Why ShieldAgent?

- 90% of AI agents are over-permissioned
- 43% of MCP implementations have command injection flaws
- 78% of MCP servers have critical vulnerabilities
- EU AI Act full enforcement: August 2026

## How It Works

```
MCP Server Directory
        |
        v
  +-- Loader --+       +-----------+
  | Discover   |       | Config    |
  | tools &    | <---- | Exclude   |
  | source     |       | patterns  |
  +-----+------+       +-----------+
        |
        v
  +-- Scan Engine --------------------------+
  |  Schema     Pattern      AST            |
  |  Scanners   Scanners    Scanners        |
  |  (input-    (poisoning, (cmd-injection, |
  |   valid.)    prompt-inj)  over-perm)    |
  +---------+--+--+---------+---------------+
            |  |  |
            v  v  v
       Finding[] (deduplicated, fingerprinted)
            |
            v
  +-- Reporters ---+
  | Table | JSON | SARIF |
  +-------+------+-------+
```

## Quick Start

```bash
# Install globally
pnpm add -g shieldagent

# Scan an MCP server
shieldagent scan ./my-mcp-server

# JSON output for CI
shieldagent scan ./my-mcp-server --format json

# SARIF for GitHub Security
shieldagent scan ./my-mcp-server --format sarif > results.sarif

# CI mode (exit code 1 on findings)
shieldagent scan ./my-mcp-server --ci

# Exclude test fixtures from scanning
shieldagent scan ./my-mcp-server --exclude "tests/**" "fixtures/**"
```

## Scanners

| Scanner | Category | Severity Range | Detects |
|---------|----------|---------------|---------|
| Input Validation | Schema | medium - high | Missing schemas, type constraints, bounds |
| Tool Poisoning | Pattern | high - critical | Hidden instructions in tool descriptions |
| Prompt Injection | Pattern | high - critical | Injections in parameter metadata |
| Auth & Transport | Pattern | medium - critical | Missing auth, insecure transport |
| Supply Chain | Pattern | medium - critical | Malicious deps, typosquatting |
| Command Injection | AST | critical | Unsanitized input to exec/spawn/eval |
| Over-Permission | AST | medium - high | Excessive capabilities vs description |
| Data Exfiltration | AST | high - critical | Sensitive data read + outbound network |

## Compliance Frameworks

- **OWASP Agentic Top 10** - Every finding maps to its OWASP category
- **Adversa MCP Top 25** - Every finding maps to its Adversa category

## Configuration

Create a `.shieldagentrc.json` in your project root:

```json
{
  "scanners": {
    "command-injection": { "enabled": true, "severity": "critical" },
    "tool-poisoning": { "enabled": true }
  },
  "exclude": ["tests/**", "node_modules/**"],
  "format": "table",
  "ci": false
}
```

## Programmatic API

```typescript
import {
  ScanEngine,
  createDefaultRegistry,
  loadMCPServer,
  formatOutput,
} from 'shieldagent';

const registry = createDefaultRegistry();
const engine = new ScanEngine(registry);
const target = await loadMCPServer('./my-mcp-server');

const result = await engine.scan(target, {
  scanners: ['command-injection', 'tool-poisoning'],
  format: 'json',
});

console.log(`Found ${result.findings.length} issues`);
const output = formatOutput(result, 'json');
```

## GitHub Actions Integration

```yaml
name: MCP Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: pnpm
      - run: pnpm add -g shieldagent
      - run: shieldagent scan . --format sarif > results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
        if: always()
```

## CLI Reference

```
shieldagent scan <path> [options]

Options:
  -f, --format <format>       Output format: table, json, sarif (default: "table")
  -s, --scanners <scanners>   Specific scanners to run
  -e, --exclude <patterns>    Glob patterns to exclude from scanning
  -c, --config <path>         Path to config file
  --ci                        CI mode: exit with code 1 if findings detected
  -v, --verbose               Verbose output
  -V, --version               Output version number
  -h, --help                  Display help
```

## License

MIT
