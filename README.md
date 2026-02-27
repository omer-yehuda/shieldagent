# ShieldAgent

**AI Agent Security Scanner** - The first tool focused on securing what AI agents **DO** (tool calls, actions), not just what they SAY.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-blue.svg)](https://www.typescriptlang.org/)

## Why ShieldAgent?

- 90% of AI agents are over-permissioned
- 43% of MCP implementations have command injection flaws
- 78% of MCP servers have critical vulnerabilities
- EU AI Act full enforcement: August 2026

## Features

- **8 Security Scanners:** Tool poisoning, command injection, data exfiltration, prompt injection, over-permissions, input validation, auth/transport, supply chain
- **Framework Compliance:** OWASP Agentic Top 10 + Adversa MCP Top 25
- **Multiple Output Formats:** Table (default), JSON, SARIF (GitHub Security)
- **CI/CD Ready:** Non-zero exit code on findings, SARIF for GitHub code scanning

## Quick Start

```bash
# Install
pnpm add -g shieldagent

# Scan an MCP server
shieldagent scan ./my-mcp-server

# JSON output for CI
shieldagent scan ./my-mcp-server --format json

# SARIF for GitHub Security
shieldagent scan ./my-mcp-server --format sarif > results.sarif

# CI mode (exit code 1 on findings)
shieldagent scan ./my-mcp-server --ci
```

## Scanners

| Scanner | Type | Detects |
|---------|------|---------|
| Input Validation | Schema | Missing schemas, type constraints, bounds |
| Tool Poisoning | Pattern | Hidden instructions in tool descriptions |
| Prompt Injection | Pattern | Injections in parameter metadata |
| Auth & Transport | Pattern | Missing auth, insecure transport |
| Supply Chain | Pattern | Malicious deps, typosquatting |
| Command Injection | AST | Unsanitized input to exec/spawn/eval |
| Over-Permission | AST | Excessive capabilities vs description |
| Data Exfiltration | AST | Sensitive data read + outbound network |

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

## License

MIT
