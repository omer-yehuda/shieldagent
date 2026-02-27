# ShieldAgent - Project Instructions

## Overview
AI Agent Security Scanner - scans MCP servers for vulnerabilities including tool poisoning, command injection, data exfiltration, over-permissions, and more.

## Tech Stack
- **Language:** TypeScript (strict mode)
- **Runtime:** Node.js >= 18
- **Package Manager:** pnpm (exclusively)
- **Bundler:** tsup (ESM-only)
- **Testing:** Vitest with >85% coverage target
- **Linting:** ESLint (strict) + Prettier

## Architecture
- `src/core/` - Types, scan engine, scanner registry
- `src/scanners/` - Individual security scanners (extend BaseScanner)
- `src/loaders/` - MCP server definition loaders
- `src/reporters/` - Output formatters (table, JSON, SARIF)
- `src/frameworks/` - Compliance framework mappings (OWASP, Adversa)
- `src/cli/` - CLI entry point and commands
- `src/config/` - Configuration loading and defaults
- `tests/fixtures/` - Test MCP servers (vulnerable + clean)

## Conventions
- Arrow functions, const-first
- Max 200 lines per file
- ESM imports only (`type: "module"`)
- No `eval()`, no `Function()` constructor
- All CLI input validated with Zod
- SARIF fingerprints use SHA-256
- Conventional commits: feat|fix|docs|style|refactor|perf|test|chore

## Scanner Pattern
Each scanner extends `BaseScanner` and implements:
- `id`: Unique scanner identifier
- `name`: Human-readable name
- `scan(target)`: Returns `Finding[]`
- `rules`: Array of `Rule` definitions

## Key Commands
```bash
pnpm test          # Run tests
pnpm build         # Build with tsup
pnpm lint          # ESLint check
pnpm typecheck     # TypeScript check
```
