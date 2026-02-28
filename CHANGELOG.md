# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-28

### Added

- Initial release of ShieldAgent
- 8 security scanners: tool poisoning, command injection, data exfiltration, prompt injection, over-permissions, input validation, auth/transport, supply chain
- MCP server loader with file discovery and tool extraction
- OWASP Agentic Top 10 compliance mapping
- Adversa MCP Top 25 compliance mapping
- Multiple output formats: table, JSON, SARIF
- CLI with `scan` command, format selection, and CI mode
- Configuration file support (`.shieldagentrc.json`)
- Exclude pattern support for reducing false positives
- `--exclude` CLI flag to override config exclude patterns
- Programmatic API with full type exports
- `exports` field in package.json for proper ESM resolution

### Fixed

- Build shebang bug: `#!/usr/bin/env node` no longer injected into library output (`dist/index.js`), only into CLI entry (`dist/cli/index.js`)
- SARIF fingerprints now use SHA-256 instead of MD5
- ESLint lint scripts no longer use invalid `--ext .ts` flag (incompatible with flat config)
- CLI version now read from package.json at runtime instead of hardcoded

### Removed

- `crypto-js` dependency (replaced by Node.js built-in `node:crypto`)
- `ts-morph` dependency (replaced by regex-based AST scanning)
- `.env.example` file (project does not use LLM APIs)
