# Contributing to ShieldAgent

Thank you for your interest in contributing to ShieldAgent! This guide will help you get started.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/omer-yehuda/shieldagent.git
cd shieldagent

# Install dependencies (pnpm only)
pnpm install

# Run tests
pnpm test

# Build
pnpm build

# Lint
pnpm lint

# Type check
pnpm typecheck
```

## Project Structure

```
src/
  core/       - Types, scan engine, scanner registry
  scanners/   - Security scanners (extend BaseScanner)
  loaders/    - MCP server definition loaders
  reporters/  - Output formatters (table, JSON, SARIF)
  frameworks/ - Compliance framework mappings
  cli/        - CLI entry point and commands
  config/     - Configuration loading and defaults
```

## Adding a New Scanner

1. Create a directory under `src/scanners/` with your scanner name
2. Extend `BaseScanner` and implement:
   - `id` - Unique scanner identifier
   - `name` - Human-readable name
   - `category` - Scanner category
   - `rules` - Array of `Rule` definitions
   - `scan(target)` - Returns `Finding[]`
3. Register the scanner in `src/core/scanner-registry.ts`
4. Add tests in the same directory (`scanner.test.ts`)

## Coding Standards

- **TypeScript** with strict mode enabled
- **Arrow functions**, const-first declarations
- **Max 200 lines** per file
- **ESM imports** only (`type: "module"`)
- No `eval()` or `Function()` constructor
- Validate CLI input with **Zod**

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new supply-chain scanner
fix: correct false positive in CI004 rule
docs: update scanner table in README
test: add edge case tests for data exfiltration
refactor: extract pattern matching into shared utility
```

## Pull Request Process

1. Fork the repository and create a feature branch
2. Make your changes with tests (target >85% coverage)
3. Ensure all checks pass: `pnpm test && pnpm lint && pnpm typecheck`
4. Submit a pull request with a clear description

## Reporting Bugs

Open a [GitHub issue](https://github.com/omer-yehuda/shieldagent/issues) with:
- Steps to reproduce
- Expected vs actual behavior
- ShieldAgent version and Node.js version

## Security Vulnerabilities

**Do NOT open a public issue.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
