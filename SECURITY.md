# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in ShieldAgent, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **security@shieldagent.dev** (or open a private security advisory on GitHub)

### What to include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline:
- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 7 days
- **Fix release:** Within 30 days for critical issues

## Scope

The following are in scope:
- Command injection in scanner analysis
- False negatives (missing real vulnerabilities)
- Supply chain risks in ShieldAgent's own dependencies
- Authentication/authorization bypasses

The following are out of scope:
- Vulnerabilities in scanned target code (that's what ShieldAgent finds)
- Social engineering attacks
- DoS attacks against the CLI tool
