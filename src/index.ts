// Core
export { ScanEngine } from './core/scan-engine.js';
export { ScannerRegistry } from './core/scanner-registry.js';
export type {
  Scanner,
  Finding,
  Rule,
  ScanTarget,
  ScanResult,
  ScanOptions,
  Severity,
  OutputFormat,
  ShieldAgentConfig,
  ToolDefinition,
} from './core/types.js';

// Scanners
export { createDefaultRegistry } from './scanners/index.js';
export { BaseScanner } from './scanners/base-scanner.js';

// Loaders
export { loadMCPServer } from './loaders/index.js';

// Reporters
export { formatOutput, formatTable, formatJson, formatSarif } from './reporters/index.js';

// Config
export { loadConfig, DEFAULT_CONFIG } from './config/index.js';

// Frameworks
export { OWASP_AGENTIC_TOP_10, ADVERSA_MCP_TOP_25 } from './frameworks/index.js';
