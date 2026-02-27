export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ScannerCategory = 'schema' | 'pattern' | 'ast';

export type OutputFormat = 'table' | 'json' | 'sarif';

export interface Rule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  category: ScannerCategory;
  frameworks?: FrameworkMapping[];
}

export interface FrameworkMapping {
  framework: string;
  id: string;
  name: string;
}

export interface Finding {
  ruleId: string;
  severity: Severity;
  message: string;
  location: FindingLocation;
  metadata?: Record<string, unknown>;
  fingerprint?: string;
  frameworks?: FrameworkMapping[];
}

export interface FindingLocation {
  file: string;
  line?: number;
  column?: number;
  endLine?: number;
  endColumn?: number;
  toolName?: string;
}

export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema?: Record<string, unknown>;
  parameters?: ToolParameter[];
}

export interface ToolParameter {
  name: string;
  type: string;
  description?: string;
  required?: boolean;
  schema?: Record<string, unknown>;
}

export interface ScanTarget {
  path: string;
  tools: ToolDefinition[];
  sourceFiles: SourceFile[];
  manifest?: PackageManifest;
  config?: MCPServerConfig;
}

export interface SourceFile {
  path: string;
  content: string;
}

export interface PackageManifest {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
}

export interface MCPServerConfig {
  name?: string;
  version?: string;
  transport?: string;
  auth?: Record<string, unknown>;
}

export interface ScanResult {
  target: string;
  findings: Finding[];
  scanners: ScannerResult[];
  duration: number;
  timestamp: string;
}

export interface ScannerResult {
  scannerId: string;
  scannerName: string;
  findings: Finding[];
  duration: number;
  error?: string;
}

export interface Scanner {
  id: string;
  name: string;
  category: ScannerCategory;
  rules: Rule[];
  scan: (target: ScanTarget) => Promise<Finding[]>;
}

export interface ScanOptions {
  scanners?: string[];
  exclude?: string[];
  format?: OutputFormat;
  ci?: boolean;
  verbose?: boolean;
  configPath?: string;
}

export interface ShieldAgentConfig {
  scanners: Record<string, ScannerConfig>;
  exclude: string[];
  format: OutputFormat;
  ci: boolean;
}

export interface ScannerConfig {
  enabled: boolean;
  severity?: Severity;
  rules?: Record<string, boolean>;
}
