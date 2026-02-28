import { readFile, readdir, stat } from 'fs/promises';
import { join, resolve, extname, relative } from 'path';
import type {
  ScanTarget,
  ToolDefinition,
  SourceFile,
  PackageManifest,
  ToolParameter,
} from '../core/types.js';

const TS_EXTENSIONS = new Set(['.ts', '.js', '.mjs', '.mts']);

const SKIP_DIRS = new Set(['node_modules', 'dist', '.git', 'coverage', '.next']);

const TOOL_DEFINITION_PATTERNS = [
  /server\.tool\(\s*["'`]([^"'`]+)["'`]\s*,\s*["'`]([^"'`]+)["'`]\s*,\s*(\{[\s\S]*?\})\s*,/g,
  /name:\s*["'`]([^"'`]+)["'`][\s\S]*?description:\s*["'`]([^"'`]+)["'`]/g,
  /\.addTool\(\s*\{[\s\S]*?name:\s*["'`]([^"'`]+)["'`][\s\S]*?description:\s*["'`]([\s\S]*?)["'`]/g,
  /tools:\s*\[[\s\S]*?\{[\s\S]*?name:\s*["'`]([^"'`]+)["'`][\s\S]*?description:\s*["'`]([\s\S]*?)["'`]/g,
];

const SCHEMA_PATTERN =
  /(?:inputSchema|schema|parameters)\s*:\s*(\{[\s\S]*?\})\s*(?:,|\})/g;

export const loadMCPServer = async (
  targetPath: string,
  excludePatterns: string[] = [],
): Promise<ScanTarget> => {
  const resolvedPath = resolve(targetPath);
  const sourceFiles = await collectSourceFiles(resolvedPath, excludePatterns);
  const tools = extractToolDefinitions(sourceFiles);
  const manifest = await loadManifest(resolvedPath);

  return {
    path: resolvedPath,
    tools,
    sourceFiles,
    manifest,
  };
};

const compileExcludePatterns = (patterns: string[]): RegExp[] =>
  patterns.map((pattern) => {
    const regexStr = pattern
      .replace(/\./g, '\\.')
      .replace(/\*\*/g, '{{GLOBSTAR}}')
      .replace(/\*/g, '[^/]*')
      .replace(/\{\{GLOBSTAR\}\}/g, '.*');
    return new RegExp(`^${regexStr}$`);
  });

const matchesExclude = (filePath: string, basePath: string, compiledPatterns: RegExp[]): boolean => {
  const rel = relative(basePath, filePath).replace(/\\/g, '/');
  return compiledPatterns.some((regex) => regex.test(rel));
};

const collectSourceFiles = async (
  dirPath: string,
  excludePatterns: string[],
): Promise<SourceFile[]> => {
  const files: SourceFile[] = [];
  const compiledPatterns = compileExcludePatterns(excludePatterns);
  await walkDirectory(dirPath, files, dirPath, compiledPatterns);
  return files;
};

const walkDirectory = async (
  dirPath: string,
  files: SourceFile[],
  basePath: string,
  compiledPatterns: RegExp[],
): Promise<void> => {
  let entries;
  try {
    entries = await readdir(dirPath, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const fullPath = join(dirPath, entry.name);

    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) {
        await walkDirectory(fullPath, files, basePath, compiledPatterns);
      }
    } else if (entry.isFile() && TS_EXTENSIONS.has(extname(entry.name))) {
      if (matchesExclude(fullPath, basePath, compiledPatterns)) continue;
      try {
        const content = await readFile(fullPath, 'utf-8');
        files.push({ path: fullPath, content });
      } catch {
        // Skip unreadable files
      }
    }
  }
};

const extractToolDefinitions = (sourceFiles: SourceFile[]): ToolDefinition[] => {
  const tools: ToolDefinition[] = [];
  const seenNames = new Set<string>();

  for (const file of sourceFiles) {
    for (const pattern of TOOL_DEFINITION_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;

      while ((match = regex.exec(file.content)) !== null) {
        const name = match[1];
        const description = match[2] ?? '';

        if (name && !seenNames.has(name)) {
          seenNames.add(name);
          const schema = extractSchema(file.content, name);
          tools.push({
            name,
            description,
            inputSchema: schema,
            parameters: extractParameters(schema),
          });
        }
      }
    }
  }

  return tools;
};

// Note: schema extraction is not yet tool-specific; toolName is reserved for future use
const extractSchema = (
  content: string,
  toolName: string,
): Record<string, unknown> | undefined => {
  const regex = new RegExp(SCHEMA_PATTERN.source, SCHEMA_PATTERN.flags);
  let match;

  while ((match = regex.exec(content)) !== null) {
    try {
      const schemaStr = match[1];
      if (schemaStr) {
        return JSON.parse(schemaStr) as Record<string, unknown>;
      }
    } catch {
      continue;
    }
  }

  return undefined;
};

const extractParameters = (
  schema: Record<string, unknown> | undefined,
): ToolParameter[] => {
  if (!schema) return [];

  const properties = schema['properties'] as Record<string, Record<string, unknown>> | undefined;
  if (!properties) return [];

  const required = (schema['required'] as string[]) ?? [];

  return Object.entries(properties).map(([name, prop]) => ({
    name,
    type: (prop['type'] as string) ?? 'unknown',
    description: prop['description'] as string | undefined,
    required: required.includes(name),
    schema: prop,
  }));
};

const loadManifest = async (dirPath: string): Promise<PackageManifest | undefined> => {
  try {
    const content = await readFile(join(dirPath, 'package.json'), 'utf-8');
    return JSON.parse(content) as PackageManifest;
  } catch {
    return undefined;
  }
};
