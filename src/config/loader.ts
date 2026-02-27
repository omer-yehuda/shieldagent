import { readFile } from 'fs/promises';
import { resolve, join } from 'path';
import { z } from 'zod/v4';
import type { ShieldAgentConfig } from '../core/types.js';
import { DEFAULT_CONFIG } from './defaults.js';

const ScannerConfigSchema = z.object({
  enabled: z.boolean().optional(),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
  rules: z.record(z.string(), z.boolean()).optional(),
});

const ConfigSchema = z.object({
  scanners: z.record(z.string(), ScannerConfigSchema).optional(),
  exclude: z.array(z.string()).optional(),
  format: z.enum(['table', 'json', 'sarif']).optional(),
  ci: z.boolean().optional(),
});

const CONFIG_FILES = ['.shieldagentrc.json', '.shieldagentrc', 'shieldagent.config.json'];

export const loadConfig = async (
  targetPath: string,
  configPath?: string,
): Promise<ShieldAgentConfig> => {
  const resolvedPath = resolve(targetPath);

  if (configPath) {
    return mergeWithDefault(await readConfigFile(resolve(configPath)));
  }

  for (const fileName of CONFIG_FILES) {
    try {
      const fullPath = join(resolvedPath, fileName);
      const config = await readConfigFile(fullPath);
      return mergeWithDefault(config);
    } catch {
      continue;
    }
  }

  return { ...DEFAULT_CONFIG };
};

const readConfigFile = async (filePath: string): Promise<Partial<ShieldAgentConfig>> => {
  const content = await readFile(filePath, 'utf-8');
  const parsed = JSON.parse(content) as unknown;
  return ConfigSchema.parse(parsed) as Partial<ShieldAgentConfig>;
};

const mergeWithDefault = (partial: Partial<ShieldAgentConfig>): ShieldAgentConfig => ({
  scanners: { ...DEFAULT_CONFIG.scanners, ...partial.scanners },
  exclude: partial.exclude ?? DEFAULT_CONFIG.exclude,
  format: partial.format ?? DEFAULT_CONFIG.format,
  ci: partial.ci ?? DEFAULT_CONFIG.ci,
});
