import type { ScanResult } from '../core/types.js';

export const formatJson = (result: ScanResult): string => {
  return JSON.stringify(result, null, 2);
};
