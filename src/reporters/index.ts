import type { OutputFormat, ScanResult } from '../core/types.js';
import { formatTable } from './table-reporter.js';
import { formatJson } from './json-reporter.js';
import { formatSarif } from './sarif-reporter.js';

export const formatOutput = (result: ScanResult, format: OutputFormat): string => {
  switch (format) {
    case 'table':
      return formatTable(result);
    case 'json':
      return formatJson(result);
    case 'sarif':
      return formatSarif(result);
  }
};

export { formatTable, formatJson, formatSarif };
