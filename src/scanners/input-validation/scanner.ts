import { BaseScanner } from '../base-scanner.js';
import type { Finding, Rule, ScanTarget } from '../../core/types.js';
import { INPUT_VALIDATION_RULES } from './rules.js';

export class InputValidationScanner extends BaseScanner {
  readonly id = 'input-validation';
  readonly name = 'Input Validation Scanner';
  readonly category = 'schema' as const;
  readonly rules: Rule[] = INPUT_VALIDATION_RULES;

  async scan(target: ScanTarget): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const tool of target.tools) {
      findings.push(...this.checkParameters(tool, target.path));
    }

    return findings;
  }

  private checkParameters(
    tool: { name: string; inputSchema?: Record<string, unknown>; parameters?: Array<{ name: string; type: string; description?: string; required?: boolean; schema?: Record<string, unknown> }> },
    targetPath: string,
  ): Finding[] {
    const findings: Finding[] = [];
    const schema = tool.inputSchema;

    if (!schema) {
      const rule = this.getRule('IV001');
      findings.push(
        this.createFinding(rule, `Tool "${tool.name}" has no input schema defined`, {
          file: targetPath,
          toolName: tool.name,
        }),
      );
      return findings;
    }

    const properties = schema['properties'] as Record<string, Record<string, unknown>> | undefined;
    const required = schema['required'] as string[] | undefined;

    if (!required || required.length === 0) {
      const rule = this.getRule('IV003');
      findings.push(
        this.createFinding(rule, `Tool "${tool.name}" has no required fields specified`, {
          file: targetPath,
          toolName: tool.name,
        }),
      );
    }

    if (properties) {
      for (const [paramName, paramSchema] of Object.entries(properties)) {
        findings.push(...this.checkParameterSchema(tool.name, paramName, paramSchema, targetPath));
      }
    }

    return findings;
  }

  private checkParameterSchema(
    toolName: string,
    paramName: string,
    schema: Record<string, unknown>,
    targetPath: string,
  ): Finding[] {
    const findings: Finding[] = [];

    if (!schema['type']) {
      const rule = this.getRule('IV002');
      findings.push(
        this.createFinding(
          rule,
          `Parameter "${paramName}" in tool "${toolName}" lacks type constraint`,
          { file: targetPath, toolName },
        ),
      );
    }

    if (schema['type'] === 'string' && !schema['maxLength'] && !schema['enum'] && !schema['pattern']) {
      const rule = this.getRule('IV004');
      findings.push(
        this.createFinding(
          rule,
          `String parameter "${paramName}" in tool "${toolName}" has no length/format constraints`,
          { file: targetPath, toolName },
        ),
      );
    }

    if (
      (schema['type'] === 'number' || schema['type'] === 'integer') &&
      schema['minimum'] === undefined &&
      schema['maximum'] === undefined
    ) {
      const rule = this.getRule('IV005');
      findings.push(
        this.createFinding(
          rule,
          `Number parameter "${paramName}" in tool "${toolName}" has no min/max bounds`,
          { file: targetPath, toolName },
        ),
      );
    }

    if (!schema['description']) {
      const rule = this.getRule('IV006');
      findings.push(
        this.createFinding(
          rule,
          `Parameter "${paramName}" in tool "${toolName}" has no description`,
          { file: targetPath, toolName },
        ),
      );
    }

    return findings;
  }
}
