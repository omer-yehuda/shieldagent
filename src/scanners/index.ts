import { ScannerRegistry } from '../core/scanner-registry.js';
import { InputValidationScanner } from './input-validation/index.js';
import { ToolPoisoningScanner } from './tool-poisoning/index.js';
import { PromptInjectionScanner } from './prompt-injection/index.js';
import { AuthTransportScanner } from './auth-transport/index.js';
import { SupplyChainScanner } from './supply-chain/index.js';
import { CommandInjectionScanner } from './command-injection/index.js';
import { OverPermissionScanner } from './over-permission/index.js';
import { DataExfiltrationScanner } from './data-exfiltration/index.js';

export const createDefaultRegistry = (): ScannerRegistry => {
  const registry = new ScannerRegistry();

  registry.register(new InputValidationScanner());
  registry.register(new ToolPoisoningScanner());
  registry.register(new PromptInjectionScanner());
  registry.register(new AuthTransportScanner());
  registry.register(new SupplyChainScanner());
  registry.register(new CommandInjectionScanner());
  registry.register(new OverPermissionScanner());
  registry.register(new DataExfiltrationScanner());

  return registry;
};

export {
  InputValidationScanner,
  ToolPoisoningScanner,
  PromptInjectionScanner,
  AuthTransportScanner,
  SupplyChainScanner,
  CommandInjectionScanner,
  OverPermissionScanner,
  DataExfiltrationScanner,
};
