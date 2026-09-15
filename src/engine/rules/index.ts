import type { Language, Rule } from '../../types.js';
import { rules as frontendRules } from './frontend/index.js';
import { rules as backendRules } from './backend/index.js';
import { rules as networkRules } from './network/index.js';
import { rules as databaseRules } from './database/index.js';
import { rules as cicdRules } from './cicd/index.js';
import { rules as observabilityRules } from './observability/index.js';

export interface RegisteredRule extends Rule {}

const registry: RegisteredRule[] = [
  ...Object.values(frontendRules),
  ...Object.values(backendRules),
  ...Object.values(networkRules),
  ...Object.values(databaseRules),
  ...Object.values(cicdRules),
  ...Object.values(observabilityRules),
];

export function getAllRules(): readonly RegisteredRule[] {
  return registry;
}

export function getRuleById(id: string): RegisteredRule | undefined {
  return registry.find((r) => r.id === id);
}

export function getRulesForLanguage(language: Language): readonly RegisteredRule[] {
  return registry.filter((r) => r.languages.includes(language));
}

export function getRulesByLayer(layer: RegisteredRule['layer']): readonly RegisteredRule[] {
  return registry.filter((r) => r.layer === layer);
}
