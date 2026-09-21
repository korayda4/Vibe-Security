import type { Language, Rule } from '../../types.js';
import { rules as frontendRules } from './frontend/index.js';
import { rules as backendRules } from './backend/index.js';
import { rules as networkRules } from './network/index.js';
import { rules as databaseRules } from './database/index.js';
import { rules as cicdRules } from './cicd/index.js';
import { rules as observabilityRules } from './observability/index.js';
import { rules as rustRules } from './rust/index.js';
import { rules as rubyRules } from './ruby/index.js';
import { rules as phpRules } from './php/index.js';
import { rules as kotlinRules } from './kotlin/index.js';
import { rules as vibeRules } from './vibe/index.js';
import { rules as lintRules } from './lint/index.js';

export interface RegisteredRule extends Rule {}

const registry: RegisteredRule[] = [
  ...Object.values(frontendRules),
  ...Object.values(backendRules),
  ...Object.values(networkRules),
  ...Object.values(databaseRules),
  ...Object.values(cicdRules),
  ...Object.values(observabilityRules),
  ...Object.values(rustRules),
  ...Object.values(rubyRules),
  ...Object.values(phpRules),
  ...Object.values(kotlinRules),
  ...Object.values(vibeRules),
  ...Object.values(lintRules),
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

export function getRulesByLanguages(languages: readonly Language[]): readonly RegisteredRule[] {
  return registry.filter((r) => r.languages.some((l) => languages.includes(l)));
}
