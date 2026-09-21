import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { getAllRules, getRuleById } from '../engine/rules/index.js';
import type { Layer } from '../types.js';

export const listRulesToolDefinition = {
  name: 'list_rules',
  description: 'List all security rules with their ID, layer, severity, title, and supported languages.',
  inputSchema: {
    type: 'object',
    properties: {
      layer: {
        type: 'string',
        enum: ['frontend', 'backend', 'network', 'database', 'cicd', 'observability'],
        description: 'Filter by layer',
      },
    },
  },
};

export async function handleListRules(args: Record<string, unknown> = {}): Promise<CallToolResult> {
  const params = args as { layer?: Layer };
  const rules = params.layer
    ? getAllRules().filter((r) => r.layer === params.layer)
    : getAllRules();

  const text = rules
    .map(
      (r) =>
        `- [\`${r.id}\`] **${r.severity.toUpperCase()}** - ${r.layer} - ${r.title}\n  Languages: ${r.languages.join(', ')}`
    )
    .join('\n');

  return {
    content: [
      {
        type: 'text',
        text: `# Available Security Rules\n\nTotal: ${rules.length}\n\n${text}`,
      },
    ],
    isError: false,
  };
}

export const getRuleDetailToolDefinition = {
  name: 'get_rule_detail',
  description: 'Show full details for a rule, including description, threat, remediation, and references.',
  inputSchema: {
    type: 'object',
    required: ['ruleId'],
    properties: {
      ruleId: {
        type: 'string',
        description: 'Rule ID (for example: "BE-004", "FE-001")',
      },
    },
  },
};

export async function handleGetRuleDetail(args: Record<string, unknown> = {}): Promise<CallToolResult> {
  const params = args as { ruleId: string };
  if (!params.ruleId) {
    return {
      content: [{ type: 'text', text: 'Error: ruleId is required' }],
      isError: true,
    };
  }

  const rule = getRuleById(params.ruleId);
  if (!rule) {
    return {
      content: [{ type: 'text', text: `Error: Rule not found: ${params.ruleId}` }],
      isError: true,
    };
  }

  const text = [
    `# ${rule.id} -- ${rule.title}`,
    '',
    `- **Layer:** ${rule.layer}`,
    `- **Severity:** ${rule.severity}`,
    rule.cwe ? `- **CWE:** ${rule.cwe}` : '',
    rule.owasp ? `- **OWASP:** ${rule.owasp}` : '',
    `- **Languages:** ${rule.languages.join(', ')}`,
    '',
    '## Description',
    '',
    rule.description,
    '',
    '## Threat / Impact',
    '',
    rule.threat,
    '',
    '## Remediation',
    '',
    rule.remediation,
    '',
    rule.references.length > 0
      ? `## References\n\n${rule.references.map((r) => `- ${r}`).join('\n')}`
      : '',
  ]
    .filter(Boolean)
    .join('\n');

  return {
    content: [{ type: 'text', text }],
    isError: false,
  };
}
