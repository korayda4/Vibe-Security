import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'AI-004',
  title: 'Direct unescaped template string interpolation in LLM prompt (Prompt Injection Sink)',
  layer: 'backend',
  severity: 'high',
  description:
    'Concatenating raw untrusted user input directly into LLM prompt template strings allows attackers to perform Prompt Injection, overriding system instructions, exfiltrating hidden prompt data, or hijacking autonomous tool execution.',
  threat:
    'Prompt Injection, system prompt leak, unauthorized action execution by autonomous LLM agents, guardrail bypass.',
  remediation:
    '1) Separate system instructions from user messages using native role structures (role: "system", role: "user") rather than concatenating single strings.\n' +
    '2) Use XML or markdown delimiter tags (e.g. <user_input>{{input}}</user_input>) and instruct the model never to follow commands inside these tags.\n' +
    '3) Validate and sanitize inputs with length caps and guardrail classifiers before passing to models.',
  references: [
    'https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-2023-v1_1.pdf',
    'https://simonwillison.net/2023/May/2/prompt-injection-explained/',
  ],
  cwe: 'CWE-77',
  owasp: 'A03:2021 Injection',
  languages: ['javascript', 'typescript', 'python'],
  check: (ctx) => {
    const patterns = [
      /prompt\s*[:=]\s*`[^`]*\$\{(?:req\.|request\.|input|userInput|params|body|query)[^}]*\}/gi,
      /messages\s*:\s*\[\s*\{\s*role\s*:\s*['"`]system['"`]\s*,\s*content\s*:\s*`[^`]*\$\{(?:req\.|userInput|input|body)/gi,
      /f['"`](?:You are a|System:|Instructions:).*\{(?:\w*user\w*|\w*input\w*|\w*request\w*)\}/gi,
    ];

    const findings = [];
    for (const re of patterns) {
      findings.push(...grepRule(rule, ctx, re));
    }
    return findings;
  },
};

export default rule;
