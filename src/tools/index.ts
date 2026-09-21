import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { scanProjectToolDefinition, handleScanProject } from './scanProject.js';
import { scanFileToolDefinition, handleScanFile } from './scanFile.js';
import {
  listRulesToolDefinition,
  handleListRules,
  getRuleDetailToolDefinition,
  handleGetRuleDetail,
} from './ruleTools.js';
import { applyFixToolDefinition, handleApplyFix } from './applyFix.js';

export const allTools = [
  scanProjectToolDefinition,
  scanFileToolDefinition,
  listRulesToolDefinition,
  getRuleDetailToolDefinition,
  applyFixToolDefinition,
];

export async function dispatchTool(
  name: string,
  args: Record<string, unknown> = {}
): Promise<CallToolResult> {
  switch (name) {
    case 'scan_project':
      return handleScanProject(args);
    case 'scan_file':
      return handleScanFile(args);
    case 'list_rules':
      return handleListRules(args);
    case 'get_rule_detail':
      return handleGetRuleDetail(args);
    case 'apply_fix':
      return handleApplyFix(args);
    default:
      return {
        content: [{ type: 'text', text: `Unknown tool: ${name}` }],
        isError: true,
      };
  }
}
