/**
 * MCP server smoke test — gerçek stdio üzerinden initialize/list_tools/call_tool yapar.
 */

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const serverPath = path.resolve(__dirname, '../dist/index.js');

const proc = spawn(process.execPath, [serverPath], {
  stdio: ['pipe', 'pipe', 'pipe'],
});

let stdout = '';
let stderr = '';
proc.stdout.on('data', (b) => (stdout += b.toString()));
proc.stderr.on('data', (b) => (stderr += b.toString()));

const messages = [
  {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'test', version: '1.0' },
    },
  },
  {
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/list',
    params: {},
  },
  {
    jsonrpc: '2.0',
    id: 3,
    method: 'tools/call',
    params: {
      name: 'list_rules',
      arguments: { layer: 'frontend' },
    },
  },
  {
    jsonrpc: '2.0',
    id: 4,
    method: 'tools/call',
    params: {
      name: 'get_rule_detail',
      arguments: { ruleId: 'FE-001' },
    },
  },
];

for (const m of messages) {
  proc.stdin.write(JSON.stringify(m) + '\n');
}

await new Promise((r) => setTimeout(r, 1500));
proc.kill();

console.log('=== STDERR (server log) ===');
console.log(stderr);
console.log('=== STDOUT (parsed MCP responses) ===');
const lines = stdout.split('\n').filter((l) => l.trim().startsWith('{'));
for (const l of lines) {
  try {
    const obj = JSON.parse(l);
    if (obj.result?.tools) {
      console.log(`#${obj.id} tools/list: ${obj.result.tools.length} tools registered`);
      for (const t of obj.result.tools) console.log(`   - ${t.name}`);
    } else if (obj.result?.content?.[0]?.text) {
      console.log(`#${obj.id} response (first 200 chars):`);
      console.log('  ', obj.result.content[0].text.slice(0, 200).replace(/\n/g, ' '));
    } else if (obj.id === 1) {
      console.log(`#1 initialize: serverName=${obj.result?.serverInfo?.name}`);
    } else {
      console.log(`#${obj.id}:`, JSON.stringify(obj).slice(0, 200));
    }
  } catch {
    // ignore
  }
}
