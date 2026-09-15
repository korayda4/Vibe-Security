const fs = require('fs');
let c = fs.readFileSync('src/server.ts', 'utf8');
const replacements = [
  ['Report written to:', 'Report written to:'],
  ['Baseline diff: showing only NEW findings', 'Baseline diff: showing only NEW findings'],
  ['â€™', '->'],
  ['â€"', '--'],
  ['Â·', '-'],
  ['âœ…', 'NO_FINDINGS_GOOD'],
  ['ğŸ›¡ï¸', 'VIBE_SECURITY'],
  ['âŒ', 'ERROR:'],
];
for (const [find, replace] of replacements) {
  while (c.indexOf(find) !== -1) {
    c = c.replace(find, replace);
  }
}
c = c.replace(/NO_FINDINGS_GOOD/g, '(no findings)');
c = c.replace(/VIBE_SECURITY/g, 'Vibe Security');
c = c.replace(/ERROR:/g, 'Error:');
fs.writeFileSync('src/server.ts', c, 'utf8');
console.log('done');
