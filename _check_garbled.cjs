const fs = require('fs');
const path = require('path');

function walk(d, files = []) {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name === 'dist' || e.name.startsWith('_to_clean')) continue;
    const p = path.join(d, e.name);
    if (e.isDirectory()) walk(p, files);
    else if (e.isFile() && /\.(ts|md)$/.test(e.name)) files.push(p);
  }
  return files;
}

const files = walk('.');
const patterns = ['Ã§', 'Ã¼', 'Ã¶', 'Ä±', 'ÄŸ', 'ÅŸ', 'â€'];
const garbled = [];
for (const f of files) {
  const c = fs.readFileSync(f, 'utf8');
  for (const p of patterns) {
    if (c.includes(p)) {
      garbled.push(f);
      break;
    }
  }
}
console.log('Garbled files count:', garbled.length);
for (const f of garbled) console.log('  ' + f);
