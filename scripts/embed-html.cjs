const fs = require('fs');
const path = require('path');

const projectRoot = path.resolve(__dirname, '..');
const srcDir = path.join(projectRoot, 'src/workers');
const indexTsPath = path.join(srcDir, 'index.ts');
const publicDir = path.join(projectRoot, 'public');

let tsContent = fs.readFileSync(indexTsPath, 'utf8');

// Remove any existing HTML base64 constants and the "导出默认处理函数" comment line
tsContent = tsContent.replace(/\/\/ ─── 导出默认处理函数[^\n]*\n/g, '');
tsContent = tsContent.replace(/const [A-Z_]+_HTML_B64 = "[^"]*";\n?/g, '');
tsContent = tsContent.replace(/const [A-Z_]+_HTML = `[^`]*`;\n/gs, '');
tsContent = tsContent.replace(/import \{ [A-Z_]+_HTML \} from '\.\/[A-Z_]+\.js';\n/g, '');

// Build base64-encoded HTML constants
let insertLines = '';
const files = ['admin', 'login', 'register', 'index'];
for (const name of files) {
  const htmlPath = path.join(publicDir, `${name}.html`);
  const content = fs.readFileSync(htmlPath, 'utf8');
  const b64 = Buffer.from(content, 'utf8').toString('base64');
  insertLines += `\nconst ${name.toUpperCase()}_HTML_B64 = "${b64}";\n`;
}

// Insert before export default with a blank line
const exportPos = tsContent.indexOf('\nexport default {');
if (exportPos > 0) {
  tsContent = tsContent.slice(0, exportPos) + insertLines + tsContent.slice(exportPos);
}

fs.writeFileSync(indexTsPath, tsContent);
console.log('Embedded HTML as base64 constants');
