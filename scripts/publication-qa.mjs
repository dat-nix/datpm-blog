import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const contentDir = path.join(root, 'src', 'content', 'blog');
const distDir = path.join(root, 'dist');
const errors = [];
const warnings = [];
const note = (list, file, message) => list.push(file ? file + ': ' + message : message);
const markdownFiles = fs.readdirSync(contentDir).filter((file) => file.endsWith('.md')).sort();

function readFrontmatter(source) {
  const lines = source.split('\n');
  if (lines[0] !== '---') return null;
  const end = lines.indexOf('---', 1);
  if (end < 0) return null;
  const raw = lines.slice(1, end);
  const value = (key) => {
    const line = raw.find((entry) => entry.startsWith(key + ':'));
    return line ? line.slice(key.length + 1).trim().replace(/^['"]|['"]$/g, '') : '';
  };
  const tagsLine = raw.find((entry) => entry.startsWith('tags:')) || '';
  const start = tagsLine.indexOf('[');
  const finish = tagsLine.lastIndexOf(']');
  const tagsText = start >= 0 && finish > start ? tagsLine.slice(start + 1, finish) : '';
  const tags = [...tagsText.matchAll(/['"]([^'"]+)['"]/g)].map((match) => match[1]);
  return { title: value('title'), date: value('date'), category: value('category'), excerpt: value('excerpt'), tags };
}

function publicPathExists(urlPath) {
  let clean = decodeURIComponent(urlPath.split('#')[0].split('?')[0]);
  while (clean.startsWith('/')) clean = clean.slice(1);
  const candidates = clean
    ? [path.join(distDir, clean), path.join(distDir, clean, 'index.html'), path.join(distDir, clean + '.html')]
    : [path.join(distDir, 'index.html')];
  return candidates.some((candidate) => fs.existsSync(candidate));
}

for (const file of markdownFiles) {
  const relative = path.join('src/content/blog', file);
  const source = fs.readFileSync(path.join(contentDir, file), 'utf8');
  const frontmatter = readFrontmatter(source);

  if (!frontmatter) {
    note(errors, relative, 'missing frontmatter');
    continue;
  }

  for (const field of ['title', 'date', 'category', 'excerpt']) {
    if (!frontmatter[field]) note(errors, relative, 'missing ' + field);
  }
  if (!frontmatter.tags.length) note(errors, relative, 'missing tags');
  if (new Set(frontmatter.tags).size !== frontmatter.tags.length) note(errors, relative, 'duplicate tag');
  if (frontmatter.date && Number.isNaN(Date.parse(frontmatter.date))) note(errors, relative, 'invalid date');

  const hasBadPlaceholder =
    source.includes('http://<') ||
    source.includes('https://<') ||
    source.includes('TODO') ||
    /0x\s+[0-9a-f]/i.test(source);
  if (hasBadPlaceholder) note(errors, relative, 'contains a placeholder or malformed hexadecimal literal');
  if (/fake_flag|placeholder/i.test(source)) {
    note(warnings, relative, 'contains an explicitly labelled placeholder/local result; verify its status before presenting it as remote');
  }

  const hasSolverHeading = /^###\s+(?:solver|reproduction)/im.test(source);
  const hasCodeFence = source.includes('~~~') || source.includes(String.fromCharCode(96));
  if (hasSolverHeading && !hasCodeFence && !source.includes('/solvers/')) {
    note(warnings, relative, 'has a solver/reproduction heading without code or a linked solver');
  }

  for (const chunk of source.split('](').slice(1)) {
    const target = chunk.split(')')[0];
    if (target.startsWith('/') && !publicPathExists(target)) {
      note(errors, relative, 'missing internal link or image: ' + target);
    }
  }
}

if (!fs.existsSync(distDir)) {
  note(errors, '', 'dist/ does not exist; run npm run build first');
} else {
  const htmlFiles = [];
  const walk = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const target = path.join(directory, entry.name);
      if (entry.isDirectory()) walk(target);
      else if (entry.name.endsWith('.html')) htmlFiles.push(target);
    }
  };
  walk(distDir);

  for (const file of htmlFiles) {
    const html = fs.readFileSync(file, 'utf8');
    const relative = path.relative(root, file);
    if (relative.startsWith(path.join('dist', 'solvers'))) continue;
    for (const marker of ['og:title', 'og:description', 'og:image', 'twitter:card', 'canonical']) {
      if (!html.includes(marker)) note(errors, relative, 'missing metadata: ' + marker);
    }
  }
  if (!fs.existsSync(path.join(distDir, 'social-card-v2.png'))) {
    note(errors, 'dist', 'missing social-card-v2.png');
  }
}

if (errors.length) {
  console.log('Errors:');
  for (const error of errors) console.log('  - ' + error);
}
if (warnings.length) {
  console.log('Warnings:');
  for (const warning of warnings) console.log('  - ' + warning);
}
const status = errors.length ? 'FAILED' : warnings.length ? 'passed with warnings' : 'passed';
console.log('Publication QA: ' + status + ' (' + markdownFiles.length + ' articles)');
if (errors.length) process.exitCode = 1;
