// SPDX-License-Identifier: AGPL-3.0-only
// Write docs/configuration.md from .env.example, so the two never disagree.
// Usage: node scripts/config-docs.mjs           (rewrite the file)
//        node scripts/config-docs.mjs --check   (exit 1 if it is out of date; CI runs this)
import { readFileSync, writeFileSync } from 'node:fs';

const lines = readFileSync('.env.example', 'utf8').split('\n');
const sections = [];
let notes = [], intro = [];
for (const raw of lines) {
  const line = raw.trimEnd();
  const heading = line.match(/^# ---- (.+) ----$/);
  if (heading) { sections.push({ title: heading[1], notes: [], vars: [] }); notes = []; continue; }
  const v = line.match(/^#? ?([A-Z][A-Z0-9_]+)=(.*)$/);
  if (v && sections.length) {
    const s = sections[sections.length - 1];
    // A comment before the first variable of a section describes the section; later ones describe the next variable.
    s.vars.push({ name: v[1], value: v[2], on: !line.startsWith('#'), about: notes.join(' ') });
    notes = [];
    continue;
  }
  const c = line.match(/^# ?(.*)$/);
  if (c) { (sections.length ? notes : intro).push(c[1]); continue; }
  notes = [];
}

// Table cells: escape pipes, and angle brackets so placeholders such as <BROD_DATA_DIR> are not read as HTML.
const cell = s => s.replace(/\|/g, '\\|').replace(/</g, '&lt;').replace(/>/g, '&gt;');
let out = `# Configuration

Brod reads its settings from environment variables, and from a \`.env\` file in its working directory. With Docker
Compose, put them in \`.env\` next to \`docker-compose.yml\`. Start from [\`.env.example\`](../.env.example).

A self-hosted Brod needs only \`BROD_ADMIN_EMAIL\`. Everything else has a working default. A hosted Brod
(\`BROD_MODE=hosted\`) must also set \`BROD_PUBLIC_URL\`, \`APPS_DOMAIN\` and every secret.

This page is generated from \`.env.example\` by \`node scripts/config-docs.mjs\`. Edit that file, not this one.

`;
for (const s of sections) {
  out += `## ${s.title[0].toUpperCase()}${s.title.slice(1)}\n\n| Variable | Example or default | What it does |\n| --- | --- | --- |\n`;
  for (const v of s.vars) {
    const value = v.value === '' ? '' : `\`${v.value.replace(/\|/g, '\\|')}\``;
    out += `| \`${v.name}\` | ${value} | ${cell(v.about)} |\n`;
  }
  out += '\n';
}
out = out.trimEnd() + '\n';

if (process.argv.includes('--check')) {
  const current = readFileSync('docs/configuration.md', 'utf8');
  if (current !== out) {
    console.error('docs/configuration.md is out of date. Run: node scripts/config-docs.mjs');
    process.exit(1);
  }
  console.log('docs/configuration.md is up to date');
} else {
  writeFileSync('docs/configuration.md', out);
  console.log(`wrote docs/configuration.md: ${sections.reduce((n, s) => n + s.vars.length, 0)} variables`);
}
