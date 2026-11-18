// Copies the repository's Markdown into src/content/docs so the website and
// GitHub show the same text. The repository files are the source; never edit
// the generated copies. Run by `npm run build` and `npm run dev`.
//
// For each file this script:
// - takes the first `# Heading` as the page title and drops it from the body,
// - adds frontmatter (title, description, editUrl pointing at the original),
// - drops badge lines and turns GitHub alerts into Starlight asides,
// - rewrites relative links: synced files go to their page under the site
//   base, everything else goes to the file on GitHub.

import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { existsSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = 'https://github.com/kanywst/visado';
const BRANCH = 'main';
const BASE = '/visado';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../..');
const out = path.resolve(here, '../src/content/docs');

// Repository path -> page slug and optional title override. The sidebar in
// astro.config.mjs refers to these slugs.
const pages = [
  { src: 'README.md', slug: 'overview', title: 'Overview' },
  { src: 'deploy/lab/README.md', slug: 'getting-started', title: 'Getting started: the lab' },
  { src: 'docs/scope.md', slug: 'concepts/scope' },
  { src: 'docs/design.md', slug: 'concepts/design', title: 'Design' },
  { src: 'docs/bindings.md', slug: 'concepts/bindings', optional: true },
  { src: 'SPEC-MAP.md', slug: 'spec-map' },
  { src: 'SECURITY.md', slug: 'security/policy' },
  { src: 'docs/research/05-threats.md', slug: 'security/threats', title: 'Threat model' },
  { src: 'ROADMAP.md', slug: 'roadmap' },
  { src: 'CHANGELOG.md', slug: 'changelog' },
  { src: 'CONTRIBUTING.md', slug: 'contributing' },
  { src: 'CODE_OF_CONDUCT.md', slug: 'code-of-conduct' },
  { src: 'docs/research/README.md', slug: 'research', title: 'Research notes' },
  { src: 'docs/research/01-market.md', slug: 'research/market' },
  { src: 'docs/research/02-specs.md', slug: 'research/specs' },
  { src: 'docs/research/03-delegation-chains.md', slug: 'research/delegation-chains' },
  { src: 'docs/research/04-landscape.md', slug: 'research/landscape' },
  { src: 'docs/research/06-idp-and-spire.md', slug: 'research/idp-and-spire' },
  { src: 'docs/research/07-observability-ui-launch.md', slug: 'research/observability-ui-launch' },
].filter((p) => !p.optional || existsSync(path.join(root, p.src)));

const bySource = new Map(pages.map((p) => [p.src, p]));

const ALERTS = { NOTE: 'note', TIP: 'tip', IMPORTANT: 'caution', WARNING: 'caution', CAUTION: 'danger' };

function rewriteTarget(target, fromSrc) {
  if (/^([a-z][a-z0-9+.-]*:|#|\/\/)/i.test(target)) return target;
  const [rawPath, hash = ''] = target.split('#');
  const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(fromSrc), rawPath));
  const anchor = hash ? `#${hash}` : '';
  const page = bySource.get(resolved) ?? bySource.get(path.posix.join(resolved, 'README.md'));
  if (page) return `${BASE}/${page.slug}/${anchor}`;
  const abs = path.join(root, resolved);
  const kind = existsSync(abs) && statSync(abs).isDirectory() ? 'tree' : 'blob';
  if (!existsSync(abs)) console.warn(`sync-docs: ${fromSrc} links to missing ${resolved}`);
  return `${REPO}/${kind}/${BRANCH}/${resolved.replace(/\/$/, '')}${anchor}`;
}

function transform(text, page) {
  const lines = text.replace(/\r\n/g, '\n').split('\n');
  let title = page.title;
  const body = [];
  let inFence = false;
  let alert = null;

  for (const line of lines) {
    if (/^\s*(```|~~~)/.test(line)) inFence = !inFence;
    if (inFence || /^\s*(```|~~~)/.test(line)) {
      body.push(line);
      continue;
    }
    const h1 = /^# (.+)$/.exec(line);
    if (h1 && body.every((l) => l.trim() === '')) {
      title ??= h1[1].trim();
      continue;
    }
    if (/^\[!\[/.test(line)) continue; // badge row
    const start = /^> \[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*$/.exec(line);
    if (start) {
      alert = ALERTS[start[1]];
      body.push(`:::${alert}`);
      continue;
    }
    if (alert) {
      if (line.startsWith('>')) {
        body.push(line.replace(/^> ?/, ''));
        continue;
      }
      body.push(':::');
      alert = null;
    }
    body.push(line);
  }
  if (alert) body.push(':::');

  let md = body.join('\n').replace(/^\n+/, '');
  // Inline links and images: [text](target) and ![alt](target "title").
  md = md.replace(/(\]\()([^)\s]+)((?:\s+"[^"]*")?\))/g, (_, a, target, b) => a + rewriteTarget(target, page.src) + b);
  // Reference definitions: [label]: target
  md = md.replace(/^(\[[^\]]+\]:\s+)(\S+)/gm, (_, a, target) => a + rewriteTarget(target, page.src));
  // Bare <img src="..."> in raw HTML.
  md = md.replace(/(<(?:img|source)[^>]*\s(?:src|srcset)=")([^"]+)(")/g, (_, a, target, b) => a + rewriteTarget(target, page.src).replace(`/blob/`, '/raw/') + b);

  const description = firstParagraph(md);
  return { title, description, md };
}

function firstParagraph(md) {
  let inFence = false;
  for (const block of md.split(/\n\s*\n/)) {
    const t = block.trim();
    if (/^(```|~~~)/.test(t)) inFence = !inFence;
    if (inFence || !t || /^(#|\||:::|>|-|\*|\d+\.|<|```)/.test(t)) continue;
    const plain = t
      .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
      .replace(/[`*_]/g, '')
      .replace(/\s+/g, ' ')
      .trim();
    return plain.length > 200 ? `${plain.slice(0, 197).replace(/\s+\S*$/, '')}…` : plain;
  }
  return '';
}

const yaml = (s) => JSON.stringify(s);

// Remove the previous run's output but keep the hand-written homepage.
for (const p of pages) {
  await rm(path.join(out, `${p.slug}.md`), { force: true });
}
for (const dir of ['concepts', 'security', 'research']) {
  await rm(path.join(out, dir), { recursive: true, force: true });
}

for (const page of pages) {
  const text = await readFile(path.join(root, page.src), 'utf8');
  const { title, description, md } = transform(text, page);
  const front = [
    '---',
    `title: ${yaml(title)}`,
    description ? `description: ${yaml(description)}` : null,
    `editUrl: ${yaml(`${REPO}/edit/${BRANCH}/${page.src}`)}`,
    '---',
    '',
    `<!-- Generated from ${page.src} by website/scripts/sync-docs.mjs. Edit that file, not this one. -->`,
    '',
    '',
  ].filter((l) => l !== null);
  const target = path.join(out, `${page.slug}.md`);
  await mkdir(path.dirname(target), { recursive: true });
  await writeFile(target, `${front.join('\n')}${md}`);
}

console.log(`sync-docs: wrote ${pages.length} pages to src/content/docs`);
