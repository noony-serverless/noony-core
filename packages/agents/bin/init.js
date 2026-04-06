#!/usr/bin/env node
'use strict';

const path = require('path');
const fs = require('fs');
const {
  installClaude,
  installClaudeRules,
  installCursor,
  installWindsurf,
  installOpenCode,
  installCodex,
  installCopilot,
  installSkills,
} = require('../lib/copy-agents');

const VERSION = require('../package.json').version;

const HELP = `
@noony-serverless/agents v${VERSION}

Install Uncle Noony + 16 skills + framework rules into your project.

Usage:
  npx @noony-serverless/agents init [options]

Platform flags (if none given, all are installed):
  --claude          Claude Code agent (.claude/agents/)
  --claude-rules    Claude Code rules (.claude/rules/)
  --cursor          Cursor agent rule + 5 framework rules (.cursor/rules/)
  --windsurf        Windsurf rules (.windsurf/rules/)
  --opencode        OpenCode agent (.opencode/agents/)
  --codex           AGENTS.md section (append/create)
  --copilot         GitHub Copilot (.github/copilot-instructions.md)
  --skills          Skill cards only (docs/noony-skills/)

Other options:
  --skills-dir=DIR  Skills destination (default: docs/noony-skills)
  --dry-run         Preview what would be written, no changes
  --force           Overwrite existing files without prompting
  --skip-existing   Skip files that already exist (no prompt)
  --help, -h        Show this help
  --version, -v     Show version

Examples:
  npx @noony-serverless/agents init
  npx @noony-serverless/agents init --dry-run
  npx @noony-serverless/agents init --cursor --claude
  npx @noony-serverless/agents init --force
  npx @noony-serverless/agents init --skills-dir=ai/noony-skills
`;

async function main() {
  const argv = process.argv.slice(2);

  if (argv.includes('--help') || argv.includes('-h')) {
    console.log(HELP);
    process.exit(0);
  }

  if (argv.includes('--version') || argv.includes('-v')) {
    console.log(VERSION);
    process.exit(0);
  }

  if (argv[0] !== 'init') {
    if (argv.length === 0) {
      console.log(HELP);
      process.exit(0);
    }
    console.error(`Unknown command: ${argv[0]}\nRun with --help for usage.`);
    process.exit(1);
  }

  const flags = argv.slice(1);
  const config = parseFlags(flags);
  const cwd = process.cwd();

  if (!fs.existsSync(path.join(cwd, 'package.json')) && !fs.existsSync(path.join(cwd, '.git'))) {
    console.warn(`\nWarning: No package.json or .git found in ${cwd}`);
    console.warn('Make sure you are running this from your project root.\n');
  }

  console.log(`\nNoony Agents v${VERSION} — installing into: ${cwd}`);
  if (config.dryRun) console.log('(dry-run mode — no files will be written)\n');
  else console.log('');

  const results = [];

  if (config.platforms.has('claude')) {
    console.log('→ Claude Code agent');
    results.push(await installClaude(cwd, config));
  }

  if (config.platforms.has('claude-rules')) {
    console.log('\n→ Claude Code rules');
    results.push(...[].concat(await installClaudeRules(cwd, config)));
  }

  if (config.platforms.has('cursor')) {
    console.log('\n→ Cursor (agent rule + framework rules)');
    results.push(...[].concat(await installCursor(cwd, config)));
  }

  if (config.platforms.has('windsurf')) {
    console.log('\n→ Windsurf rules');
    results.push(...[].concat(await installWindsurf(cwd, config)));
  }

  if (config.platforms.has('opencode')) {
    console.log('\n→ OpenCode agent');
    results.push(await installOpenCode(cwd, config));
  }

  if (config.platforms.has('codex')) {
    console.log('\n→ Codex / AGENTS.md');
    results.push(await installCodex(cwd, config));
  }

  if (config.platforms.has('copilot')) {
    console.log('\n→ GitHub Copilot');
    results.push(await installCopilot(cwd, config));
  }

  if (config.platforms.has('skills')) {
    results.push(...[].concat(await installSkills(cwd, config)));
  }

  printSummary(results, config);
}

function parseFlags(flags) {
  const known = new Set([
    'claude', 'claude-rules', 'cursor', 'windsurf',
    'opencode', 'codex', 'copilot', 'skills',
  ]);
  const selected = new Set();

  let dryRun = false;
  let force = false;
  let skipExisting = false;
  let skillsDir = 'docs/noony-skills';

  for (const flag of flags) {
    if (flag === '--dry-run') { dryRun = true; continue; }
    if (flag === '--force') { force = true; continue; }
    if (flag === '--skip-existing') { skipExisting = true; continue; }
    if (flag.startsWith('--skills-dir=')) {
      skillsDir = flag.slice('--skills-dir='.length);
      continue;
    }
    if (flag.startsWith('--') && known.has(flag.slice(2))) {
      selected.add(flag.slice(2));
      continue;
    }
    console.warn(`Unknown flag: ${flag} (ignored)`);
  }

  const platforms = selected.size > 0 ? selected : new Set([...known]);
  return { platforms, dryRun, force, skipExisting, skillsDir };
}

function printSummary(results, config) {
  if (config.dryRun) return;

  const counts = { written: 0, created: 0, updated: 0, appended: 0, skipped: 0 };
  for (const r of results.flat()) {
    if (r && r.action && counts[r.action] !== undefined) counts[r.action]++;
  }

  const installed = counts.written + counts.created + counts.updated + counts.appended;
  console.log('\n─────────────────────────────────────');
  console.log('Done.');
  if (installed > 0) console.log(`  ${installed} file(s) installed/updated`);
  if (counts.skipped > 0) console.log(`  ${counts.skipped} file(s) skipped (already exist)`);
  console.log('─────────────────────────────────────\n');
  console.log('Next steps:');
  console.log('  • Open your project in Claude Code, Cursor, Windsurf, OpenCode, or Codex');
  console.log('  • Ask about Noony — Uncle Noony and the framework rules will guide you\n');
}

main().catch((err) => {
  console.error('\nError:', err.message);
  process.exit(1);
});
