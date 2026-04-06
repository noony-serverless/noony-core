'use strict';

const path = require('path');
const { copyTemplate, copyDirRecursive, TEMPLATES_DIR } = require('./utils');
const { patchAgentsMd } = require('./patch-agents-md');

const RULE_FILES = [
  'noony-middleware-ordering',
  'noony-error-handling',
  'noony-type-safety',
  'noony-testing',
  'noony-dependency-injection',
];

async function installClaude(cwd, config) {
  const dest = path.join(cwd, '.claude', 'agents', 'uncle-noony.md');
  return copyTemplate(path.join('claude', 'uncle-noony.md'), dest, config);
}

async function installClaudeRules(cwd, config) {
  const results = [];
  for (const name of RULE_FILES) {
    const dest = path.join(cwd, '.claude', 'rules', `${name}.md`);
    results.push(await copyTemplate(path.join('claude-rules', `${name}.md`), dest, config));
  }
  return results;
}

async function installCursor(cwd, config) {
  // Main routing/agent rule
  const dest = path.join(cwd, '.cursor', 'rules', 'noony-framework.mdc');
  const main = await copyTemplate(path.join('cursor', 'noony-framework.mdc'), dest, config);

  // Individual Noony rules
  const results = [main];
  for (const name of RULE_FILES) {
    const ruleDest = path.join(cwd, '.cursor', 'rules', `${name}.mdc`);
    results.push(await copyTemplate(path.join('cursor-rules', `${name}.mdc`), ruleDest, config));
  }
  return results;
}

async function installWindsurf(cwd, config) {
  const results = [];
  for (const name of RULE_FILES) {
    const dest = path.join(cwd, '.windsurf', 'rules', `${name}.md`);
    results.push(await copyTemplate(path.join('windsurf-rules', `${name}.md`), dest, config));
  }
  return results;
}

async function installOpenCode(cwd, config) {
  const dest = path.join(cwd, '.opencode', 'agents', 'uncle-noony.md');
  return copyTemplate(path.join('opencode', 'uncle-noony.md'), dest, config);
}

async function installCodex(cwd, config) {
  const dest = path.join(cwd, 'AGENTS.md');
  return patchAgentsMd(dest, config);
}

async function installCopilot(cwd, config) {
  const dest = path.join(cwd, '.github', 'copilot-instructions.md');
  return copyTemplate(path.join('github', 'copilot-instructions.md'), dest, config);
}

async function installSkills(cwd, config) {
  const srcDir = path.join(TEMPLATES_DIR, 'skills');
  const destDir = path.join(cwd, config.skillsDir);
  if (config.dryRun) {
    console.log(`[dry-run] would copy 16 skills to: ${destDir}`);
    return { action: 'dry-run' };
  }
  console.log(`\nInstalling skills → ${destDir}`);
  return copyDirRecursive(srcDir, destDir, config);
}

module.exports = {
  installClaude,
  installClaudeRules,
  installCursor,
  installWindsurf,
  installOpenCode,
  installCodex,
  installCopilot,
  installSkills,
};
