'use strict';

const fs = require('fs');
const path = require('path');
const { TEMPLATES_DIR } = require('./utils');

const SENTINEL_START = '<!-- noony-agents:start -->';
const SENTINEL_END = '<!-- noony-agents:end -->';

/**
 * Insert or update the Noony Skill System section in the consumer's AGENTS.md.
 *
 * Three cases:
 *   1. No AGENTS.md → create with Noony section only
 *   2. AGENTS.md has sentinel markers → update section in place (idempotent)
 *   3. AGENTS.md exists but no sentinel → append with separator
 */
async function patchAgentsMd(destPath, config) {
  const { dryRun, force } = config;

  const sectionContent = fs.readFileSync(
    path.join(TEMPLATES_DIR, 'agents-md-section.md'),
    'utf8'
  );
  const wrappedSection = `${SENTINEL_START}\n${sectionContent.trimEnd()}\n${SENTINEL_END}`;

  // Case 1: file doesn't exist
  if (!fs.existsSync(destPath)) {
    if (dryRun) {
      console.log(`[dry-run] would create: ${destPath}`);
      return { action: 'dry-run' };
    }
    fs.writeFileSync(destPath, wrappedSection + '\n');
    console.log(`[✓]       created ${destPath}`);
    return { action: 'created' };
  }

  const existing = fs.readFileSync(destPath, 'utf8');

  // Case 2: sentinel already present
  if (existing.includes(SENTINEL_START)) {
    if (!force) {
      console.log(`[skip]    ${destPath} (Noony section already present — use --force to update)`);
      return { action: 'skipped' };
    }
    if (dryRun) {
      console.log(`[dry-run] would update Noony section in: ${destPath}`);
      return { action: 'dry-run' };
    }
    const sentinelRegex = new RegExp(
      `${escapeRegex(SENTINEL_START)}[\\s\\S]*?${escapeRegex(SENTINEL_END)}`,
      'g'
    );
    const updated = existing.replace(sentinelRegex, wrappedSection);
    fs.writeFileSync(destPath, updated);
    console.log(`[✓]       updated Noony section in ${destPath}`);
    return { action: 'updated' };
  }

  // Case 3: file exists, no sentinel — append
  if (dryRun) {
    console.log(`[dry-run] would append Noony section to: ${destPath}`);
    return { action: 'dry-run' };
  }
  const separator = existing.trimEnd().endsWith('---') ? '\n\n' : '\n\n---\n\n';
  fs.appendFileSync(destPath, separator + wrappedSection + '\n');
  console.log(`[~]       appended Noony section to ${destPath}`);
  return { action: 'appended' };
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

module.exports = { patchAgentsMd };
