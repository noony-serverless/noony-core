'use strict';

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const TEMPLATES_DIR = path.join(__dirname, '..', 'templates');

function mkdirpSync(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

/**
 * Copy a single template file to a destination path.
 * Handles dry-run, force, skip-existing, and interactive conflict prompts.
 */
async function copyTemplate(templateRel, destAbs, config) {
  const src = path.join(TEMPLATES_DIR, templateRel);
  const { dryRun, force, skipExisting } = config;

  if (dryRun) {
    const exists = fs.existsSync(destAbs);
    console.log(`[dry-run] ${exists ? 'would overwrite' : 'would write'}: ${destAbs}`);
    return { action: 'dry-run' };
  }

  mkdirpSync(path.dirname(destAbs));

  if (fs.existsSync(destAbs)) {
    if (skipExisting) {
      console.log(`[skip]    ${destAbs}`);
      return { action: 'skipped' };
    }
    if (!force) {
      const overwrite = await promptConfirm(`File exists: ${destAbs}\n  Overwrite? [y/N] `);
      if (!overwrite) {
        console.log(`[skip]    ${destAbs}`);
        return { action: 'skipped' };
      }
    }
  }

  fs.copyFileSync(src, destAbs);
  console.log(`[✓]       ${destAbs}`);
  return { action: 'written' };
}

/**
 * Recursively copy all files from a source directory into a destination directory.
 */
async function copyDirRecursive(srcDir, destDir, config) {
  const results = [];
  const entries = walkDir(srcDir);
  for (const absFile of entries) {
    const rel = path.relative(srcDir, absFile);
    const dest = path.join(destDir, rel);
    const result = await copyTemplate(path.relative(TEMPLATES_DIR, absFile), dest, config);
    results.push({ file: rel, ...result });
  }
  return results;
}

/**
 * Recursively collect all file paths under a directory.
 */
function walkDir(dir) {
  const results = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...walkDir(fullPath));
    } else {
      results.push(fullPath);
    }
  }
  return results;
}

/**
 * Prompt user for yes/no confirmation via stdin.
 */
function promptConfirm(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase() === 'y');
    });
  });
}

module.exports = { mkdirpSync, copyTemplate, copyDirRecursive, walkDir, TEMPLATES_DIR };
