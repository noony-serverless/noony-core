# Task Plan

## Rename Noony skill names with `noony-` prefix

- [x] What: Update every Noony skill card `name:` field and `# skill:` identifier to add the `noony-` prefix.
  Why: Skill invocation names should consistently use the Noony namespace without changing skill file locations.
  How: Edit each `docs/skills/*/SKILL.md` card in place, preserving existing paths and structure.
  Success criteria: Every Noony skill card declares a `name:` and `# skill:` value starting with `noony-`.

- [x] What: Update all references to those skill names in docs and between skills.
  Why: Cross-links, examples, and guidance need to match the new invocation names.
  How: Replace human-readable and code-style skill references across `docs/` and related repo content, while keeping links and directory names unchanged.
  Success criteria: Repo searches no longer find old bare skill names used as skill identifiers or references.

- [x] What: Verify the rename and document the outcome.
  Why: Completion should be backed by concrete checks, not assumption.
  How: Run targeted `rg` searches for old and new skill-name patterns and review the diff for accidental path changes.
  Success criteria: Verification shows expected `noony-` prefixes and no unintended file renames.

## Review

- Updated all 16 Noony skill cards under `docs/skills/*/SKILL.md` so their `name:` and `# skill:` identifiers now use the `noony-` prefix.
- Updated cross-skill references in the skill cards, the skills index, and the uncle-noony workflow docs to use the new prefixed skill names while keeping existing directory names and markdown link targets unchanged.
- Restored adopter-template file references and markdown anchor fragments that should continue pointing at unchanged filenames/headings.
- Verification:
  - `rg -n "noony-noony|noony-auth-guards|auth-guards|references/.+#.*noony-|docs/skills/[0-9]+-noony-" docs/skills docs/meta` returned no matches.
  - Targeted regex checks found only expected unchanged filenames/headings in references, not unprefixed skill invocation names to rename.
