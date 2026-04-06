# Platform Sync Guide

Canonical source of truth for all Noony skills: `docs/skills/`

This file documents how skills are surfaced across AI coding tools and what to update when the skill system changes.

---

## Platform File Map

| Platform | Entry Point | Content Strategy | Can Read External Files? |
|----------|-------------|------------------|--------------------------|
| Claude Code | `.claude/agents/uncle-noony.md` | Self-contained agent with inlined dispatch table | Yes (tools: Read, Glob, Grep) |
| Cursor | `.cursor/rules/noony-framework.mdc` | Inlined router + core rules + skill path table | **No** — text must be inlined |
| OpenAI Codex | `AGENTS.md` (Noony Skill System section) | Compact list + file pointers; Codex reads SKILL.md on demand | Yes |
| OpenCode | `.opencode/agents/uncle-noony.md` | Identity card + explicit Read instructions for canonical files | Yes |

---

## When Adding a New Skill

Follow this checklist every time a new skill is added to `docs/skills/`:

### Required (canonical)

- [ ] Create `docs/skills/<new-skill-name>/SKILL.md` with frontmatter `name` and `description`
- [ ] Create `docs/skills/<new-skill-name>/references/` with at least one reference doc
- [ ] Add a row to the dispatch table in `docs/skills/uncle-noony/SKILL.md`
- [ ] Add a row to the skill router table in `docs/skills/README.md`

### Platform updates

- [ ] **`.cursor/rules/noony-framework.mdc`** — add one row to the Skill Reference Paths table AND one `if/then` routing rule in the "If/Then Routing" section *(manual sync required — Cursor cannot read external files)*
- [ ] **`AGENTS.md`** — add one bullet to the `### Skill List` section
- [ ] **`.claude/agents/uncle-noony.md`** — add one row to the Quick Dispatch Table
- [ ] **`.opencode/agents/uncle-noony.md`** — add one row to the Quick Dispatch table *(if the dispatch table is included; if the file only instructs `Read docs/skills/uncle-noony/SKILL.md`, no update needed)*

---

## Sync Burden by Platform

| Platform file | Sync required on new skill? | What to update |
|--------------|--------------------------|----------------|
| `.cursor/rules/noony-framework.mdc` | **Yes — manual** | Skill Reference Paths table + If/Then Routing rule |
| `AGENTS.md` | Yes — one bullet | `### Skill List` section |
| `.claude/agents/uncle-noony.md` | Yes — one row | Quick Dispatch Table |
| `.opencode/agents/uncle-noony.md` | Only if dispatch table is inlined | Quick Dispatch table row |
| `docs/skills/README.md` | Yes — one row | Skill Router table |
| `docs/skills/uncle-noony/SKILL.md` | Yes — one row | Quick Dispatch Table |

---

## Content Ownership

### Files that must stay in sync with each other

- `docs/skills/README.md` (router table) ↔ `.cursor/rules/noony-framework.mdc` (If/Then routing + Skill Reference Paths)
- `docs/skills/uncle-noony/SKILL.md` (dispatch table) ↔ `.claude/agents/uncle-noony.md` (Quick Dispatch Table)
- `AGENTS.md` skill list ↔ `docs/skills/README.md` skill router table (same 16 skills)

### Files that are fully DRY (no sync needed)

- `.opencode/agents/uncle-noony.md` — instructs the model to `Read` canonical files dynamically
- All `docs/skills/*/SKILL.md` files — single source of truth
- All `docs/skills/*/references/*.md` files — single source of truth

---

## Adding a New Platform

To add support for a new AI coding tool (e.g., Windsurf, Copilot Workspace):

1. Check if the platform can read external files at runtime
   - **Yes** → create a compact entry-point file that points to `docs/skills/uncle-noony/SKILL.md` and `docs/skills/README.md`
   - **No** → inline the content from `docs/skills/README.md` (Stricter + Router+Workflow blocks) plus the Core Rules block
2. Include the Noony Core Rules block (middleware ordering, error handling, type safety, forbidden patterns) in the platform file
3. Add the new platform to the Platform File Map table above
4. Add a row to the "Sync required on new skill?" table above

---

## Core Rules Reference

The following rules must appear in every platform file. They are the most important Noony invariants:

**Middleware ordering**: `ErrorHandlerMiddleware` first, `ResponseWrapperMiddleware` last, `before` runs 0→N, `after`/`onError` runs N→0.

**Error handling**: Always throw typed errors (`ValidationError`, `UnauthorizedError`, `ForbiddenError`, `NotFoundError`, `ConflictError`, `InternalServerError`). Never `throw new Error()`. Never `context.res.status().json()`.

**Type safety**: Preserve `<TBody, TUser>` through every layer. All middleware implements `BaseMiddleware<TBody, TUser>`. Never `as any`.

**Forbidden**: `ErrorHandlerMiddleware` not at position 1 · `ResponseWrapperMiddleware` not last · double-send · `throw new Error()` · `as any` · `Container.set()`/`Container.reset()` in production · `@fastify/otel`.
