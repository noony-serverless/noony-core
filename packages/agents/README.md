# @noony-serverless/agents

Install **Uncle Noony + 16 skills** into your Noony project — AI agents and rules for Claude Code, Cursor, OpenCode, and Codex in one command.

## Quick Start

```bash
npx @noony-serverless/agents init
```

That's it. Run this from your project root.

## What Gets Installed

| Destination | For |
|-------------|-----|
| `.claude/agents/uncle-noony.md` | Claude Code |
| `.cursor/rules/noony-framework.mdc` | Cursor |
| `.opencode/agents/uncle-noony.md` | OpenCode |
| `AGENTS.md` (Noony section appended/created) | OpenAI Codex |
| `docs/noony-skills/` (16 skill cards + references) | All platforms |

## What Is Uncle Noony?

Uncle Noony is an AI orchestrator that routes Noony framework questions to the right skill. Instead of asking your AI assistant generic questions and getting generic answers, you get Noony-specific guidance — middleware ordering, typed errors, DI setup, guards, testing patterns, and more.

The 16 skills cover every Noony concern:

| Skill | What it handles |
|-------|----------------|
| `noony-create-fastify-server` | Local Fastify dev setup |
| `noony-convert-cloud-functions-to-fastify` | Cloud Functions → Fastify migration |
| `noony-middleware-ordering` | Canonical middleware chain order |
| `noony-error-handling` | Typed errors and HTTP status codes |
| `noony-type-inference` | `<TBody, TUser>` generics and type chain |
| `noony-validation-schemas` | Zod validation patterns |
| `noony-dependency-injection` | TypeDI service resolution |
| `noony-dependency-initialization` | Singleton startup initialization |
| `noony-guard-system` | Auth, permissions, RBAC guards |
| `noony-middleware-development` | Custom middleware authoring |
| `noony-path-parameters` | Route params (`:id`, `:userId`) |
| `noony-complete-dual-entry` | Fastify + Cloud Functions production pattern |
| `noony-custom-adapter` | Adapters for Koa, Hapi, NestJS, etc. |
| `noony-performance-optimization` | Cold starts, memory, performance |
| `noony-testing-handlers` | Handler and middleware tests |
| `noony-uncle-noony` | Orchestrator — start here for broad questions |

## Options

```
npx @noony-serverless/agents init [options]

Platform filters (install one platform only):
  --claude          Claude Code agent
  --cursor          Cursor rule
  --opencode        OpenCode agent
  --codex           AGENTS.md section
  --skills          Skill cards only

Other options:
  --skills-dir=DIR  Skills destination (default: docs/noony-skills)
  --dry-run         Preview what would be written, no changes
  --force           Overwrite existing files without prompting
  --skip-existing   Silent skip for files that already exist
  --help, -h        Show help
  --version, -v     Show version
```

## Examples

```bash
# Install everything
npx @noony-serverless/agents init

# Preview first
npx @noony-serverless/agents init --dry-run

# Claude Code only
npx @noony-serverless/agents init --claude

# Update skills to latest version
npx @noony-serverless/agents init --skills --force

# Custom skills location
npx @noony-serverless/agents init --skills-dir=ai/noony-skills

# Re-run safely (skip existing files)
npx @noony-serverless/agents init --skip-existing
```

## Re-running

Safe to re-run. By default, existing files prompt for confirmation. Use `--skip-existing` to silently skip or `--force` to overwrite all.

The `AGENTS.md` section is idempotent — it uses sentinel markers to detect and update the Noony section without affecting the rest of your file.

## For Maintainers

### Syncing templates

Templates in `packages/agents/templates/` mirror the canonical files in the repo root. After updating any agent/rule/skill file, sync them:

```bash
npm run sync-templates -w packages/agents
```

### CI check

Add this to CI to catch template drift:

```bash
npm run sync-templates -w packages/agents
git diff --exit-code packages/agents/templates/
```

### Publishing

```bash
npm publish --workspace=packages/agents
```
