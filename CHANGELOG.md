# Changelog

All notable changes to the Noony Serverless Core framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.9.1] - 2026-03-17 - Documentation Overhaul

### 📝 Documentation

- **Complete Diataxis restructure**: Reorganized 46 doc files into 4 categories:
  - `docs/tutorials/` — 4 sequential learning guides (getting started, auth, Fastify, testing)
  - `docs/guides/` — 10 task-oriented how-to guides (error handling, custom middleware, DI, validation, performance, Pub/Sub, troubleshooting, etc.)
  - `docs/reference/` — 25 lookup docs (API, errors, telemetry, 15 middleware references, 6 auth references)
  - `docs/explanation/` — 3 architecture deep-dives (pipeline, container model, design patterns)
- **All 15 middlewares now documented**: Previously 8 of 15 had no reference docs. New: authentication, opentelemetry, security-headers, rate-limiting, response-wrapper, http-attributes, processing, security-audit, validation, error-handler
- **New `docs/INDEX.md`**: Site map with 4 audience reading paths (new adopter, feature builder, production readiness, contributor)
- **New error reference** (`docs/reference/errors.md`): Complete error class hierarchy with 12 classes, status codes, and usage examples
- **New telemetry reference** (`docs/reference/telemetry.md`): OpenTelemetry providers, presets, environment variables, GCP Cloud Trace integration

### 🛠 Skills (agentskills.so Standard)

- **Restructured all 16 skills** to follow the [Agent Skills](https://agentskills.io) open standard:
  - Directory-based format: `skill-name/SKILL.md` + `references/`
  - YAML frontmatter with `name` (kebab-case) and `description`
  - Progressive disclosure: SKILL.md < 130 lines, references < 500 lines
- **New `uncle-noony` orchestrator skill**: Central mentor that diagnoses developer needs and routes to the right skill sequence via 11 guided journeys
- **Cross-reference network**: All skills reference each other by kebab-case name with explicit "Do not use this skill when" sections
- **Skill clusters**: Framework Setup (4), Type Safety (2), Request Pipeline (4), Data & Auth (4), Quality (1)
- **Resolved skill 05/13 overlap**: `dependency-initialization` = focused init pattern, `performance-optimization` = broader optimization including init

### 🔧 Changed

- Updated `CLAUDE.md` with all new documentation paths
- Removed old flat doc files (`00-getting-started.md`, `01-handler-guide.md`, `02-api-reference.md`, `03-container-architecture.md`)
- Removed old `docs/middlewares/` and `docs/auth/` directories (content moved to `docs/reference/`)
- Removed old flat skill files and `docs/skills/resources/` (replaced by directory-based skills)

---

## [0.9.0] - 2026-03-11 - Performance Patterns & Code Quality

### ✨ Added

- **New source files**:
  - `src/core/constants.ts` — Centralized HTTP error codes, size limits, cache TTLs, and telemetry configuration constants
  - `src/core/error-categorizer.ts` — Standardized error categorization for ErrorHandlerMiddleware (DATABASE_ERROR, TIMEOUT_ERROR, EXTERNAL_SERVICE_ERROR, INTERNAL_ERROR)
  - `src/core/telemetry/base-provider.ts` — Abstract base class for telemetry providers (OpenTelemetry, Console, Noop)
  - `src/utils/http-wrapper-base.ts` — Shared error handling logic across framework adapters (GCP, Express, Fastify)
- **Performance optimization patterns documentation**:
  - Singleton initialization guard (three-condition pattern)
  - Lazy vs eager initialization strategies
  - Cold start and warm start analysis with benchmarks
- **Testing patterns documentation**:
  - Full handler chain testing (integration)
  - Middleware isolation testing (unit)
  - DI service mocking patterns
  - Error path verification

### ⬆️ Updated

**Production Dependencies:**
- `@google-cloud/firestore`: ^8.2.0 → ^8.3.0
- `@google-cloud/pubsub`: ^5.2.2 → ^5.3.0
- `axios`: ^1.13.4 → ^1.13.6
- `fastify`: ^5.7.4 → ^5.8.2
- `firebase-admin`: ^13.6.0 → ^13.7.0
- `firebase-functions`: ^6.6.0 → ^7.1.1 ⚠️ **Major version bump**

### 🔧 Changed

- Improved error handling in `bodyParserMiddleware` with better error categorization
- Enhanced type definitions in `rateLimitingMiddleware`
- Code formatting and readability improvements across middleware files
- Added ESLint rule exceptions for `require()` imports in telemetry files (dynamic provider loading)
- Removed legacy backup files (`.bak` middleware files)
- Cleaned up old documentation files (release notes, integration plans, improvement docs)

### 📝 Documentation

- Reorganized documentation structure:
  - Renamed `HOW_USE_NOONY.md` → `docs/00-getting-started.md`
  - Renamed `Handler-Complete-Guide.md` → `docs/01-handler-guide.md`
  - Renamed `API-AGUIDE.md` → `docs/02-api-reference.md`
  - Renamed `IMPROVE_NOONY_CONTAINER.md` → `docs/03-container-architecture.md`
- Created `docs/auth/` folder with 6 auth guides (getting started, route guards, multi-auth, token validator, Firebase, OAuth2)
- Created `docs/middlewares/` folder with 8 middleware guides (overview, body parser, body validation, headers, query params, DI, integration, error handler)
- Created `docs/skills/` folder with 15 skill cards and 15 resource files
- Added `docs/meta/ADOPTER_CLAUDE_MD_TEMPLATE.md` for framework adopters

---

## [0.8.0] - 2026-02-04 - Security & Tooling

### 🔒 Security

- **CRITICAL**: Fixed Fastify DoS vulnerabilities (GHSA-jx2c-rxcm-jvmq, GHSA-mrq3-vjjr-p77c)
- **CRITICAL**: Fixed fast-xml-parser DoS vulnerability (GHSA-37qj-frw5-hhjh)
- **MODERATE**: Fixed ESLint stack overflow with circular references (GHSA-p5wg-g6qr-c7cg)
- Added security overrides for `fast-xml-parser@^5.3.4` and `lodash@^4.17.21`

**Production Security Status:** ✅ **0 vulnerabilities** (was 4 high + 1 moderate)

### ✨ Added

- New security audit scripts:
  - `npm run audit` — Check moderate+ vulnerabilities
  - `npm run audit:fix` — Auto-fix vulnerabilities
  - `npm run audit:production` — Check production dependencies only
- Created consolidated `CHANGELOG.md`
- Created `CHANGELOG-SECURITY-v0.7.1.md` with full security audit details

### ⬆️ Updated

**Production Dependencies:**
- `fastify`: 5.7.1 → 5.7.4 (security fix)
- `axios`: 1.11.0 → 1.13.4 (security + bug fixes)
- `zod`: 4.3.5 → 4.3.6 (bug fixes)

**Development Dependencies:**
- `eslint`: 8.57.1 → 9.39.2 ⚠️ **Breaking Change**
- `@typescript-eslint/eslint-plugin`: 6.21.0 → 8.54.0
- `@typescript-eslint/parser`: 6.21.0 → 8.54.0
- `eslint-config-prettier`: 9.1.2 → 10.1.8
- `@types/node`: 20.19.30 → 20.19.31
- `prettier`: 3.8.0 → 3.8.1
- Added: `globals@^17.3.0`

### 🔧 Changed

- **BREAKING**: Migrated ESLint from v8 to v9 with flat config format
- Replaced `.eslintrc.json` with `eslint.config.mjs`
- Removed deprecated `.eslintignore` file
- Improved ESLint configuration with separate rules for source, test, and example files

### 📊 Results

- **Before**: 5 vulnerabilities (4 high, 1 moderate)
- **After**: 0 production vulnerabilities
- **Tests**: ✅ All 571 tests passing
- **Build**: ✅ Successful

**📖 Full Details:** See [CHANGELOG-SECURITY-v0.7.1.md](CHANGELOG-SECURITY-v0.7.1.md)

---

## [0.7.0] - 2026-01-21 - Type Safety Release

### ✨ Added

- **Type-Safe Handlers**: Invariant generics `Handler<TBody, TUser>` eliminate need for `as any` casts
- **Dual Generics**: Full type safety for both request body (`TBody`) and authenticated user (`TUser`)
- **Type Inference**: New `createTypedHandler()` for automatic type inference from controller signature
- **BaseAuthenticatedUser**: Base interface for extending authenticated user types
- **730+ lines of type safety tests** covering invariant generics, type chain preservation, and edge cases

### 🔧 Changed

- **Context Interface**: Enhanced with dual generics `Context<TBody, TUser>`
- **All Middlewares**: Updated to preserve type chain with proper generics
- **Type Chain Preservation**: Fixed type erasure in middleware pipeline

### 🐛 Fixed

- Type safety issues in middleware chain
- Type erasure when using multiple middlewares
- Need for `as any` casts in handlers

### 📝 Documentation

- Complete migration guide from v0.6.x
- Updated all examples with type-safe patterns
- Added type safety best practices
- New example file: `examples/type-safety-v0.7.0.ts`

**📖 Full Details:** See [CHANGELOG-v0.7.0.md](CHANGELOG-v0.7.0.md)

---

## [0.6.0] - Previous Release

See Git history for earlier releases.

---

## Version Naming Convention

- **Major** (x.0.0): Breaking API changes, significant architectural changes
- **Minor** (0.x.0): New features, backward compatible
- **Patch** (0.0.x): Bug fixes, security patches, dependency updates

## Security Updates

Security vulnerabilities are treated with highest priority. Security patches may be released as:
- **Minor versions** if they include dependency updates with breaking changes
- **Patch versions** if they are backward compatible

Always check the `CHANGELOG-SECURITY-*.md` files for detailed security information.

---

## Links

- [Repository](https://github.com/noony-serverless/noony-core)
- [Issues](https://github.com/noony-serverless/noony-core/issues)
- [Security Policy](https://github.com/noony-serverless/noony-core/security/policy)
- [NPM Package](https://www.npmjs.com/package/@noony-serverless/core)

---

[0.9.1]: https://github.com/noony-serverless/noony-core/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/noony-serverless/noony-core/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/noony-serverless/noony-core/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/noony-serverless/noony-core/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/noony-serverless/noony-core/releases/tag/v0.6.0
