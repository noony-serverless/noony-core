# Changelog

All notable changes to the Noony Serverless Core framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.7.1] - 2026-02-04 - Security Update

### 🔒 Security

- **CRITICAL**: Fixed Fastify DoS vulnerabilities (GHSA-jx2c-rxcm-jvmq, GHSA-mrq3-vjjr-p77c)
- **CRITICAL**: Fixed fast-xml-parser DoS vulnerability (GHSA-37qj-frw5-hhjh)
- **MODERATE**: Fixed ESLint stack overflow with circular references (GHSA-p5wg-g6qr-c7cg)
- Added security overrides for `fast-xml-parser@^5.3.4` and `lodash@^4.17.21`

**Production Security Status:** ✅ **0 vulnerabilities**

### ✨ Added

- New security audit scripts:
  - `npm run audit` - Check moderate+ vulnerabilities
  - `npm run audit:fix` - Auto-fix vulnerabilities
  - `npm run audit:production` - Check production dependencies only

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
- **After**: 0 production vulnerabilities, 1 dev-only moderate (lodash, already latest version)
- **Tests**: ✅ All 571 tests passing
- **Build**: ✅ Successful

**📖 Full Details:** See [CHANGELOG-SECURITY-v0.7.1.md](CHANGELOG-SECURITY-v0.7.1.md)

---

## [0.7.0] - 2025-01-XX - Type Safety Release

### ✨ Added

- **Type-Safe Handlers**: Invariant generics `Handler<TBody, TUser>` eliminate need for `as any` casts
- **Dual Generics**: Full type safety for both request body (`TBody`) and authenticated user (`TUser`)
- **Type Inference**: New `createTypedHandler()` for automatic type inference from controller signature
- **BaseAuthenticatedUser**: Base interface for extending authenticated user types

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

[0.7.1]: https://github.com/noony-serverless/noony-core/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/noony-serverless/noony-core/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/noony-serverless/noony-core/releases/tag/v0.6.0
