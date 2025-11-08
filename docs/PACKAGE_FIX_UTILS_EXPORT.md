# Package Fix: Missing Utils Export

## Problem

When importing from `@noony-serverless/core`, users encountered this runtime error:

```
Error: Cannot find module './utils'
    at Function.Module._resolveFilename (internal/modules/cjs/loader.js:...)
    at Function.Module._load (internal/modules/cjs/loader.js:...)
```

The package's main entry point (`node_modules/@noony-serverless/core/build/index.js`) contains:
```javascript
__exportStar(require("./utils"), exports);
```

However, the `utils` module files were not being included in the published npm package.

## Root Cause

The `package.json` file's `"files"` array was missing the utils directory:

```json
"files": [
  "build/core/**/*.js",
  "build/core/**/*.d.ts",
  "build/middlewares/**/*.js",
  "build/middlewares/**/*.d.ts",
  "build/index.js",
  "build/index.d.ts",
  "README.md"
]
```

## Solution

Added the missing utils directory to the `"files"` array in `package.json`:

```json
"files": [
  "build/core/**/*.js",
  "build/core/**/*.d.ts",
  "build/middlewares/**/*.js",
  "build/middlewares/**/*.d.ts",
  "build/utils/**/*.js",           // ✅ ADDED
  "build/utils/**/*.d.ts",          // ✅ ADDED
  "build/index.js",
  "build/index.d.ts",
  "README.md"
]
```

## Verification

After the fix, the package now correctly includes all utils files:

```bash
npm pack --dry-run | grep "build/utils"
```

Output:
```
npm notice 1.0kB build/utils/container.utils.d.ts
npm notice 1.2kB build/utils/container.utils.js
npm notice 212B build/utils/index.d.ts
npm notice 1.1kB build/utils/index.js
npm notice 2.4kB build/utils/query-param.utils.d.ts
npm notice 2.9kB build/utils/query-param.utils.js
```

## Utils Available for Export

The utils module provides the following utilities:

### Container Utilities
- `getService<T>(context: Context, serviceClass: ServiceIdentifier<T>): T` - Type-safe service resolution from DI container

### Query Parameter Utilities
- `asString(value: string | string[] | undefined): string | undefined` - Convert to single string
- `asStringArray(value: string | string[] | undefined): string[] | undefined` - Convert to string array
- `asNumber(value: string | string[] | undefined): number | undefined` - Parse to number
- `asBoolean(value: string | string[] | undefined): boolean | undefined` - Parse to boolean

## Usage Example

```typescript
import {
  getService,
  asString,
  asNumber,
  asBoolean,
  asStringArray
} from '@noony-serverless/core';

// Query parameter parsing
export async function listUsersController(context: Context) {
  const query = context.req.query;

  const options = {
    search: asString(query.search),
    page: asNumber(query.page) || 1,
    limit: asNumber(query.limit) || 10,
    active: asBoolean(query.active),
    tags: asStringArray(query.tags),
  };

  const users = await service.listUsers(options);
  return { data: users };
}

// Service resolution
export async function createUserController(context: Context<CreateUserRequest>) {
  const userService = getService(context, UserService);
  const user = await userService.createUser(context.req.parsedBody);
  return { data: user };
}
```

## Impact

This fix ensures that:
1. ✅ All utility functions are available when importing from `@noony-serverless/core`
2. ✅ No runtime errors occur due to missing modules
3. ✅ TypeScript definitions are properly included
4. ✅ Full API surface is accessible to package consumers

## Version

Fixed in version: **0.3.2**

---

**Date:** 2025-11-05
**Author:** Claude Code (Anthropic)
**Issue Type:** Package Distribution / npm files configuration
