# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

- **Build**: `npm run build` - Compiles TypeScript to build/ directory and copies package.json
- **Watch**: `npm run watch` - Continuous TypeScript compilation with watch mode
- **Test**: `npm run test` - Run all Jest tests
- **Test with Coverage**: `npm run test:coverage` - Run tests with coverage report
- **Lint**: `npm run lint` - ESLint check for TypeScript files
- **Lint Fix**: `npm run lint:fix` - ESLint with auto-fix
- **Format**: `npm run format` - Prettier formatting for TypeScript, JS, JSON files
- **Format Check**: `npm run format:check` - Check formatting without fixing

## Architecture Overview

This is a **serverless middleware framework** for Google Cloud Functions that provides a Middy-like experience with full TypeScript support. The framework centers around three core concepts:

### 1. Handler System (`src/core/handler.ts`)
- **Handler class**: Manages middleware execution pipeline with `before`, `after`, and `onError` lifecycle hooks
- **BaseMiddleware interface**: Defines middleware contract with optional lifecycle methods
- **Fluent API**: Chain middlewares using `.use()` and define business logic with `.handle()`

### 2. Context System (`src/core/core.ts`)
- **Context interface**: Contains `req`, `res`, `container`, `error`, `businessData`, and `user` properties
- **CustomRequest**: Extends GCP Functions Request with `parsedBody` and `validatedBody` properties
- **Dependency injection**: Uses TypeDI container for service management

### 3. Middleware Ecosystem (`src/middlewares/`)
Built-in middlewares for common patterns:
- **errorHandlerMiddleware**: Centralized error handling with custom error types
- **bodyParserMiddleware**: JSON and Pub/Sub message parsing
- **bodyValidationMiddleware**: Zod schema validation
- **authenticationMiddleware**: JWT token verification
- **responseWrapperMiddleware**: Standardized response format
- **headerVariablesMiddleware**: Required header validation
- **queryParametersMiddleware**: Query string processing

### Key Framework Patterns

1. **Middleware Order Matters**: Execute `before` methods in order, `after` and `onError` in reverse order
2. **Type Safety**: Generics flow through Handler<T, U> for request/response typing
3. **Error Propagation**: Errors trigger `onError` handlers in reverse middleware order
4. **Shared State**: Use `context.businessData` Map to share data between middlewares

### Example Usage Pattern
```typescript
const handler = new Handler()
  .use(errorHandler())          // Always first
  .use(bodyParser())           // Parse requests
  .use(bodyValidator(schema))  // Validate data
  .use(authentication(verify)) // Auth if needed
  .use(responseWrapper())      // Always last
  .handle(async (context) => {
    // Business logic here
  });
```

## Testing
- Tests use Jest with ts-jest preset
- All `*.test.ts` files in src/ are automatically discovered
- Coverage excludes index.ts files and test files
- Path mapping: `@/` maps to `src/`

## Key Dependencies
- **@google-cloud/functions-framework**: Core GCP Functions runtime
- **zod**: Schema validation
- **typedi**: Dependency injection
- **jsonwebtoken**: JWT handling
- **firebase-admin**: Firebase integration