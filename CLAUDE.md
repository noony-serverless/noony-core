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

This is a **serverless middleware framework** for Google Cloud Functions that provides a Middy-like experience with full TypeScript support. The framework is designed to be framework-agnostic and supports both legacy GCP Functions and modern HTTP frameworks like Fastify and Express.

### Core Architecture Components

### 1. Handler System (`src/core/handler.ts`)
- **Handler class**: Manages middleware execution pipeline with `before`, `after`, and `onError` lifecycle hooks
- **BaseMiddleware interface**: Defines middleware contract with optional lifecycle methods
- **Fluent API**: Chain middlewares using `.use()` and define business logic with `.handle()`
- **Framework Agnostic**: Supports both legacy GCP Functions and generic HTTP frameworks via `execute()` and `executeGeneric()` methods

### 2. Context System (`src/core/core.ts`)
- **Context interface**: Enhanced with `requestId`, `startTime`, `timeoutSignal`, and `responseData` for better request tracking
- **GenericRequest/GenericResponse**: Framework-agnostic interfaces that work with any HTTP framework
- **Legacy Support**: CustomRequest/CustomResponse maintained for backward compatibility
- **Security Config**: Built-in security configurations for request processing
- **Dependency injection**: Uses TypeDI container for service management

### 3. Error System (`src/core/errors.ts`)
Built-in error classes with proper HTTP status codes:
- **HttpError**: Base error with custom status codes
- **ValidationError**: 400 - Input validation failures
- **AuthenticationError**: 401 - Authentication failures
- **SecurityError**: 403 - Security violations
- **TimeoutError**: 408 - Request timeouts
- **TooLargeError**: 413 - Request size limits
- **BusinessError**: Custom business logic errors

### 4. Middleware Ecosystem (`src/middlewares/`)
Built-in middlewares for common patterns:
- **errorHandlerMiddleware**: Centralized error handling with custom error types
- **bodyParserMiddleware**: JSON and Pub/Sub message parsing
- **bodyValidationMiddleware**: Zod schema validation with TypeScript integration
- **authenticationMiddleware**: JWT token verification
- **responseWrapperMiddleware**: Standardized response format
- **headerVariablesMiddleware**: Required header validation
- **queryParametersMiddleware**: Query string processing
- **dependencyInjectionMiddleware**: TypeDI container setup
- **httpAttributesMiddleware**: HTTP request attributes processing

### Framework Integration Patterns

The framework supports multiple execution patterns:

**GCP Functions (Legacy)**:
```typescript
export const myFunction = http('myFunction', (req, res) => {
  return handler.execute(req, res);
});
```

**Framework Agnostic**:
```typescript
// Works with Express, Fastify, etc.
await handler.executeGeneric(genericReq, genericRes);
```

### Key Framework Patterns

1. **Middleware Order Matters**: Execute `before` methods in order, `after` and `onError` in reverse order
2. **Type Safety**: Generics flow through Handler<T, U> for request/response typing
3. **Error Propagation**: Errors trigger `onError` handlers in reverse middleware order
4. **Shared State**: Use `context.businessData` Map to share data between middlewares
5. **Request Tracking**: Each request gets a unique `requestId` and timing information

### Example Usage Pattern
```typescript
const handler = new Handler<RequestType, UserType>()
  .use(new ErrorHandlerMiddleware())        // Always first
  .use(new HeaderVariablesMiddleware([...]))
  .use(new AuthenticationMiddleware(verify))
  .use(new BodyParserMiddleware())          
  .use(new BodyValidationMiddleware(schema))
  .use(new DependencyInjectionMiddleware([...]))
  .use(new ResponseWrapperMiddleware())     // Always last
  .handle(async (context) => {
    // Business logic here - fully typed context
    const { validatedBody } = context.req; // Type: RequestType
    const { userId } = context.user!;      // Type: UserType
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
- **axios**: HTTP client for external API calls
- **fastify**: Optional Fastify integration support