# API Reference

---

## Handler\<TBody, TUser\>

Central request pipeline orchestrator. Every API endpoint maps to one `Handler` instance.

```typescript
class Handler<T = unknown, U = unknown>
```

| Generic        | Default   | Description                            |
| -------------- | --------- | -------------------------------------- |
| `T` (`TBody`)  | `unknown` | Type of the validated request body     |
| `U` (`TUser`)  | `unknown` | Type of the authenticated user         |

### Methods

#### `.use(middleware)`

Appends a middleware to the pipeline. Returns a new `Handler` with the same generics, enabling fluent chaining.

```typescript
use<NewT = T, NewU = U>(middleware: BaseMiddleware<NewT, NewU>): Handler<NewT, NewU>
```

#### `.handle(controller)`

Sets the terminal controller function. Must be called exactly once, after all `.use()` calls.

```typescript
handle(fn: (context: Context<T, U>) => Promise<void>): Handler<T, U>
```

#### `.execute(req, res)`

Executes the pipeline against a raw Express/GCP `Request` and `Response`. Used in Cloud Functions entry points.

```typescript
execute(req: Request, res: Response): Promise<void>
```

#### `.executeGeneric(req, res)`

Executes the pipeline against framework-agnostic `GenericRequest` and `GenericResponse`. Used in Fastify integration via `createFastifyHandler()`.

```typescript
executeGeneric(req: GenericRequest<T>, res: GenericResponse): Promise<void>
```

---

## Context\<TBody, TUser\>

Immutable state carrier passed to every middleware `before`, `after`, `onError` hook and to the controller.

```typescript
interface Context<T = unknown, V = unknown>
```

### Properties

| Property            | Type                                              | Description                                               |
| ------------------- | ------------------------------------------------- | --------------------------------------------------------- |
| `req`               | `GenericRequest<T>`                               | Request object with typed body                            |
| `req.body`          | `unknown`                                         | Raw unparsed request body                                 |
| `req.parsedBody`    | `T \| undefined`                                  | Validated body set by validation middleware               |
| `req.validatedBody` | `T \| undefined`                                  | Alias for `parsedBody`                                    |
| `req.params`        | `Record<string, string>`                          | URL path parameters                                       |
| `req.headers`       | `Record<string, string \| string[] \| undefined>` | Request headers                                           |
| `req.query`         | `Record<string, string \| string[] \| undefined>` | Query string parameters                                   |
| `req.ip`            | `string`                                          | Client IP address                                         |
| `req.method`        | `string`                                          | HTTP method                                               |
| `req.path`          | `string`                                          | Route path (e.g. `/api/users/:id`)                        |
| `req.userAgent`     | `string \| undefined`                             | `User-Agent` header value                                 |
| `res`               | `GenericResponse`                                 | Framework-agnostic response object                        |
| `user`              | `V \| undefined`                                  | Authenticated user; populated by auth middleware          |
| `container`         | `ContainerInstance`                               | Hybrid proxy DI container                                 |
| `businessData`      | `Map<string, unknown>`                            | Shared data bag for passing state between middleware      |
| `requestId`         | `string`                                          | Unique per-request identifier                             |
| `startTime`         | `number`                                          | Unix timestamp (ms) when the request entered the pipeline |
| `error`             | `Error \| null \| undefined`                      | Current error if set                                      |
| `timeoutSignal`     | `AbortSignal \| undefined`                        | Optional abort signal for request timeout                 |
| `responseData`      | `unknown`                                         | Set by `ResponseWrapperMiddleware`                        |

### GenericResponse methods

| Method        | Signature                                              | Description                             |
| ------------- | ------------------------------------------------------ | --------------------------------------- |
| `status`      | `(code: number) => GenericResponse`                    | Set HTTP status code; chainable         |
| `json`        | `(data: unknown) => void`                              | Send JSON-encoded response              |
| `send`        | `(data: unknown) => void`                              | Send raw response                       |
| `header`      | `(name: string, value: string) => GenericResponse`     | Set a single response header; chainable |
| `headers`     | `(headers: Record<string, string>) => GenericResponse` | Set multiple headers; chainable         |
| `end`         | `() => void`                                           | End the response with no body           |
| `headersSent` | `boolean`                                              | Whether headers have already been sent  |

---

## BaseMiddleware\<TBody, TUser\>

Interface implemented by all middleware classes.

```typescript
interface BaseMiddleware<T = unknown, U = unknown> {
  before?(context: Context<T, U>): Promise<void>;
  after?(context: Context<T, U>): Promise<void>;
  onError?(error: Error, context: Context<T, U>): Promise<void>;
}
```

All three methods are optional. A middleware that only needs to run before the controller implements `before` alone.

Custom middleware must carry the same generics as the handler it is used in:

```typescript
class MyMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser> {
  async before(context: Context<TBody, TUser>): Promise<void> { ... }
}
```

---

## Built-in Middleware

### ErrorHandlerMiddleware\<TBody, TUser\>

Catches all errors thrown by subsequent middleware or the controller and maps them to HTTP responses.

```typescript
class ErrorHandlerMiddleware<T = unknown, U = unknown>
  implements BaseMiddleware<T, U>
```

Must be registered **first** in the chain. Implements `onError`.

Legacy factory alias: `errorHandler()` — returns `new ErrorHandlerMiddleware()`.

### BodyValidationMiddleware\<TBody\>

Validates `context.req.body` against a Zod schema. On success, populates `context.req.parsedBody` and `context.req.validatedBody`. On failure, responds with 400 and Zod error details.

```typescript
class BodyValidationMiddleware<T> implements BaseMiddleware<T> {
  constructor(schema: ZodTypeAny)
}
```

Factory alias: `bodyValidator<T>(schema: ZodTypeAny): BaseMiddleware<T>`.

### ResponseWrapperMiddleware\<TResponse, TBody, TUser\>

Wraps successful responses in a standard envelope: `{ success: true, data: T }`.

```typescript
class ResponseWrapperMiddleware<TResponse = unknown, TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
```

Must be registered **last** in the chain (before `.handle()`). Implements `after`.

### AuthenticationMiddleware

Extracts a Bearer JWT from the `Authorization` header, validates it, and populates `context.user`. Does not enforce authentication — a missing or invalid token is silently ignored, leaving `context.user` undefined.

```typescript
class AuthenticationMiddleware implements BaseMiddleware
```

Use `RequireAuthMiddleware` after this to enforce that a user is present.

### RequireAuthMiddleware

Responds with `401` if `context.user` is undefined. Must be placed after `AuthenticationMiddleware`.

```typescript
class RequireAuthMiddleware implements BaseMiddleware
```

Factory alias: `requireAuth(): BaseMiddleware`.

### RequirePermissionMiddleware

Responds with `403` if the authenticated user does not have the specified permission string in their `permissions` array. Responds with `401` if no user is set.

```typescript
class RequirePermissionMiddleware implements BaseMiddleware {
  constructor(permission: string)
}
```

Factory alias: `requirePermission(permission: string): BaseMiddleware`.

---

## BaseAuthenticatedUser

Base interface for user types. Extend this when defining your application's user shape.

```typescript
interface BaseAuthenticatedUser {
  sub: string;
  iat: number;
  exp: number;
}
```

---

## Error Classes

All error classes extend `HttpError`. `ErrorHandlerMiddleware` maps each to its HTTP status code automatically.

| Class                | Status | Code                   |
| -------------------- | ------ | ---------------------- |
| `ValidationError`    | 400    | `VALIDATION_ERROR`     |
| `UnauthorizedError`  | 401    | `UNAUTHORIZED`         |
| `ForbiddenError`     | 403    | `FORBIDDEN`            |
| `NotFoundError`      | 404    | `NOT_FOUND`            |
| `ConflictError`      | 409    | `CONFLICT`             |
| `InternalServerError`| 500    | `INTERNAL_SERVER_ERROR`|
| `HttpError`          | custom | custom                 |

```typescript
import { NotFoundError, ValidationError, HttpError } from '@noony-serverless/core';

throw new NotFoundError('User not found');
throw new ValidationError('Invalid input', { field: 'email', reason: 'invalid format' });
throw new HttpError(418, "I'm a teapot", 'TEAPOT_ERROR');
```

Error response envelope (produced by `ErrorHandlerMiddleware`):

```typescript
{
  success: false,
  error: {
    message: string,
    code: string,
    details?: unknown
  }
}
```

---

## Utility Functions

### `getService(context, ServiceClass)`

Resolves a service from the request's DI container without manual casting.

```typescript
function getService<T>(context: Context, ServiceClass: Constructor<T>): T
```

```typescript
const orderService = getService(context, OrderService); // Type: OrderService
```

### `asBoolean(value)`

Parses a query parameter string to `boolean`. Returns `undefined` for absent values.

```typescript
function asBoolean(value: string | string[] | undefined): boolean | undefined
```

### `asNumber(value)`

Parses a query parameter string to `number`. Returns `undefined` for absent or non-numeric values.

```typescript
function asNumber(value: string | string[] | undefined): number | undefined
```

### `asString(value)`

Normalises a query parameter that may be `string | string[]` to `string | undefined`.

```typescript
function asString(value: string | string[] | undefined): string | undefined
```

---

## Framework Adapters

### `createFastifyHandler(noonyHandler, functionName, initializeDependencies)`

Primary function for integrating a Noony handler with a Fastify route. Handles request/response adaptation, dependency initialization, and error formatting.

```typescript
function createFastifyHandler(
  noonyHandler: Handler<unknown>,
  functionName: string,
  initializeDependencies: () => Promise<void>
): (req: FastifyRequest, reply: FastifyReply) => Promise<void>
```

| Parameter                | Type                  | Description                                  |
| ------------------------ | --------------------- | -------------------------------------------- |
| `noonyHandler`           | `Handler<unknown>`    | Handler with fully composed middleware chain |
| `functionName`           | `string`              | Name used in error logs                      |
| `initializeDependencies` | `() => Promise<void>` | Singleton initialization function            |

### `adaptFastifyRequest<T>(req)`

Converts a Fastify `FastifyRequest` to `GenericRequest<T>`. Called internally by `createFastifyHandler()`.

```typescript
function adaptFastifyRequest<T>(req: FastifyRequest): GenericRequest<T>
```

### `adaptFastifyResponse(reply)`

Converts a Fastify `FastifyReply` to `GenericResponse`. Called internally by `createFastifyHandler()`.

```typescript
function adaptFastifyResponse(reply: FastifyReply): GenericResponse
```

### `createHttpFunction(noonyHandler, functionName, initializeDependencies)`

Wraps a Noony handler into a GCP `HttpFunction`. An equivalent pattern is commonly implemented inline in `src/functions.ts`.

```typescript
function createHttpFunction(
  noonyHandler: Handler<unknown>,
  functionName: string,
  initializeDependencies: () => Promise<void>
): HttpFunction
```

---

## Middleware execution order reference

| Position         | Middleware                                             | Hook                                         |
| ---------------- | ------------------------------------------------------ | -------------------------------------------- |
| 1st (outermost)  | `ErrorHandlerMiddleware`                               | `before` then `onError` (catches everything) |
| 2nd              | `AuthenticationMiddleware`                             | `before` (populates `context.user`)          |
| 3rd              | `RequireAuthMiddleware` / `RequirePermissionMiddleware`| `before` (enforces auth)                     |
| 4th              | `BodyValidationMiddleware`                             | `before` (populates `validatedBody`)         |
| Last (innermost) | `ResponseWrapperMiddleware`                            | `after` (wraps response)                     |
| —                | `.handle(controller)`                                  | —                                            |
