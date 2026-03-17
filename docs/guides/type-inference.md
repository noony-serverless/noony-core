# Type Inference

How generics flow through the Handler, middleware, and Context pipeline, and how to choose between explicit generics and automatic type inference with `createTypedHandler()`.

**Related links:** [Architecture](../explanation/architecture.md) | [Custom Middleware](./custom-middleware.md) | [Validation Schemas](./validation-schemas.md)

## Prerequisites

- Familiarity with TypeScript generics
- Understanding of the Noony Handler and middleware pipeline

---

## The Generic Type Chain

Every Noony handler carries two generic parameters:

- **`TBody`** -- The type of the validated request body.
- **`TUser`** -- The type of the authenticated user.

These generics flow through the entire pipeline:

```
Handler<TBody, TUser>
    |
    +-- Middleware.before(context: Context<TBody, TUser>)
    |
    +-- Controller(context: Context<TBody, TUser>)
    |
    +-- Middleware.after(context: Context<TBody, TUser>)
```

When every component in the chain uses both generics, `context.req.validatedBody` is typed as `TBody` and `context.user` is typed as `TUser`. Break the chain anywhere, and those types degrade to `unknown`.

## Two Approaches to Typed Handlers

Noony supports two approaches. Both provide full compile-time type safety. Choose based on your team's preference for verbosity vs brevity.

### Option 1: Explicit Generics

Specify the type parameters on the Handler and pass them through to every middleware. This approach is clear and explicit -- types are visible at the handler definition site.

```typescript
import { Handler, Context } from '@noony-serverless/core';
import { z } from 'zod';

const createUserSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email(),
  age: z.number().min(18).max(120),
  role: z.enum(['user', 'admin']).default('user')
});

type CreateUserRequest = z.infer<typeof createUserSchema>;

interface AuthenticatedUser {
  id: string;
  email: string;
  role: 'user' | 'admin';
}

const createUserHandler = new Handler<CreateUserRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware<CreateUserRequest, AuthenticatedUser>())
  .use(new BodyValidationMiddleware<CreateUserRequest, AuthenticatedUser>(createUserSchema))
  .use(new ResponseWrapperMiddleware<CreateUserRequest, AuthenticatedUser>())
  .handle(async (context: Context<CreateUserRequest, AuthenticatedUser>) => {
    const { name, email, age } = context.req.validatedBody!;
    const currentUser = context.user!;  // Type: AuthenticatedUser
    return { data: { name, email } };
  });
```

**When to use explicit generics:**
- Handler is defined before the controller function exists
- Controller has complex conditional type logic
- You want maximum clarity for code reviewers
- Teaching others the framework

### Option 2: Type Inference with createTypedHandler()

When the controller already has explicit type annotations, `createTypedHandler()` infers `TBody` and `TUser` from the controller's signature, eliminating the need to repeat generics on every middleware.

```typescript
import { createTypedHandler, Context } from '@noony-serverless/core';
import { z } from 'zod';

const createUserSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email(),
  age: z.number().min(18).max(120)
});

type CreateUserRequest = z.infer<typeof createUserSchema>;

interface AuthenticatedUser {
  id: string;
  email: string;
  role: 'user' | 'admin';
}

// Controller with explicit type annotation
async function createUserController(context: Context<CreateUserRequest, AuthenticatedUser>) {
  const { name, email, age } = context.req.validatedBody!;
  const user = context.user!;
  const newUser = await userService.create({ name, email, age });
  return { data: newUser };
}

// Types inferred from controller signature -- no generics on middlewares
const createUserHandler = createTypedHandler(createUserController)
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(createUserSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(createUserController);
```

**When to use type inference:**
- Controller already has explicit `Context<TBody, TUser>` annotation
- You want minimal boilerplate
- Building rapid prototypes
- Team is comfortable with TypeScript inference

## Comparison

| Aspect | Explicit Generics | Type Inference |
|--------|-------------------|---------------|
| Boilerplate | Higher (generics on Handler + every middleware) | Lower (inferred from controller) |
| Readability | Types visible at definition site | Cleaner code, types in controller |
| Flexibility | Works with partial types | Requires full type signature on controller |
| Best for | Complex types, planning phase | Standard CRUD handlers |
| Compile-time safety | Full | Full |

## Preserving the Type Chain in Custom Middleware

When you write custom middleware, always implement `BaseMiddleware<TBody, TUser>` with both generics. This is the most common source of broken type chains.

```typescript
// CORRECT -- type chain preserved
class CustomMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
{
  async before(context: Context<TBody, TUser>): Promise<void> {
    // Types flow correctly through chain
  }
}

// WRONG -- breaks type chain
class CustomMiddleware implements BaseMiddleware {
  async before(context: Context): Promise<void> {
    // TBody and TUser are lost!
  }
}
```

The default values `= unknown` on the generics allow the middleware to be used without explicit type parameters (e.g., `new CustomMiddleware()`) while still preserving the type chain when parameters are provided.

## Multiple Handlers Sharing Types

When several handlers share the same user type, define it once and reference it everywhere:

```typescript
type AuthUser = AuthenticatedUser;

// Inferred approach for standard handlers
const loginHandler = createTypedHandler(loginController)
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(loginSchema))
  .handle(loginController);

// Explicit approach for handlers with complex middleware chains
const getUserHandler = new Handler<void, AuthUser>()
  .use(new ErrorHandlerMiddleware<void, AuthUser>())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .handle(async (context: Context<void, AuthUser>) => {
    const user = await userService.getById(context.user!.id);
    return { data: user };
  });
```

## Anti-Patterns

### Forgetting the controller type annotation with createTypedHandler()

```typescript
// WRONG -- createTypedHandler cannot infer types without annotation
const createUserController = async (context) => {
  // context type is implicit 'any'
};

const handler = createTypedHandler(createUserController); // Types lost

// CORRECT -- explicit type on controller parameter
const createUserController = async (context: Context<CreateUserRequest, AuthUser>) => {
  // Types properly inferred
};
```

### Mixing approaches in the same handler

```typescript
// WRONG -- explicit generics on Handler but implicit on middlewares
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())  // Are these inferred or missing?
  .use(new BodyValidationMiddleware(schema))
  .handle(createUserController);

// CORRECT -- pick one approach, use consistently
// All explicit:
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware<CreateUserRequest, AuthUser>())
  .use(new BodyValidationMiddleware<CreateUserRequest, AuthUser>(schema))
  .handle(createUserController);

// Or all inferred:
const handler = createTypedHandler(createUserController)
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(schema))
  .handle(createUserController);
```

### Using `as any` to bypass type errors

```typescript
// WRONG -- defeats the entire purpose of type safety
const handler = new Handler<any, any>() as Handler<CreateUserRequest, AuthUser>;

// CORRECT -- use proper type declarations
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware<CreateUserRequest, AuthUser>())
  .handle(createUserController);
```

### Using Handler<unknown> with validation

```typescript
// WRONG -- validatedBody stays typed as unknown
const handler = new Handler<unknown>()
  .use(new BodyValidationMiddleware(schema))
  .handle(async (context) => {
    context.req.validatedBody; // type: unknown
  });

// CORRECT -- use the inferred schema type
type CreateUserRequest = z.infer<typeof schema>;
const handler = new Handler<CreateUserRequest>()
  .use(new BodyValidationMiddleware(schema))
  .handle(async (context) => {
    context.req.validatedBody; // type: CreateUserRequest
  });
```

## See Also

- [Architecture](../explanation/architecture.md) -- How the generic system fits into the overall framework design
- [Custom Middleware](./custom-middleware.md) -- Building middleware that preserves the type chain
- [Validation Schemas](./validation-schemas.md) -- Deriving TypeScript types from Zod schemas with `z.infer`
