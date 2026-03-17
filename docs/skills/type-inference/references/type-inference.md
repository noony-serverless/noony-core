# Resource: Type Inference with createTypedHandler()

## Option 1: Explicit Generics (Recommended for Clear Declarations)

For complex types or when controller signature is not yet defined, specify generics explicitly on the Handler:

```typescript
import { Handler, Context } from '@noony-serverless/core';
import { z } from 'zod';

// 1. Define request schema
const createUserSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email(),
  age: z.number().min(18).max(120),
  role: z.enum(['user', 'admin']).default('user')
});

// 2. Infer TypeScript type from Zod schema
type CreateUserRequest = z.infer<typeof createUserSchema>;

// 3. Define authenticated user type
interface AuthenticatedUser {
  id: string;
  email: string;
  role: 'user' | 'admin';
}

// 4. Specify generics explicitly on Handler
const createUserHandler = new Handler<CreateUserRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware<CreateUserRequest, AuthenticatedUser>())
  .use(new BodyValidationMiddleware<CreateUserRequest, AuthenticatedUser>(createUserSchema))
  .use(new ResponseWrapperMiddleware<CreateUserRequest, AuthenticatedUser>())
  .handle(async (context: Context<CreateUserRequest, AuthenticatedUser>) => {
    // Full type safety - body and user are properly typed
    const { name, email, age } = context.req.validatedBody!;
    const currentUser = context.user!;  // Type: AuthenticatedUser

    const newUser = await userService.create({
      name,
      email,
      age,
      role: 'user',
      createdBy: currentUser.id
    });

    return { data: newUser };
  });
```

**Benefits:**
- Clear and explicit — types visible at handler definition
- Works when controller doesn't exist yet
- Easier to understand for new developers
- No implicit type inference

**Boilerplate:** You must specify generics on Handler AND all middlewares

## Option 2: Type Inference with createTypedHandler() (Recommended for Convenience)

When controller already has explicit type annotations, let the framework infer types automatically:

```typescript
import { createTypedHandler, Context } from '@noony-serverless/core';
import { z } from 'zod';

// 1. Define schema
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

// 2. Define controller WITH EXPLICIT TYPES
async function createUserController(context: Context<CreateUserRequest, AuthenticatedUser>) {
  const { name, email, age } = context.req.validatedBody!;
  const user = context.user!;

  const newUser = await userService.create({ name, email, age });
  return { data: newUser };
}

// 3. Use createTypedHandler to infer types from controller signature
const createUserHandler = createTypedHandler(createUserController)
  .use(new ErrorHandlerMiddleware())        // Types inferred automatically!
  .use(new BodyValidationMiddleware(createUserSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(createUserController);
```

**Benefits:**
- ~50% less boilerplate — no explicit generics on Handler or middlewares
- Types still fully checked at compile time
- Easier to read and maintain

**Requirement:** Controller must have explicit `Context<TBody, TUser>` type annotation

## Comparison Table

| Aspect | Explicit Generics | Type Inference |
|--------|-------------------|-----------------|
| Boilerplate | High (specify on Handler + middlewares) | Low (infer from controller) |
| Readability | Clear and explicit | Cleaner code |
| Flexibility | Can use partial types | Requires full type signature |
| Best For | Complex types, planning | Controllers with explicit types |
| Compile Time Safety | ✅ Full type checking | ✅ Full type checking |
| Learning Curve | Easier to understand | Slightly steeper (inference rules) |

## Advanced: Type Inference with Multiple Handlers

When you have multiple handlers sharing types:

```typescript
// Define types once
type LoginRequest = z.infer<typeof loginSchema>;
type AuthUser = AuthenticatedUser;

// Create controller with explicit types
const loginController: ControllerFn<LoginRequest, AuthUser> = async (context) => {
  const { email, password } = context.req.validatedBody!;
  const user = await authService.verifyLogin(email, password);
  return { token: jwt.sign(user) };
};

// Infer types from controller signature
const loginHandler = createTypedHandler(loginController)
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(loginSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(loginController);

// Explicit generics for complex middleware chains
const getUserHandler = new Handler<void, AuthUser>()
  .use(new ErrorHandlerMiddleware<void, AuthUser>())
  .use(new AuthenticationMiddleware(tokenVerifier))  // Requires AuthUser type
  .handle(async (context: Context<void, AuthUser>) => {
    const user = await userService.getById(context.user!.id);
    return { data: user };
  });
```

## When to Use Each Approach

### Use Explicit Generics If:
- Handler is defined before controller function
- Controller has complex conditional type logic
- You're teaching others and want explicit types
- Types are shared across multiple files
- You want maximum clarity for code reviewers

### Use Type Inference If:
- Controller already has explicit `Context<TBody, TUser>` annotation
- You want minimal boilerplate
- Building rapid prototypes
- Team is comfortable with TypeScript inference
- Most handlers follow standard pattern

## Gotchas and Solutions

### ❌ Forgetting Controller Type Annotation

```typescript
// WRONG - createTypedHandler can't infer without explicit types
const createUserController = async (context) => {  // No type annotation!
  // TypeScript doesn't know type of context
};

const handler = createTypedHandler(createUserController);  // ❌ Loses type safety
```

### ✅ Solution: Add Explicit Type

```typescript
// CORRECT - Explicit type on controller
const createUserController = async (context: Context<CreateUserRequest, AuthUser>) => {
  // TypeScript now knows exact types
};

const handler = createTypedHandler(createUserController);  // ✅ Types inferred
```

### ❌ Mixing Approaches in Same Handler

```typescript
// WRONG - Explicit AND inference creates confusion
const handler = new Handler<CreateUserRequest, AuthUser>()  // Explicit
  .use(new ErrorHandlerMiddleware())  // No type (inference? or error?)
  .use(new BodyValidationMiddleware(schema))
  .handle(createUserController);  // Also explicit
```

### ✅ Solution: Pick One Consistently

```typescript
// CORRECT - All explicit
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware<CreateUserRequest, AuthUser>())
  .use(new BodyValidationMiddleware<CreateUserRequest, AuthUser>(schema))
  .handle(createUserController);

// OR CORRECT - All inferred
const handler = createTypedHandler(createUserController)
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(schema))
  .handle(createUserController);
```

### ❌ Using `as any` to Bypass Type Checking

```typescript
// WRONG - Defeats entire purpose of type safety
const handler = new Handler<any, any>() as Handler<CreateUserRequest, AuthUser>;
```

### ✅ Solution: Use Proper Type Declaration

```typescript
// CORRECT - Types are accurate
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware<CreateUserRequest, AuthUser>())
  .handle(createUserController);
```

## Type Chain Preservation

When using either approach, ensure all middlewares in the chain preserve types:

```typescript
// ✅ CORRECT - Type chain preserved through all middlewares
class CustomMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
{
  async before(context: Context<TBody, TUser>): Promise<void> {
    // Types flow through chain
  }
}

// ❌ WRONG - Breaks type chain
class CustomMiddleware implements BaseMiddleware {
  async before(context: Context): Promise<void> {
    // Type information lost
  }
}
```

Every middleware must explicitly implement `BaseMiddleware<TBody, TUser>` with both generics for type safety to work correctly.
