# How to Validate Request Bodies with Zod

Validates the parsed request body against a Zod schema and exposes the result as `context.req.validatedBody` with full TypeScript types.

## Prerequisites

- `zod` installed (`npm install zod`)
- `BodyParserMiddleware` already in the chain (validation reads `parsedBody`)
- `BodyValidationMiddleware` (or `bodyValidatorMiddleware`) imported from `@/middlewares/bodyValidationMiddleware`

## Primary Workflow

**1. Define the Zod schema and derive the TypeScript type from it.**

```typescript
import { z } from 'zod';

const createUserSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email(),
  age: z.number().int().min(18),
  newsletter: z.boolean().optional().default(false),
});

type CreateUserRequest = z.infer<typeof createUserSchema>;
```

Don't define a separate TypeScript interface alongside the schema — use `z.infer` to derive it automatically. A separate interface means two sources of truth that will diverge.

**2. Add `BodyValidationMiddleware` after `BodyParserMiddleware`.**

```typescript
import { Handler, Context } from '@/core/handler';
import { BodyParserMiddleware } from '@/middlewares/bodyParserMiddleware';
import { BodyValidationMiddleware } from '@/middlewares/bodyValidationMiddleware';

async function handleCreateUser(context: Context<CreateUserRequest>) {
  const user = context.req.validatedBody!; // Typed as CreateUserRequest

  return {
    success: true,
    user: { id: `user_${Date.now()}`, ...user },
  };
}

export const createUserHandler = new Handler<CreateUserRequest>()
  .use(new BodyParserMiddleware<CreateUserRequest>())
  .use(new BodyValidationMiddleware(createUserSchema))
  .handle(handleCreateUser);
```

**3. Read validated data from `context.req.validatedBody`, not from `context.req.body` or `parsedBody`.**

After validation, `validatedBody` contains the Zod-transformed value. `parsedBody` still holds the raw decoded object — do not use it for business logic.

## If You Need Partial Updates (PATCH)

Use `.partial()` and add a `.refine()` to reject empty payloads:

```typescript
const updateUserSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  email: z.string().email().optional(),
  age: z.number().int().min(18).optional(),
}).refine(
  (data) => Object.keys(data).length > 0,
  { message: 'At least one field must be provided for update' }
);

type UpdateUserRequest = z.infer<typeof updateUserSchema>;

async function handleUpdateUser(context: Context<UpdateUserRequest>) {
  const updates = context.req.validatedBody!;
  const userId = context.req.params?.id;

  const updatedUser = await updateUser(userId, updates);
  return { success: true, user: updatedUser };
}

export const updateUserHandler = new Handler<UpdateUserRequest>()
  .use(new BodyParserMiddleware<UpdateUserRequest>())
  .use(new BodyValidationMiddleware(updateUserSchema))
  .handle(handleUpdateUser);
```

## If You Need Conditional Schemas

Validate a discriminant field first, then branch:

```typescript
const baseActionSchema = z.object({
  action: z.enum(['create', 'update', 'delete']),
});

const createActionSchema = baseActionSchema.extend({
  data: z.object({ name: z.string().min(1), description: z.string() }),
});

const deleteActionSchema = baseActionSchema.extend({
  id: z.string().uuid(),
  confirm: z.literal(true),
});

async function handleDynamicAction(context: Context) {
  const base = baseActionSchema.parse(context.req.parsedBody);

  if (base.action === 'create') {
    const payload = createActionSchema.parse(context.req.parsedBody);
    return await createItem(payload.data);
  }

  if (base.action === 'delete') {
    const payload = deleteActionSchema.parse(context.req.parsedBody);
    return await deleteItem(payload.id);
  }
}

export const dynamicActionHandler = new Handler()
  .use(new BodyParserMiddleware())
  .handle(handleDynamicAction);
```

## If You Need Transforms

Zod transforms run during validation, so `validatedBody` receives the transformed values:

```typescript
const signupSchema = z.object({
  name: z.string().min(1).transform((v) => v.trim()),
  email: z.string().email().transform((v) => v.toLowerCase()),
  birthDate: z.string().transform((v) => new Date(v)),
  tags: z.string().transform((v) => v.split(',').map((t) => t.trim())),
}).refine(
  (data) => {
    const age = new Date().getFullYear() - data.birthDate.getFullYear();
    return age >= 18;
  },
  { message: 'Must be at least 18 years old', path: ['birthDate'] }
);

type SignupRequest = z.infer<typeof signupSchema>;

export const signupHandler = new Handler<SignupRequest>()
  .use(new BodyParserMiddleware<SignupRequest>())
  .use(new BodyValidationMiddleware(signupSchema))
  .handle(async (context: Context<SignupRequest>) => {
    const data = context.req.validatedBody!;
    // data.name is trimmed, data.email is lowercase, data.birthDate is a Date
    // data.tags is string[]
    return { success: true, user: await createUser(data) };
  });
```

## With Authenticated Users (Dual Generics)

`BodyValidationMiddleware` supports dual generics `<TBody, TUser>` for pipelines that also set `context.user`:

```typescript
interface AuthenticatedUser {
  id: string;
  email: string;
  roles: string[];
}

const profileUpdateSchema = z.object({
  name: z.string().min(1).optional(),
  bio: z.string().max(500).optional(),
});

type ProfileUpdateRequest = z.infer<typeof profileUpdateSchema>;

async function handleUpdateProfile(
  context: Context<ProfileUpdateRequest, AuthenticatedUser>
) {
  const updates = context.req.validatedBody!; // ProfileUpdateRequest
  const user = context.user!;                 // AuthenticatedUser

  return { success: true, profile: { ...user, ...updates } };
}

export const updateProfileHandler = new Handler<ProfileUpdateRequest, AuthenticatedUser>()
  .use(new BodyParserMiddleware<ProfileUpdateRequest>())
  .use(new BodyValidationMiddleware<ProfileUpdateRequest, AuthenticatedUser>(profileUpdateSchema))
  .handle(handleUpdateProfile);
```

## Anti-Patterns

**Don't access `context.req.body` or `context.req.parsedBody` after this middleware** — use `context.req.validatedBody`. `parsedBody` is the raw decoded object; `validatedBody` has been transformed and is the correct typed value.

**Don't define a TypeScript interface separately from the Zod schema.** Two type definitions for the same shape will diverge. Use `z.infer<typeof schema>` as the single source of truth.

**Don't use async refinements for synchronous validations.** `parseAsync` adds overhead; use `parse` unless you actually need async (e.g. database uniqueness checks).

## Related

- [How to Parse Request Bodies](./02-body-parser.md) — must come before this middleware
- [How to Compose Middleware Pipelines](./07-integration-guide.md) — canonical ordering
