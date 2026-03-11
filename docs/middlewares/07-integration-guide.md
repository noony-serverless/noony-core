# How to Compose Middleware Pipelines

Combines multiple middlewares in the correct order to produce a complete, production-ready request handler.

## Canonical Ordering

| Position | Middleware | Why here |
| -------- | ---------- | -------- |
| 1 | `ErrorHandlerMiddleware` | Its `onError` hook runs last (reverse order), catching errors from every middleware below it |
| 2 | `DependencyInjectionMiddleware` | Services must be available before any subsequent middleware calls them |
| 3 | `HeaderVariablesMiddleware` | Cheap fail-fast — rejects requests without required headers before any expensive work |
| 4 | `PathParametersMiddleware` | Route params available to auth/guard logic |
| 5 | `QueryParametersMiddleware` | Optional presence-check before business logic |
| 6 | `BodyParserMiddleware` | Parses body only if earlier validations pass |
| 7 | `BodyValidationMiddleware` | Validates the parsed body |
| 8 | Auth / guard middlewares | Runs after all inputs are present and validated |
| last | `ResponseWrapperMiddleware` | Its `after` hook fires last, wrapping the controller's return value |

**The core rule: put cheap, structural middleware early; put expensive, semantic middleware late.** A request that is missing a required header should never trigger a database call.

## Primary Workflow

A complete handler with the most common middlewares:

```typescript
import { Handler } from '@/core/handler';
import { z } from 'zod';
import {
  ErrorHandlerMiddleware,
  ResponseWrapperMiddleware,
  HeaderVariablesMiddleware,
  BodyParserMiddleware,
  BodyValidationMiddleware,
  DependencyInjectionMiddleware,
} from '@/middlewares';

const createUserSchema = z.object({
  name: z.string().min(1),
  email: z.string().email(),
  role: z.enum(['user', 'admin']).default('user'),
});

type CreateUserRequest = z.infer<typeof createUserSchema>;

const services = [
  { id: UserService, value: userService },
  { id: EmailService, value: emailService },
];

export const createUserHandler = new Handler<CreateUserRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())              // 1. catch everything
  .use(new DependencyInjectionMiddleware(services)) // 2. services ready
  .use(new HeaderVariablesMiddleware(['authorization', 'content-type'])) // 3. fail fast
  .use(new BodyParserMiddleware<CreateUserRequest>())   // 4. parse
  .use(new BodyValidationMiddleware(createUserSchema))  // 5. validate
  .use(new ResponseWrapperMiddleware())           // last — wrap response
  .handle(async (context) => {
    const userSvc = context.container?.get(UserService);
    const emailSvc = context.container?.get(EmailService);
    const userData = context.req.validatedBody!;

    const user = await userSvc.create(userData);
    await emailSvc.sendWelcomeEmail(user.email, user.name);

    return { success: true, user };
  });
```

## If You Need Path Params AND Query Params AND Headers

All three attribute-extraction middlewares compose cleanly:

```typescript
import {
  HeaderVariablesMiddleware,
  PathParametersMiddleware,
  QueryParametersMiddleware,
} from '@/middlewares';

interface UserParams { userId: string; }

const getUserHandler = new Handler<UserParams>()
  .use(new ErrorHandlerMiddleware())
  .use(new HeaderVariablesMiddleware(['authorization', 'accept']))
  .use(new PathParametersMiddleware())       // extracts userId from URL
  .use(new QueryParametersMiddleware())      // page, limit, include_posts, etc.
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    // Headers validated
    const auth = context.req.headers.authorization as string;

    // Path param extracted
    const { userId } = context.req.params as UserParams;

    // Query params available
    const { page = '1', limit = '10', include_posts = 'false' } = context.req.query;

    const user = await authenticateAndGetUser(auth, userId);
    const data = await enrichUserData(user, {
      includePosts: include_posts === 'true',
      page: parseInt(page as string),
      limit: parseInt(limit as string),
    });

    return { success: true, user: data };
  });
```

## If You Need a Fully-Typed REST Handler

Use generics throughout to keep the entire pipeline type-safe:

```typescript
interface ProductParams { productId: string; }

interface ProductHeaders {
  'authorization': string;
  'x-client-version': string;
}

const productQuerySchema = z.object({
  include_reviews: z.enum(['true', 'false']).default('false'),
});

type ProductQuery = z.infer<typeof productQuerySchema>;

const productHandler = new Handler<ProductParams>()
  .use(new ErrorHandlerMiddleware())
  .use(new DependencyInjectionMiddleware([{ id: ProductService, value: productService }]))
  .use(new HeaderVariablesMiddleware(['authorization', 'x-client-version']))
  .use(new PathParametersMiddleware())
  .use(new QueryParametersMiddleware())
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const headers = context.req.headers as ProductHeaders;
    const { productId } = context.req.params as ProductParams;
    const query = productQuerySchema.parse(context.req.query);

    const productSvc = context.container?.get(ProductService);
    const product = await productSvc.findById(productId);
    const reviews = query.include_reviews === 'true'
      ? await getReviews(productId)
      : undefined;

    return { success: true, product, reviews };
  });
```

## Anti-Patterns

**Don't place expensive middleware before cheap validation.**

```typescript
// Wrong — DB call happens even for requests missing the authorization header
new Handler()
  .use(expensiveDbAuthMiddleware)
  .use(new HeaderVariablesMiddleware(['authorization']))

// Correct — header check fails first at negligible cost
new Handler()
  .use(new HeaderVariablesMiddleware(['authorization']))
  .use(expensiveDbAuthMiddleware)
```

**Don't omit `ErrorHandlerMiddleware`.** Without it, unhandled errors bubble up as unformatted 500s with no body shaping.

**Don't place `ResponseWrapperMiddleware` anywhere except last.** Its `after` hook must fire after the controller runs.

**Don't add `BodyValidationMiddleware` without `BodyParserMiddleware` before it.** `validatedBody` is derived from `parsedBody` — there is nothing to validate if parsing hasn't run.

**Don't skip ordering review when adding a new middleware to an existing pipeline.** Wrong order causes subtle failures that only appear at runtime under specific request shapes.

## Related

- [Middleware Reference](./01-overview.md) — full signature list
- [How to Parse Request Bodies](./02-body-parser.md)
- [How to Validate Request Bodies with Zod](./03-body-validation.md)
- [How to Validate Required HTTP Headers](./04-headers.md)
- [How to Extract and Validate Query Parameters](./05-query-params.md)
- [How to Inject Services into Handlers](./06-dependency-injection.md)
