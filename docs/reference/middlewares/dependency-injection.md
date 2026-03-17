# How to Inject Services into Handlers

Populates `context.container` with service instances so controllers can resolve them without importing singletons directly.

The container has two scopes:

- **Global** — services initialised once at module startup (database clients, email clients, config). Shared across all requests.
- **Local (per-request)** — services registered by `DependencyInjectionMiddleware` for each individual request. Inherit from the global container via a proxy, so global services are accessible without re-registering them.

## Prerequisites

- `DependencyInjectionMiddleware` imported from `@/middlewares/dependencyInjectionMiddleware`
- Service classes defined (any class — no decorator required for manual registration)

## Primary Workflow

**1. Initialise global services at module startup (outside any handler).**

```typescript
// services/index.ts — runs once when the module loads
import { UserService, EmailService, LoggerService } from './core-services';

export const userService = new UserService();
export const emailService = new EmailService({
  apiKey: process.env.EMAIL_API_KEY!,
  fromEmail: process.env.FROM_EMAIL!,
});
export const loggerService = new LoggerService('MyAPI');
```

Don't create service instances inside a middleware `before()` or inside a controller — they would be reinstantiated on every request.

**2. Register services with `DependencyInjectionMiddleware`.**

```typescript
import { Handler, Context } from '@/core/handler';
import { DependencyInjectionMiddleware } from '@/middlewares/dependencyInjectionMiddleware';
import { userService, emailService, loggerService } from '../services';
import { UserService, EmailService, LoggerService } from './core-services';

const services = [
  { id: UserService, value: userService },
  { id: EmailService, value: emailService },
  { id: LoggerService, value: loggerService },
  { id: 'config', value: { apiUrl: process.env.API_URL, env: process.env.NODE_ENV } },
];

const userDI = new DependencyInjectionMiddleware(services);
```

**3. Resolve services in the controller via `context.container.get()`.**

```typescript
async function handleCreateUser(context: Context) {
  const userSvc = context.container?.get(UserService);
  const emailSvc = context.container?.get(EmailService);
  const logger = context.container?.get(LoggerService);

  const userData = context.req.parsedBody;
  logger.info('Creating user', { email: userData.email });

  const user = await userSvc.create(userData);
  await emailSvc.sendWelcomeEmail(user.email, user.name);

  return { success: true, user };
}

export const createUserHandler = new Handler()
  .use(userDI)
  .handle(handleCreateUser);
```

## If Using `@Service` Decorator (TypeDI)

TypeDI can register services automatically when decorated with `@Service`. The middleware resolves them from the global TypeDI container, so you don't build the `services` array manually.

```typescript
import { Service } from 'typedi';

@Service()
export class UserService {
  async findById(id: string) { /* ... */ }
  async create(data: any) { /* ... */ }
}

@Service()
export class EmailService {
  async sendWelcomeEmail(email: string, name: string) { /* ... */ }
}
```

```typescript
import { DependencyInjectionMiddleware } from '@/middlewares/dependencyInjectionMiddleware';

// No services array needed — TypeDI resolves @Service classes automatically
const diMiddleware = new DependencyInjectionMiddleware([]);

async function handleCreateUser(context: Context) {
  const userSvc = context.container?.get(UserService);
  const emailSvc = context.container?.get(EmailService);

  const user = await userSvc.create(context.req.parsedBody);
  await emailSvc.sendWelcomeEmail(user.email, user.name);

  return { success: true, user };
}

export const createUserHandler = new Handler()
  .use(diMiddleware)
  .handle(handleCreateUser);
```

Use `@Service` when you have complex, deeply nested dependency graphs and want automatic resolution. Use manual registration when you need explicit control over instantiation order, different configurations per environment, or easy mock injection in tests.

## Reusing DI Middleware Across Handlers

Create the middleware once and share it across related handlers:

```typescript
// One middleware instance, shared across all user handlers
const userDI = new DependencyInjectionMiddleware([
  { id: UserService, value: userService },
  { id: EmailService, value: emailService },
]);

export const createUserHandler = new Handler().use(userDI).handle(handleCreateUser);
export const updateUserHandler = new Handler().use(userDI).handle(handleUpdateUser);
export const deleteUserHandler = new Handler().use(userDI).handle(handleDeleteUser);
```

## Testing with Mocked Services

Manual registration makes unit testing straightforward — swap real services for mocks at the point of registration:

```typescript
const mockUserService = {
  create: jest.fn().mockResolvedValue({ id: '123', name: 'Test User' }),
  findById: jest.fn(),
};

const mockEmailService = {
  sendWelcomeEmail: jest.fn().mockResolvedValue({ sent: true }),
};

const testDI = new DependencyInjectionMiddleware([
  { id: UserService, value: mockUserService },
  { id: EmailService, value: mockEmailService },
]);

const testHandler = new Handler().use(testDI).handle(handleCreateUser);
```

## Anti-Patterns

**Don't initialise global services inside a middleware `before()` or inside a controller.** Services would be re-instantiated on every request, recreating database connections and losing any in-memory state.

```typescript
// Wrong — new DB connection on every request
const handler = new Handler()
  .use({
    async before(context) {
      context.container.set(DBService, new DBService()); // ← recreated each time
    }
  })
  .handle(myController);

// Correct — initialise once at module level
const dbService = new DBService();
const handler = new Handler()
  .use(new DependencyInjectionMiddleware([{ id: DBService, value: dbService }]))
  .handle(myController);
```

**Don't mix manual registration and `@Service` decoration for the same service class.** Pick one approach per codebase. Mixing causes duplicate instances and unpredictable resolution order.

**Don't access services via module-level imports inside controllers when DI is in use.** Import through `context.container.get()` so mocks work in tests.

## Related

- [How to Compose Middleware Pipelines](../../guides/middleware-ordering.md) — where DI fits in the ordering
- `docs/ARCHITECTURE.md#hybrid-proxy-container` — deep dive on global vs local container scopes
