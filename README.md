# Noony Serverless Framework

A powerful and flexible serverless middleware framework for Google Cloud Functions with full TypeScript support. This framework provides a clean, type-safe way to handle HTTP and Pub/Sub requests through a composable middleware system inspired by Middy.js.

## Core Architecture

### Handler System

The `Handler` class manages the middleware execution pipeline with `before`, `after`, and `onError` lifecycle hooks:

```typescript
const handler = new Handler<RequestType, UserType>()
  .use(errorHandler())
  .use(bodyParser())
  .use(bodyValidator(schema))
  .handle(async (context) => {
    // Your business logic here
  });
```

### Type-Safe Context

The context system provides full TypeScript support with generic typing:

```typescript
interface Context<T = unknown, U = unknown> {
  req: CustomRequest<T>;     // Request with parsedBody and validatedBody
  res: CustomResponse;       // Response object
  container?: Container;     // TypeDI dependency injection
  error?: Error | null;      // Error handling
  businessData: Map<string, unknown>; // Inter-middleware data sharing
  user?: U;                  // Authenticated user data
}
```

### Middleware Lifecycle

Middlewares support three lifecycle hooks:
- **before**: Execute before the main handler
- **after**: Execute after the main handler (reverse order)
- **onError**: Handle errors (reverse order)

## Quick Start

### Installation

```bash
npm install @noony/serverless
# or
yarn add @noony/serverless
```

### Basic HTTP Function

```typescript
import { http } from '@google-cloud/functions-framework';
import { z } from 'zod';
import {
  Handler,
  ErrorHandlerMiddleware,
  BodyValidationMiddleware,
  ResponseWrapperMiddleware,
} from '@noony/serverless';

// Define request schema
const userSchema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  age: z.number().min(18),
});

type UserRequest = z.infer<typeof userSchema>;

// Create handler with full type safety
const createUserHandler = new Handler<UserRequest, unknown>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(userSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    // TypeScript knows validatedBody is UserRequest
    const { name, email, age } = context.req.validatedBody!;
    
    // Your business logic
    const user = await createUser({ name, email, age });
    
    context.res.json({
      message: 'User created successfully',
      userId: user.id,
    });
  });

// Export Google Cloud Function
export const createUser = http('createUser', (req, res) => {
  return createUserHandler.execute(req, res);
});
```

### Pub/Sub Function Example

```typescript
import { cloudEvent } from '@google-cloud/functions-framework';
import { z } from 'zod';
import {
  Handler,
  ErrorHandlerMiddleware,
  BodyParserMiddleware,
  BodyValidationMiddleware,
} from '@noony/serverless';

// Define message schema
const messageSchema = z.object({
  userId: z.string().uuid(),
  action: z.enum(['CREATE', 'UPDATE', 'DELETE']),
  payload: z.record(z.unknown()),
});

type PubSubMessage = z.infer<typeof messageSchema>;

// Create Pub/Sub handler
const pubsubHandler = new Handler<PubSubMessage, unknown>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyParserMiddleware()) // Decodes base64 Pub/Sub messages
  .use(new BodyValidationMiddleware(messageSchema))
  .handle(async (context) => {
    const { action, payload } = context.req.validatedBody!;
    
    // Process message based on action
    switch (action) {
      case 'CREATE':
        await handleCreateAction(payload);
        break;
      case 'UPDATE':
        await handleUpdateAction(payload);
        break;
      case 'DELETE':
        await handleDeleteAction(payload);
        break;
    }
  });

// Export Cloud Function
export const processPubSubMessage = cloudEvent('processPubSubMessage', (cloudEvent) => {
  return pubsubHandler.execute(cloudEvent.data, {});
});
```

## Built-in Middlewares

### ErrorHandlerMiddleware

Centralized error handling with custom error types:

```typescript
.use(new ErrorHandlerMiddleware())

// Handles these error types:
throw new HttpError(400, 'Bad Request');
throw new ValidationError('Invalid input');
throw new AuthenticationError('Unauthorized');
```

### BodyParserMiddleware

Automatically parses JSON and Pub/Sub messages:

```typescript
.use(new BodyParserMiddleware())
// Sets context.req.parsedBody
```

### BodyValidationMiddleware

Zod schema validation with TypeScript integration:

```typescript
const schema = z.object({ name: z.string() });
.use(new BodyValidationMiddleware(schema))
// Sets context.req.validatedBody with proper typing
```

### AuthenticationMiddleware

JWT token verification:

```typescript
const tokenVerifier = {
  async verifyToken(token: string) {
    // Your verification logic
    return { userId: '123', role: 'user' };
  }
};
.use(new AuthenticationMiddleware(tokenVerifier))
// Sets context.user
```

### ResponseWrapperMiddleware

Standardized response format:

```typescript
.use(new ResponseWrapperMiddleware())
// Wraps responses in: { success: true, payload: data, timestamp }
```

### HeaderVariablesMiddleware

Validate required headers:

```typescript
.use(new HeaderVariablesMiddleware(['authorization', 'content-type']))
```

### QueryParametersMiddleware

Process query parameters:

```typescript
.use(new QueryParametersMiddleware())
// Processes context.req.query
```

### DependencyInjectionMiddleware

TypeDI container integration:

```typescript
.use(new DependencyInjectionMiddleware([
  { id: 'userService', value: new UserService() }
]))
```

## Error Handling

Built-in error classes with proper HTTP status codes:

```typescript
// HTTP errors with custom status codes
throw new HttpError(400, 'Bad Request', 'INVALID_INPUT');

// Validation errors (400 status)
throw new ValidationError('Invalid email format', zodErrors);

// Authentication errors (401 status)
throw new AuthenticationError('Invalid token');

// Authorization errors (403 status) 
throw new AuthorizationError('Insufficient permissions');
```

## Framework Integration

### Google Cloud Functions

```typescript
import { http } from '@google-cloud/functions-framework';

export const myFunction = http('myFunction', (req, res) => {
  return handler.execute(req, res);
});
```

### Fastify Integration

```typescript
import Fastify from 'fastify';
import { Handler } from '@noony/serverless';

const fastify = Fastify();

fastify.post('/users', async (request, reply) => {
  const req = { ...request, body: request.body };
  const res = {
    status: (code: number) => reply.status(code),
    json: (data: any) => reply.send(data)
  };
  
  await handler.execute(req, res);
});
```

### Express Integration

```typescript
import express from 'express';
import { Handler } from '@noony/serverless';

const app = express();

app.post('/users', async (req, res) => {
  await handler.execute(req, res);
});
```

## Best Practices

### 1. Middleware Order

```typescript
const handler = new Handler<RequestType, UserType>()
  .use(new ErrorHandlerMiddleware())        // Always first
  .use(new HeaderVariablesMiddleware(...))  // Required headers
  .use(new AuthenticationMiddleware(...))   // Authentication
  .use(new BodyParserMiddleware())          // Parse body
  .use(new BodyValidationMiddleware(...))   // Validate
  .use(new DependencyInjectionMiddleware(...))
  .use(new ResponseWrapperMiddleware())     // Always last
  .handle(async (context) => {
    // Business logic
  });
```

### 2. Type Safety

```typescript
// Define clear interfaces
interface UserRequest {
  name: string;
  email: string;
}

interface UserContext {
  userId: string;
  role: string;
}

// Use throughout the handler
const handler = new Handler<UserRequest, UserContext>();
```

### 3. Error Handling

- Always use ErrorHandlerMiddleware first
- Throw appropriate error types
- Handle errors gracefully in business logic
- Use proper HTTP status codes

### 4. Testing

```typescript
// Mock context for testing
const mockContext = {
  req: { validatedBody: { name: 'test' } },
  res: { json: jest.fn() },
  businessData: new Map(),
};

await handler.handle(mockContext);
```

## TypeScript Support

The framework provides full type safety through generic types:

```typescript
import {
  Handler,
  Context,
  BaseMiddleware,
  ErrorHandlerMiddleware,
  BodyValidationMiddleware,
} from '@noony/serverless';

// No type casting needed with proper generics
const handler = new Handler<UserRequest, UserContext>()
  .handle(async (context) => {
    // TypeScript knows validatedBody is UserRequest
    const { name, email } = context.req.validatedBody!;
    // TypeScript knows user is UserContext
    const { userId } = context.user!;
  });
```

## Development Commands

```bash
npm run build          # Compile TypeScript
npm run watch          # Watch mode compilation  
npm run test           # Run Jest tests
npm run test:coverage  # Test with coverage
npm run lint           # ESLint check
npm run format         # Prettier formatting
```

## Example API Usage

```bash
# Create user with authentication
curl -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer valid-token" \
  -H "x-api-version: v1" \
  -d '{"name":"John Doe","email":"john@example.com","age":30}'

# Get user by ID
curl -H "Authorization: Bearer valid-token" \
  http://localhost:3000/api/users/123

# List users with query parameters
curl -H "Authorization: Bearer valid-token" \
  "http://localhost:3000/api/users?name=john"
```

## Deployment

### Google Cloud Functions

```bash
# Deploy HTTP function
gcloud functions deploy myFunction \
  --runtime nodejs20 \
  --trigger-http \
  --entry-point myFunction \
  --allow-unauthenticated

# Deploy Pub/Sub function
gcloud functions deploy myPubSubFunction \
  --runtime nodejs20 \
  --trigger-topic my-topic \
  --entry-point myPubSubFunction
```

### Cloud Run

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build
EXPOSE 8080
CMD ["npm", "start"]
```

## Publishing to npm

This package is published as `@noony-serverless/core` on npm. Follow these steps to publish a new version:

### Prerequisites

1. **npm Account**: You need an npm account. Create one at [npmjs.com/signup](https://www.npmjs.com/signup)
2. **Organization Access**: You must have access to the `@noony-serverless` organization on npm
   - If you own the organization, you're all set
   - If not, you need to [create the organization](https://www.npmjs.com/org/create) first
3. **Two-Factor Authentication**: Highly recommended for security

### Publishing Steps

#### 1. Login to npm

```bash
npm login
```

You'll be prompted for:

- Username
- Password
- Email
- One-time password (if 2FA is enabled)

Verify you're logged in:

```bash
npm whoami
```

#### 2. Prepare the Package

Ensure all changes are committed and tests pass:

```bash
# Run tests
npm test

# Run linter
npm run lint

# Build the package
npm run build
```

#### 3. Update Version

Update the version in `package.json` following [Semantic Versioning](https://semver.org/):

```bash
# For bug fixes (0.4.0 -> 0.4.1)
npm version patch

# For new features (0.4.0 -> 0.5.0)
npm version minor

# For breaking changes (0.4.0 -> 1.0.0)
npm version major
```

This will:

- Update `package.json` version
- Create a git commit
- Create a git tag

#### 4. Publish to npm

For scoped packages (like `@noony-serverless/core`), you must specify public access:

```bash
npm publish --access public
```

**For the first publish only**, you need the `--access public` flag. Subsequent publishes can use:

```bash
npm publish
```

#### 5. Push to Git

Don't forget to push the version commit and tags:

```bash
git push && git push --tags
```

### Publishing Checklist

Before publishing, verify:

- [ ] All tests pass (`npm test`)
- [ ] No linting errors (`npm run lint`)
- [ ] Build succeeds (`npm run build`)
- [ ] Version number updated in `package.json`
- [ ] CHANGELOG.md updated (if applicable)
- [ ] README.md is up to date
- [ ] All changes committed to git
- [ ] Logged into npm (`npm whoami`)

### Troubleshooting

#### Error: "Access token expired or revoked"

**Solution**: Run `npm login` to re-authenticate

#### Error: "404 Not Found - Not in this registry"

**Solution**: For first publish of a scoped package, use:

```bash
npm publish --access public
```

#### Error: "You do not have permission to publish"

**Solution**:

- Verify you're logged in as the correct user
- Check you have publish access to the `@noony-serverless` organization
- Create the organization if it doesn't exist

#### Error: "Cannot publish over existing version"

**Solution**: Update the version number in `package.json` or use:

```bash
npm version patch  # or minor/major
```

#### Error: "403 Forbidden"

**Solutions**:

- Ensure you're logged in: `npm whoami`
- Verify you own the package or have collaborator access
- If this is a new scoped package, verify the organization exists

### Automated Publishing with GitHub Actions

For automated publishing, create `.github/workflows/publish.yml`:

```yaml
name: Publish to npm

on:
  release:
    types: [created]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '20'
          registry-url: 'https://registry.npmjs.org'
      - run: npm ci
      - run: npm test
      - run: npm run build
      - run: npm publish --access public
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

To use this:

1. Create an npm access token at [npmjs.com/settings/tokens](https://www.npmjs.com/settings/tokens)
2. Add it as a GitHub secret named `NPM_TOKEN`
3. Create a GitHub release to trigger publishing

### Version Management

This package follows [Semantic Versioning](https://semver.org/):

- **MAJOR** version (1.0.0 → 2.0.0): Breaking changes
- **MINOR** version (1.0.0 → 1.1.0): New features, backwards compatible
- **PATCH** version (1.0.0 → 1.0.1): Bug fixes, backwards compatible

Current version: **0.4.0**

### Package Distribution

When published, the package includes only the `build/` directory contents:

- `build/core/**/*.js` and `*.d.ts`
- `build/middlewares/**/*.js` and `*.d.ts`
- `build/utils/**/*.js` and `*.d.ts`
- `build/index.js` and `index.d.ts`
- `README.md`

Source TypeScript files are not included in the npm package.

## Community & Support

- 📖 [Documentation](https://github.com/noony-org/noony-serverless)
- 🐛 [Issue Tracker](https://github.com/noony-org/noony-serverless/issues)
- 💬 [Discussions](https://github.com/noony-org/noony-serverless/discussions)
- 📦 [npm Package](https://www.npmjs.com/package/@noony-serverless/core)

## License

MIT License - see [LICENSE](LICENSE) file for details.