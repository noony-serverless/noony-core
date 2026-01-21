# Skill 13: Performance Optimization

## Triggers

When user asks to:
- "Optimize cold start"
- "Improve performance"
- "Speed up serverless"
- "Use Container Pool"

## What it provides

Usage of `containerPool` for pre-warming services to reduce cold start latency in serverless environments.

## Complete Example

```typescript
import { containerPool } from '@noony-serverless/core';
import { UserService } from './services/UserService';
import { DatabaseService } from './services/DatabaseService';

// Run during cold start (outside handler)
const warmUp = async () => {
  containerPool.register([UserService, DatabaseService]);
  await containerPool.preWarm([DatabaseService]); // Connect to DB
};

await warmUp();

// In Handler
// ~10x faster than Container.get() during cold start
const userService = containerPool.get(UserService); 
```

## When to use

- Deploying to Google Cloud Functions, AWS Lambda
- When experiencing high latency on first request
- For heavy initialization services (DB connections)
