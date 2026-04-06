---
description: Noony testing rules. Apply when writing tests for handlers, middleware, or services in a Noony project.
globs:
  - "**/*.test.ts"
  - "**/*.spec.ts"
alwaysApply: false
---

# Noony — Testing Rules

## Rules

- Test the full handler chain as a unit — not the controller function in isolation
- At least one error path test per handler (NotFoundError, UnauthorizedError, ValidationError)
- Mock services through the DI container, not via `jest.mock()` module mocking
- Verify typed error classes, not generic Error messages: `toBeInstanceOf(NotFoundError)`
- Reset request-scoped container state between tests: `containerPool.resetLocal()`

## Test Structure

```typescript
describe('MyHandler', () => {
  let mockService: jest.Mocked<MyService>;

  beforeEach(() => {
    mockService = { find: jest.fn() };
    // Wire handler with mocked DI
  });

  afterEach(() => jest.clearAllMocks());

  it('handles valid request', async () => { ... });
  it('throws ValidationError on invalid body', async () => { ... });
  it('throws NotFoundError when resource missing', async () => { ... });
  it('throws UnauthorizedError when unauthenticated', async () => { ... });
});
```

## Forbidden

- Testing the controller function directly — misses middleware behavior
- `jest.mock('../services/...')` — use DI mocking instead
- `toThrow('some message string')` — use `toBeInstanceOf(TypedError)`
- Missing error path tests

## Reference

→ `docs/noony-skills/testing-handlers/SKILL.md`
