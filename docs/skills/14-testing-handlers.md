# Skill 14: Testing Handlers

## Triggers

When user asks to:
- "Test handler"
- "Write unit test"
- "Mock services"
- "Test middleware"

## What it provides

Pattern for testing handlers using `Container.reset()` and mocked dependencies.

## Complete Example

```typescript
import { Container } from 'typedi';
import { handler } from '../src/handlers/myHandler';

describe('UserHandler', () => {
  beforeEach(() => {
    Container.reset(); // Clear DI
  });

  it('should create user successfully', async () => {
    // 1. Mock Service
    const mockUserService = { createUser: jest.fn().mockResolvedValue({ id: '1' }) };
    Container.set(UserService, mockUserService);

    // 2. Execute Handler (mocking req/res)
    const req = { body: { name: 'Test' } };
    const res = { status: jest.fn().mockReturnThis(), send: jest.fn() };
    
    // Assuming handler.execute is available
    await handler.execute(req, res);

    expect(res.status).toHaveBeenCalledWith(201);
    expect(mockUserService.createUser).toHaveBeenCalled();
  });
});
```

## When to use

- Writing unit tests for business logic
- Verifying middleware chains
- Ensuring error handling works
