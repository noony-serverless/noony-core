# Skill 11: Dependency Injection Best Practices

## Triggers

When user asks to:
- "Inject service"
- "Setup DI"
- "Use TypeDI"
- "Manage dependencies"

## What it provides

Correct `@Service()` decoration and injection patterns for services and repositories using TypeDI.

## Complete Example

```typescript
import 'reflect-metadata';
import { Service, Container } from 'typedi';

@Service()
class UserRepository {
  async findUser(id: string) { /* ... */ }
}

@Service()
class UserService {
  // Automatic injection via constructor
  constructor(private userRepo: UserRepository) {}

  async getUser(id: string) {
    return this.userRepo.findUser(id);
  }
}

// In handler
const userService = Container.get(UserService); // Get instance
```

## When to use

- Decoupling business logic from handlers
- Managing database connections
- Unit testing (easier mocking)
