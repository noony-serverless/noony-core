# Skill 10: Robust Error Handling

## Triggers

When user asks to:
- "Handle errors"
- "Return 400 or 401"
- "Throw custom error"
- "Error categories"

## What it provides

Usage of built-in error classes like `ValidationError`, `AuthenticationError`, `BusinessError` to ensure correct HTTP status codes.

## Complete Example

```typescript
import { 
  ValidationError, 
  AuthenticationError, 
  BusinessError, 
  SecurityError 
} from '@noony-serverless/core';

// Inside handler or middleware
// Validation Error (400)
if (!isValidEmail(email)) {
  throw new ValidationError('Invalid email format'); 
}

// Authentication Error (401)
if (!token) {
  throw new AuthenticationError('Missing token'); 
}

// Security/Permission Error (403)
if (!user.hasPermission('admin')) {
  throw new SecurityError('Admin access required'); 
}

// Business Logic Error (500 or custom)
if (balance < amount) {
  throw new BusinessError('Insufficient funds', 'INSUFFICIENT_FUNDS'); 
}
```

## When to use

- Validating business rules
- Enforcing security policies
- Whenever an operation cannot complete successfully
