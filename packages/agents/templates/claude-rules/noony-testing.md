---
description: Noony testing rules — apply when writing handler or middleware tests.
globs: ["**/*.test.ts", "**/*.spec.ts"]
---

# Noony — Testing Rules

- Test the full handler chain as a unit — not the controller in isolation
- At least one error path test per handler (NotFoundError, UnauthorizedError, ValidationError)
- Mock services through DI, not via `jest.mock()` module mocking
- Assert on typed error classes: `toBeInstanceOf(NotFoundError)` not `toThrow('message')`
- Reset request-scoped state between tests: `containerPool.resetLocal()`

Forbidden: testing controller directly · `jest.mock('../service')` · `toThrow('string message')` · missing error path tests.
