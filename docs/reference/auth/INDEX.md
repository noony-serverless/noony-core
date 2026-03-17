# Auth Reference

Noony's auth system has two layers:

- **Authentication** — Verify identity via middleware (Firebase, OAuth2, custom tokens)
- **Authorization** — Control access via RouteGuards (role checks, permission gates)

Authentication middleware validates the incoming token and populates `context.user` with the typed `TUser` object. RouteGuards then inspect that user to decide whether the request is allowed to proceed.

> **Getting started with auth?** See the [Add Authentication](../../tutorials/02-add-authentication.md) tutorial for a step-by-step walkthrough.

---

## Auth Documents

| Document | Description |
|----------|-------------|
| [Route Guards](route-guards.md) | Route-level permission checks — define who can access what |
| [Multi-Auth](multi-auth.md) | Support multiple authentication strategies in a single handler |
| [Token Validator](token-validator.md) | Build custom token validation logic for non-standard providers |
| [Firebase](firebase.md) | Firebase Authentication integration and configuration |
| [OAuth2](oauth2.md) | OAuth2 provider integration (Google, GitHub, custom) |

---

## Quick Reference

```
Handler<TBody, TUser>
  .use(FirebaseAuthMiddleware)    // Authentication: populates context.user
  .use(RouteGuard([ADMIN]))       // Authorization: checks permissions
  .handle(controller)             // Business logic runs only if both pass
```

Unauthorized requests receive a `401` (authentication failure) or `403` (authorization failure) with structured error responses.
