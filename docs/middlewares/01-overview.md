# Middleware Reference

Quick-reference decision matrix for all built-in Noony middlewares.

## Middleware Catalogue

| Middleware | Purpose | When to use | Key option |
| ---------- | ------- | ----------- | ---------- |
| `ErrorHandlerMiddleware` | Catches all pipeline errors and maps them to HTTP status codes | Every handler | None |
| `DependencyInjectionMiddleware` | Populates `context.container` with registered services | When handlers need services | `services: ServiceEntry[]` |
| `BodyParserMiddleware<T>` | Decodes raw request body (JSON + Pub/Sub) into `context.req.parsedBody` | Any handler that reads a body | `maxBytes?: number` |
| `BodyValidationMiddleware<T, U>` | Validates `parsedBody` against a Zod schema; sets `context.req.validatedBody` | After `BodyParserMiddleware` | `schema: ZodType<T>` |
| `HeaderVariablesMiddleware` | Asserts required headers are present and non-empty | Auth, API-key, tenant headers | `requiredHeaders: string[]` |
| `PathParametersMiddleware` | Copies route params into `context.req.params` | RESTful resource handlers | None |
| `QueryParametersMiddleware` | Parses and optionally requires query string params | Filtering, pagination | `required?: string[]` |
| `ResponseWrapperMiddleware` | Wraps controller return value in a standard envelope | Every handler | None |

## Canonical Middleware Ordering

Add middlewares to `.use()` in this order. The `before` hooks run top-to-bottom; the `after`/`onError` hooks run bottom-to-top.

| Position | Middleware | Rationale |
| -------- | ---------- | --------- |
| 1 | `ErrorHandlerMiddleware` | Must be first so its `onError` hook fires last and can shape every error response |
| 2 | `DependencyInjectionMiddleware` | Services must exist before any middleware that calls them |
| 3 | `HeaderVariablesMiddleware` | Cheap fail-fast check before any expensive work |
| 4 | `PathParametersMiddleware` | Needed by auth/guard middleware that reads resource IDs |
| 5 | `QueryParametersMiddleware` | Parsed before business-logic middleware may inspect them |
| 6 | `BodyParserMiddleware` | Body must be parsed before it can be validated |
| 7 | `BodyValidationMiddleware` | Must follow parser |
| 8 | Auth / guard middlewares | Runs after all inputs are available |
| last | `ResponseWrapperMiddleware` | Runs `after` hook after the controller returns |

## Constructor Signatures

```typescript
new ErrorHandlerMiddleware()

new DependencyInjectionMiddleware(services: Array<{ id: any; value: any }>)

new BodyParserMiddleware<T>(maxBytes?: number)
bodyParser<T>(maxBytes?: number)                        // functional alias

new BodyValidationMiddleware<TBody, TUser>(schema: ZodType<TBody>)
bodyValidatorMiddleware<TBody, TUser>(schema: ZodType<TBody>)  // functional alias

new HeaderVariablesMiddleware(requiredHeaders: string[])
headerVariablesMiddleware(requiredHeaders: string[])    // functional alias

new PathParametersMiddleware()
pathParameters()                                        // functional alias

new QueryParametersMiddleware(required?: string[])
queryParametersMiddleware(required?: string[])          // functional alias

new ResponseWrapperMiddleware()
```

## Individual How-to Guides

- [How to Parse Request Bodies](./02-body-parser.md)
- [How to Validate Request Bodies with Zod](./03-body-validation.md)
- [How to Validate Required HTTP Headers](./04-headers.md)
- [How to Extract and Validate Query Parameters](./05-query-params.md)
- [How to Inject Services into Handlers](./06-dependency-injection.md)
- [How to Compose Middleware Pipelines](./07-integration-guide.md)
