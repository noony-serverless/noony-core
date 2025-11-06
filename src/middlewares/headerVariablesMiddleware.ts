import { BaseMiddleware, Context, ValidationError } from '../core';

const validateHeaders = (
  requiredHeaders: string[],
  headers: Record<string, string | string[] | undefined>
): void => {
  for (const header of requiredHeaders) {
    const headerValue = headers[header.toLowerCase()];
    if (
      !headerValue ||
      (Array.isArray(headerValue) && headerValue.length === 0)
    ) {
      throw new ValidationError(`Missing required header: ${header}`);
    }
  }
};

/**
 * Middleware class that validates the presence of required HTTP headers.
 * Throws a ValidationError if any required header is missing or empty.
 *
 * @implements {BaseMiddleware}
 *
 * @example
 * API key authentication via headers:
 * ```typescript
 * import { Handler, HeaderVariablesMiddleware } from '@noony-serverless/core';
 *
 * const requiredHeaders = ['authorization', 'x-api-key', 'content-type'];
 *
 * const secureApiHandler = new Handler()
 *   .use(new HeaderVariablesMiddleware(requiredHeaders))
 *   .handle(async (context) => {
 *     const authHeader = context.req.headers.authorization;
 *     const apiKey = context.req.headers['x-api-key'];
 *
 *     // Headers are guaranteed to exist after middleware validation
 *     console.log('Auth header:', authHeader);
 *     console.log('API key:', apiKey);
 *
 *     return { success: true, authenticated: true };
 *   });
 * ```
 *
 * @example
 * Content negotiation requirements:
 * ```typescript
 * const contentHeaders = ['accept', 'content-type', 'accept-language'];
 *
 * const internationalApiHandler = new Handler()
 *   .use(new HeaderVariablesMiddleware(contentHeaders))
 *   .handle(async (context) => {
 *     const acceptLang = context.req.headers['accept-language'];
 *     const contentType = context.req.headers['content-type'];
 *
 *     const language = Array.isArray(acceptLang) ? acceptLang[0] : acceptLang;
 *     const responseData = getLocalizedContent(language);
 *
 *     return { success: true, data: responseData, language };
 *   });
 * ```
 *
 * @example
 * Custom business headers validation:
 * ```typescript
 * const businessHeaders = ['x-tenant-id', 'x-request-id', 'x-client-version'];
 *
 * const multiTenantHandler = new Handler()
 *   .use(new HeaderVariablesMiddleware(businessHeaders))
 *   .handle(async (context) => {
 *     const tenantId = context.req.headers['x-tenant-id'];
 *     const requestId = context.req.headers['x-request-id'];
 *     const clientVersion = context.req.headers['x-client-version'];
 *
 *     console.log(`Processing request ${requestId} for tenant ${tenantId} with client ${clientVersion}`);
 *
 *     const tenantData = await getTenantData(tenantId as string);
 *     return { success: true, tenant: tenantData };
 *   });
 * ```
 */
export class HeaderVariablesMiddleware implements BaseMiddleware {
  constructor(private requiredHeaders: string[]) {}

  async before(context: Context): Promise<void> {
    context.req.headers = context.req.headers || {};
    validateHeaders(this.requiredHeaders, context.req.headers);
  }
}

/**
 * Factory function that creates a header validation middleware.
 * Validates that all required headers are present in the request.
 *
 * @param requiredHeaders - Array of header names that must be present
 * @returns BaseMiddleware object with header validation logic
 *
 * @example
 * Simple header validation:
 * ```typescript
 * import { Handler, headerVariablesMiddleware } from '@noony-serverless/core';
 *
 * const authHandler = new Handler()
 *   .use(headerVariablesMiddleware(['authorization']))
 *   .handle(async (context) => {
 *     const token = context.req.headers.authorization;
 *     // Proceed with authentication logic
 *     return { success: true, message: 'Authenticated' };
 *   });
 * ```
 *
 * @example
 * Multiple required headers:
 * ```typescript
 * const webhookHandler = new Handler()
 *   .use(headerVariablesMiddleware([
 *     'x-webhook-signature',
 *     'x-webhook-timestamp',
 *     'content-type'
 *   ]))
 *   .handle(async (context) => {
 *     const signature = context.req.headers['x-webhook-signature'];
 *     const timestamp = context.req.headers['x-webhook-timestamp'];
 *
 *     // Validate webhook authenticity
 *     const isValid = validateWebhookSignature(signature, timestamp, context.req.body);
 *     return { success: isValid };
 *   });
 * ```
 *
 * @example
 * API versioning through headers:
 * ```typescript
 * const versionedApiHandler = new Handler()
 *   .use(headerVariablesMiddleware(['x-api-version', 'accept']))
 *   .handle(async (context) => {
 *     const apiVersion = context.req.headers['x-api-version'];
 *     const accept = context.req.headers.accept;
 *
 *     const handler = getHandlerForVersion(apiVersion as string);
 *     return handler.process(context.req.body);
 *   });
 * ```
 */
export const headerVariablesMiddleware = (
  requiredHeaders: string[]
): BaseMiddleware => ({
  async before(context: Context): Promise<void> {
    context.req.headers = context.req.headers || {};
    validateHeaders(requiredHeaders, context.req.headers);
  },
});
