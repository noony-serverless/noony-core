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

export class HeaderVariablesMiddleware implements BaseMiddleware {
  constructor(private requiredHeaders: string[]) {}

  async before(context: Context): Promise<void> {
    context.req.headers = context.req.headers || {};
    validateHeaders(this.requiredHeaders, context.req.headers);
  }
}

export const headerVariablesMiddleware = (
  requiredHeaders: string[]
): BaseMiddleware => ({
  async before(context: Context): Promise<void> {
    context.req.headers = context.req.headers || {};
    validateHeaders(requiredHeaders, context.req.headers);
  },
});
