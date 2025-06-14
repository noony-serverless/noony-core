import { BaseMiddleware, Context, ValidationError } from '../core';
import { ParsedQs } from 'qs';

const validateQueryParameters = (
  requiredParams: string[],
  query: Record<string, string | string[]>
): void => {
  for (const param of requiredParams) {
    if (!query[param]) {
      throw new ValidationError(`Missing required query parameter: ${param}`);
    }
  }
};

const convertQueryToRecord = (
  query: ParsedQs
): Record<string, string | string[]> => {
  const result: Record<string, string | string[]> = {};
  for (const key in query) {
    if (query[key] !== undefined) {
      result[key] = Array.isArray(query[key])
        ? query[key].map(String)
        : String(query[key]);
    }
  }
  return result;
};

export class QueryParametersMiddleware implements BaseMiddleware {
  constructor(private readonly requiredParams: string[] = []) {}

  async before(context: Context): Promise<void> {
    const host =
      (Array.isArray(context.req.headers.host)
        ? context.req.headers.host[0]
        : context.req.headers.host) || 'localhost';
    const url = new URL(context.req.url, `http://${host}`);
    context.req.query = Object.fromEntries(url.searchParams);
    const query = convertQueryToRecord(context.req.query);
    validateQueryParameters(this.requiredParams, query);
  }
}

export const queryParametersMiddleware = (
  requiredParams: string[] = []
): BaseMiddleware => ({
  async before(context: Context): Promise<void> {
    const host =
      (Array.isArray(context.req.headers.host)
        ? context.req.headers.host[0]
        : context.req.headers.host) || 'localhost';
    const url = new URL(context.req.url, `http://${host}`);
    context.req.query = Object.fromEntries(url.searchParams);
    const query = convertQueryToRecord(context.req.query);
    validateQueryParameters(requiredParams, query);
  },
});
