export declare class HttpError extends Error {
  status: number;
  code?: string;
  details?: unknown;
  constructor(
    status: number,
    message: string,
    code?: string,
    details?: unknown
  );
}
export declare class ValidationError extends HttpError {
  constructor(message: string, details?: unknown);
}
export declare class AuthenticationError extends HttpError {
  constructor(message?: string);
}
//# sourceMappingURL=errors.d.ts.map
