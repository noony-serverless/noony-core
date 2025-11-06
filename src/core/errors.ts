export class HttpError extends Error {
  status: number;
  code?: string;
  details?: unknown;

  constructor(
    status: number,
    message: string,
    code?: string,
    details?: unknown
  ) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
    this.name = 'HttpError';
  }
}

export class ValidationError extends HttpError {
  constructor(message: string, details?: unknown) {
    super(400, message, 'VALIDATION_ERROR', details);
    this.name = 'ValidationError';
  }
}

export class AuthenticationError extends HttpError {
  constructor(message: string = 'Unauthorized') {
    super(401, message, 'AUTHENTICATION_ERROR');
    this.name = 'AuthenticationError';
  }
}

export class BusinessError extends HttpError {
  constructor(message: string, status: number = 500, details?: unknown) {
    super(status, message, 'BUSINESS_ERROR', details);
    this.name = 'BusinessError';
  }
}

export class SecurityError extends HttpError {
  constructor(
    message: string = 'Security violation detected',
    details?: unknown
  ) {
    super(403, message, 'SECURITY_ERROR', details);
    this.name = 'SecurityError';
  }
}

export class TimeoutError extends HttpError {
  constructor(message: string = 'Request timeout', details?: unknown) {
    super(408, message, 'TIMEOUT_ERROR', details);
    this.name = 'TimeoutError';
  }
}

export class TooLargeError extends HttpError {
  constructor(message: string = 'Request entity too large', details?: unknown) {
    super(413, message, 'TOO_LARGE_ERROR', details);
    this.name = 'TooLargeError';
  }
}

/**
 * 401 Unauthorized - Authentication required
 * Alias for AuthenticationError for better semantic clarity
 */
export class UnauthorizedError extends HttpError {
  constructor(message: string = 'Authentication required') {
    super(401, message, 'UNAUTHORIZED_ERROR');
    this.name = 'UnauthorizedError';
  }
}

/**
 * 403 Forbidden - Insufficient permissions
 * Use this for authorization failures (user is authenticated but lacks permission)
 */
export class ForbiddenError extends HttpError {
  constructor(message: string = 'Access denied', details?: unknown) {
    super(403, message, 'FORBIDDEN_ERROR', details);
    this.name = 'ForbiddenError';
  }
}

/**
 * 404 Not Found - Resource not found
 */
export class NotFoundError extends HttpError {
  constructor(message: string = 'Resource not found', details?: unknown) {
    super(404, message, 'NOT_FOUND_ERROR', details);
    this.name = 'NotFoundError';
  }
}

/**
 * 409 Conflict - Resource already exists or state conflict
 */
export class ConflictError extends HttpError {
  constructor(message: string = 'Resource already exists', details?: unknown) {
    super(409, message, 'CONFLICT_ERROR', details);
    this.name = 'ConflictError';
  }
}

/**
 * 500 Internal Server Error - Unexpected errors with optional cause chaining
 */
export class InternalServerError extends HttpError {
  constructor(
    message: string = 'Internal server error',
    public cause?: Error,
    details?: unknown
  ) {
    super(500, message, 'INTERNAL_SERVER_ERROR', details);
    this.name = 'InternalServerError';
    if (cause) {
      this.stack = `${this.stack}\nCaused by: ${cause.stack}`;
    }
  }
}

/**
 * Service layer error with error code
 * Use this in service classes for business logic errors
 * Not tied to specific HTTP status codes
 */
export class ServiceError extends Error {
  constructor(
    message: string,
    public code: string,
    public details?: unknown
  ) {
    super(message);
    this.name = 'ServiceError';
  }
}
