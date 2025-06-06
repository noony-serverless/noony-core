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
