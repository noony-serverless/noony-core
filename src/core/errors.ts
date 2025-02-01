export class HttpError extends Error {
  status: number;
  code?: string;
  details?: any;

  constructor(status: number, message: string, code?: string, details?: any) {
    super(message);
    this.status = status;
    this.code = code;
    this.details =
      typeof details === 'string' ? details : JSON.stringify(details);
    this.name = 'HttpError';
  }
}

export class ValidationError extends HttpError {
  constructor(message: string, details?: any) {
    super(
      400,
      message,
      'VALIDATION_ERROR',
      details ? JSON.stringify(details) : undefined
    );
    this.name = 'ValidationError';
  }
}

export class AuthenticationError extends HttpError {
  constructor(message: string = 'Unauthorized') {
    super(401, message, 'AUTHENTICATION_ERROR');
    this.name = 'AuthenticationError';
  }
}
