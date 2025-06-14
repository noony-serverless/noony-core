'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.AuthenticationError =
  exports.ValidationError =
  exports.HttpError =
    void 0;
class HttpError extends Error {
  status;
  code;
  details;
  constructor(status, message, code, details) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
    this.name = 'HttpError';
  }
}
exports.HttpError = HttpError;
class ValidationError extends HttpError {
  constructor(message, details) {
    super(400, message, 'VALIDATION_ERROR', details);
    this.name = 'ValidationError';
  }
}
exports.ValidationError = ValidationError;
class AuthenticationError extends HttpError {
  constructor(message = 'Unauthorized') {
    super(401, message, 'AUTHENTICATION_ERROR');
    this.name = 'AuthenticationError';
  }
}
exports.AuthenticationError = AuthenticationError;
//# sourceMappingURL=errors.js.map
