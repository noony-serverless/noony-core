import { HttpError, ValidationError, AuthenticationError } from './errors';

describe('HttpError', () => {
  it('creates an instance with status, message, code, and details', () => {
    const error = new HttpError(404, 'Not Found', 'NOT_FOUND', {
      resource: 'User',
    });
    expect(error.status).toBe(404);
    expect(error.message).toBe('Not Found');
    expect(error.code).toBe('NOT_FOUND');
    expect(JSON.parse(error.details)).toEqual({ resource: 'User' });
    expect(error.name).toBe('HttpError');
  });

  it('creates an instance without details', () => {
    const error = new HttpError(500, 'Internal Server Error', 'INTERNAL_ERROR');
    expect(error.status).toBe(500);
    expect(error.message).toBe('Internal Server Error');
    expect(error.code).toBe('INTERNAL_ERROR');
    expect(error.details).toBeUndefined();
    expect(error.name).toBe('HttpError');
  });
});

describe('ValidationError', () => {
  it('creates an instance with message and details', () => {
    const error = new ValidationError('Invalid input', { field: 'email' });
    expect(error.status).toBe(400);
    expect(error.message).toBe('Invalid input');
    expect(error.code).toBe('VALIDATION_ERROR');
    expect(JSON.parse(error.details)).toEqual({ field: 'email' });
    expect(error.name).toBe('ValidationError');
  });

  it('creates an instance without details', () => {
    const error = new ValidationError('Invalid input');
    expect(error.status).toBe(400);
    expect(error.message).toBe('Invalid input');
    expect(error.code).toBe('VALIDATION_ERROR');
    expect(error.details).toBeUndefined();
    expect(error.name).toBe('ValidationError');
  });
});

describe('AuthenticationError', () => {
  it('creates an instance with default message', () => {
    const error = new AuthenticationError();
    expect(error.status).toBe(401);
    expect(error.message).toBe('Unauthorized');
    expect(error.code).toBe('AUTHENTICATION_ERROR');
    expect(error.details).toBeUndefined();
    expect(error.name).toBe('AuthenticationError');
  });

  it('creates an instance with custom message', () => {
    const error = new AuthenticationError('Custom message');
    expect(error.status).toBe(401);
    expect(error.message).toBe('Custom message');
    expect(error.code).toBe('AUTHENTICATION_ERROR');
    expect(error.details).toBeUndefined();
    expect(error.name).toBe('AuthenticationError');
  });
});
