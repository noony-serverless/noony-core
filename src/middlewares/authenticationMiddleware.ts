import { BaseMiddleware } from '../core/handler';
import { Context } from '../core/core';
import { AuthenticationError, HttpError } from '../core/errors';

export interface CustomTokenVerificationPort<T> {
  verifyToken(token: string): Promise<T>;
}

async function verifyToken<T>(
  tokenVerificationPort: CustomTokenVerificationPort<T>,
  context: Context
): Promise<void> {
  const authHeader = context.req.headers?.authorization;

  if (!authHeader) {
    throw new HttpError(401, 'No authorization header');
  }

  const authHeaderString = Array.isArray(authHeader)
    ? authHeader[0]
    : authHeader;
  const token = authHeaderString?.split('Bearer ')[1];
  if (!token) {
    throw new AuthenticationError('Invalid token format');
  }

  try {
    context.user = await tokenVerificationPort.verifyToken(token);
  } catch (error) {
    if (error instanceof HttpError) {
      throw error;
    }
    throw new AuthenticationError('Invalid authentication');
  }
}

export class AuthenticationMiddleware<T> implements BaseMiddleware {
  constructor(private tokenVerificationPort: CustomTokenVerificationPort<T>) {}

  async before(context: Context): Promise<void> {
    await verifyToken(this.tokenVerificationPort, context);
  }
}

export const verifyAuthTokenMiddleware = <T>(
  tokenVerificationPort: CustomTokenVerificationPort<T>
): BaseMiddleware => ({
  async before(context: Context): Promise<void> {
    await verifyToken(tokenVerificationPort, context);
  },
});

/*
// Example protected endpoint
const protectedHandler = new Handler()
  .use(verifyAuthTokenMiddleware(customTokenVerificationPort))
  .use(errorHandler())
  .use(responseWrapperMiddleware<any>())
  .handle(async (context: Context) => {
    const user = context.user;
    setResponseData(context, {
      message: 'Protected endpoint',
      user,
    });
  });
*/
