import { Request, Response } from '@google-cloud/functions-framework';
import Container from 'typedi';

/**
 * Represents a custom HTTP request interface extending the standard Request interface.
 * This interface allows for additional properties to manage parsed and validated request bodies.
 *
 * @template T The type of the parsed or validated body. Defaults to `unknown`.
 *
 * @property {T} [parsedBody] An optional property containing the parsed contents of the request body.
 * @property {T} [validatedBody] An optional property containing the validated contents of the request body.
 */
export interface CustomRequest<T = unknown> extends Request {
  parsedBody?: T;
  validatedBody?: T;
}

/**
 * CustomResponse is an interface extending the native Response interface
 * provided by the Fetch API. It allows for customization and enhancement of
 * the standard Response object functionalities.
 *
 * This interface can be used when additional properties or methods need to
 * be associated with the standard Response object for specific application
 * use cases.
 *
 * It inherits all properties and methods of the Fetch API's Response interface.
 */
export interface CustomResponse extends Response {}

/**
 * Represents the execution context for handling a request and response in an application.
 *
 * @template T Specifies the type of the custom request payload.
 * @template V Specifies the type of the user-related information.
 *
 * @property {CustomRequest<T>} req The custom request object that carries request-specific data.
 * @property {CustomResponse} res The custom response object for sending output to the client.
 * @property {Container} [container] An optional dependency injection container for managing services and dependencies.
 * @property {Error | null} [error] An optional error object that may store details about an error encountered during processing.
 * @property {Map<string, unknown>} businessData A map object for storing and sharing business-specific data across the context lifecycle.
 * @property {V} [user] An optional user object or data representing authenticated or associated user information.
 */
export interface Context<T = unknown, V = unknown> {
  req: CustomRequest<T>;
  res: CustomResponse;
  container?: Container;
  error?: Error | null;
  businessData: Map<string, unknown>;
  user?: V;
}
