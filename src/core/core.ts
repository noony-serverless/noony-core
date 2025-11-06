<<<<<<< Updated upstream
import { Request, Response } from '@google-cloud/functions-framework';
import Container from 'typedi';
=======
import { Container, ContainerInstance } from 'typedi';
>>>>>>> Stashed changes

/**
 * Framework-agnostic HTTP method enum
 */
export enum HttpMethod {
  GET = 'GET',
  POST = 'POST',
  PUT = 'PUT',
  DELETE = 'DELETE',
  PATCH = 'PATCH',
  OPTIONS = 'OPTIONS',
  HEAD = 'HEAD',
}

/**
 * Framework-agnostic request interface that can work with any HTTP framework
 */
export interface GenericRequest<T = unknown> {
  method: HttpMethod | string;
  url: string;
  path?: string;
  headers: Record<string, string | string[] | undefined>;
  query: Record<string, string | string[] | undefined>;
  params: Record<string, string>;
  body?: unknown;
  rawBody?: Buffer | string;
  parsedBody?: T;
  validatedBody?: T;
  ip?: string;
  userAgent?: string;
}

/**
 * Framework-agnostic response interface that can work with any HTTP framework
 */
export interface GenericResponse {
  status(code: number): GenericResponse;
  json(data: unknown): GenericResponse | void;
  send(data: unknown): GenericResponse | void;
  header(name: string, value: string): GenericResponse;
  headers(headers: Record<string, string>): GenericResponse;
  end(): void;
  statusCode?: number;
  headersSent?: boolean;
}

/**
 * Legacy GCP Functions-specific request interface for backward compatibility
 * @deprecated Use GenericRequest instead
 */
export interface CustomRequest<T = unknown> extends Request {
  parsedBody?: T;
  validatedBody?: T;
}

/**
 * Legacy GCP Functions-specific response interface for backward compatibility
 * @deprecated Use GenericResponse instead
 */
export interface CustomResponse extends Response {}

/**
 * Security configuration for request processing
 */
export interface SecurityConfig {
  maxBodySize?: number;
  maxDepth?: number;
  allowedContentTypes?: string[];
  enableSanitization?: boolean;
}

/**
 * Handler configuration options
 */
export interface HandlerOptions {
  timeout?: number;
  middlewareTimeout?: number;
  security?: SecurityConfig;
  enableAsyncContext?: boolean;
}

/**
 * Represents the execution context for handling a request and response in an application.
 *
 * @template T Specifies the type of the custom request payload.
 * @template V Specifies the type of the user-related information.
 */
<<<<<<< Updated upstream
export interface Context<T = unknown, V = unknown> {
  readonly req: GenericRequest<T>;
  readonly res: GenericResponse;
  container?: Container;
=======
export interface Context<T = unknown> {
  readonly req: NoonyRequest<T>;
  readonly res: NoonyResponse;
  container: ContainerInstance;
>>>>>>> Stashed changes
  error?: Error | null;
  readonly businessData: Map<string, unknown>;
  user?: V;
  readonly startTime: number;
  readonly requestId: string;
  timeoutSignal?: AbortSignal;
  responseData?: unknown;
}

/**
 * Legacy context interface for backward compatibility
 * @deprecated Use Context with GenericRequest/GenericResponse instead
 */
export interface LegacyContext<T = unknown, V = unknown> {
  req: CustomRequest<T>;
  res: CustomResponse;
  container?: Container;
  error?: Error | null;
  businessData: Map<string, unknown>;
  user?: V;
}

/**
 * Utility function to generate unique request IDs
 */
export function generateRequestId(): string {
  return `req_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
}

/**
 * Adapter to convert GCP Functions Request to GenericRequest
 */
export function adaptGCPRequest<T = unknown>(
  gcpRequest: Request
): GenericRequest<T> {
  return {
    method: (gcpRequest.method as HttpMethod) || HttpMethod.GET,
    url: gcpRequest.url || '/',
    path: gcpRequest.path,
    headers: (gcpRequest.headers as Record<string, string>) || {},
    query: (gcpRequest.query as Record<string, string>) || {},
    params: (gcpRequest.params as Record<string, string>) || {},
    body: gcpRequest.body,
    rawBody: gcpRequest.rawBody,
    ip: gcpRequest.ip,
    userAgent: gcpRequest.get?.('user-agent'),
  };
}

/**
 * Adapter to convert GCP Functions Response to GenericResponse
 */
export function adaptGCPResponse(gcpResponse: Response): GenericResponse {
  let currentStatusCode = 200;
  let isHeadersSent = false;

  return {
    status: (code: number): GenericResponse => {
      currentStatusCode = code;
      gcpResponse.status(code);
      return adaptGCPResponse(gcpResponse);
    },
    json: (data: unknown): void => {
      isHeadersSent = true;
      gcpResponse.json(data);
    },
    send: (data: unknown): void => {
      isHeadersSent = true;
      gcpResponse.send(data);
    },
    header: (name: string, value: string): GenericResponse => {
      gcpResponse.header(name, value);
      return adaptGCPResponse(gcpResponse);
    },
    headers: (headers: Record<string, string>): GenericResponse => {
      Object.entries(headers).forEach(([key, value]) => {
        gcpResponse.header(key, value);
      });
      return adaptGCPResponse(gcpResponse);
    },
    end: (): void => {
      isHeadersSent = true;
      gcpResponse.end();
    },
    get statusCode(): number {
      return gcpResponse.statusCode || currentStatusCode;
    },
    get headersSent(): boolean {
      return gcpResponse.headersSent || isHeadersSent;
    },
  };
}

/**
 * Creates a context object for framework-agnostic handlers
 */
export function createContext<T = unknown, V = unknown>(
  req: GenericRequest<T>,
  res: GenericResponse,
  options: Partial<Context<T, V>> = {}
): Context<T, V> {
  return {
    req,
    res,
    container: options.container || Container.of(),
    error: options.error || null,
    businessData: options.businessData || new Map<string, unknown>(),
    user: options.user,
    startTime: options.startTime || Date.now(),
    requestId: options.requestId || generateRequestId(),
    timeoutSignal: options.timeoutSignal,
    responseData: options.responseData,
  };
}
