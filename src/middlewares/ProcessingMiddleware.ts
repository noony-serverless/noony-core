import {
  BaseMiddleware,
  Context,
  ValidationError,
  TooLargeError,
  NoonyRequest,
} from '../core';

/**
 * Configuration for body parsing functionality
 */
export interface BodyParserConfig {
  maxSize?: number;
  supportPubSub?: boolean;
  allowEmptyBody?: boolean;
  customParser?: (body: unknown) => Promise<unknown> | unknown;
  enableAsyncParsing?: boolean;
  asyncThreshold?: number; // Size threshold for async parsing
}

/**
 * Configuration for query parameter processing
 */
export interface QueryProcessingConfig {
  parseArrays?: boolean;
  parseNumbers?: boolean;
  parseBooleans?: boolean;
  maxKeys?: number;
  delimiter?: string;
  arrayDelimiter?: string;
  customParser?: (query: Record<string, unknown>) => Record<string, unknown>;
}

/**
 * Configuration for HTTP attributes extraction
 */
export interface AttributesConfig {
  extractIP?: boolean;
  extractUserAgent?: boolean;
  extractTimestamp?: boolean;
  extractContentLength?: boolean;
  extractAcceptLanguage?: boolean;
  extractReferer?: boolean;
  customExtractors?: Record<string, (req: NoonyRequest) => unknown>;
  trustProxy?: boolean; // Trust X-Forwarded-* headers
}

/**
 * Complete configuration for ProcessingMiddleware
 */
export interface ProcessingMiddlewareConfig {
  parser?: BodyParserConfig;
  query?: QueryProcessingConfig;
  attributes?: AttributesConfig;
  skipProcessing?: (context: Context) => boolean;
}

interface PubSubMessage {
  message: {
    data: string;
    publishTime?: string;
    messageId?: string;
    attributes?: Record<string, string>;
  };
}

/**
 * Consolidated ProcessingMiddleware that combines body parsing, query processing, and attribute extraction.
 *
 * This middleware replaces the need for separate:
 * - BodyParserMiddleware
 * - QueryParametersMiddleware
 * - HttpAttributesMiddleware
 *
 * @example
 * Complete processing setup:
 * ```typescript
 * const handler = new Handler()
 *   .use(new ProcessingMiddleware({
 *     parser: {
 *       maxSize: 1024 * 1024, // 1MB
 *       supportPubSub: true,
 *       enableAsyncParsing: true
 *     },
 *     query: {
 *       parseArrays: true,
 *       parseNumbers: true,
 *       parseBooleans: true,
 *       maxKeys: 100
 *     },
 *     attributes: {
 *       extractIP: true,
 *       extractUserAgent: true,
 *       extractTimestamp: true,
 *       trustProxy: true
 *     }
 *   }))
 *   .handle(async (context) => {
 *     // context.req.parsedBody contains parsed JSON
 *     // context.req.query contains processed query parameters
 *     // context.req.ip, context.req.userAgent, etc. are extracted
 *     return { message: 'Processing complete' };
 *   });
 * ```
 *
 * @example
 * Parser-only for API endpoints:
 * ```typescript
 * const handler = new Handler()
 *   .use(new ProcessingMiddleware({
 *     parser: {
 *       maxSize: 512 * 1024, // 512KB
 *       supportPubSub: false
 *     }
 *   }));
 * ```
 */
export class ProcessingMiddleware implements BaseMiddleware {
  private config: ProcessingMiddlewareConfig;

  constructor(config: ProcessingMiddlewareConfig = {}) {
    this.config = {
      parser: {
        maxSize: 1024 * 1024, // 1MB default
        supportPubSub: true,
        allowEmptyBody: true,
        enableAsyncParsing: true,
        asyncThreshold: 10000, // 10KB
      },
      query: {
        parseArrays: false,
        parseNumbers: false,
        parseBooleans: false,
        maxKeys: 1000,
        delimiter: '&',
        arrayDelimiter: ',',
      },
      attributes: {
        extractIP: true,
        extractUserAgent: true,
        extractTimestamp: false,
        trustProxy: false,
      },
      ...config,
    };
  }

  async before(context: Context): Promise<void> {
    // Skip processing if custom skip function returns true
    if (this.config.skipProcessing && this.config.skipProcessing(context)) {
      return;
    }

    // 1. Extract HTTP attributes first (lightweight)
    if (this.config.attributes) {
      await this.extractAttributes(context);
    }

    // 2. Process query parameters (moderate cost)
    if (this.config.query) {
      await this.processQueryParameters(context);
    }

    // 3. Parse body (most expensive, do last)
    if (this.config.parser) {
      await this.parseBody(context);
    }
  }

  private async extractAttributes(context: Context): Promise<void> {
    const attributesConfig = this.config.attributes!;
    const req = context.req;

    // Extract IP address
    if (attributesConfig.extractIP) {
      req.ip = this.extractIPAddress(req, attributesConfig.trustProxy || false);
    }

    // Extract User-Agent
    if (attributesConfig.extractUserAgent) {
      req.userAgent = this.extractUserAgent(req);
    }

    // Extract timestamp
    if (attributesConfig.extractTimestamp) {
      (req as NoonyRequest & { timestamp: string }).timestamp =
        new Date().toISOString();
    }

    // Extract content length
    if (attributesConfig.extractContentLength) {
      (req as NoonyRequest & { contentLength?: number }).contentLength =
        this.extractContentLength(req);
    }

    // Extract Accept-Language
    if (attributesConfig.extractAcceptLanguage) {
      (req as NoonyRequest & { acceptLanguage?: string }).acceptLanguage =
        this.extractAcceptLanguage(req);
    }

    // Extract Referer
    if (attributesConfig.extractReferer) {
      (req as NoonyRequest & { referer?: string }).referer =
        this.extractReferer(req);
    }

    // Apply custom extractors
    if (attributesConfig.customExtractors) {
      for (const [key, extractor] of Object.entries(
        attributesConfig.customExtractors
      )) {
        try {
          (req as NoonyRequest & Record<string, unknown>)[key] = extractor(req);
        } catch (error) {
          console.warn(`Custom extractor '${key}' failed:`, error);
        }
      }
    }
  }

  private async processQueryParameters(context: Context): Promise<void> {
    const queryConfig = this.config.query!;
    const query = context.req.query || {};

    // Check max keys limit
    if (
      queryConfig.maxKeys &&
      Object.keys(query).length > queryConfig.maxKeys
    ) {
      throw new ValidationError(
        'Too many query parameters',
        `Maximum ${queryConfig.maxKeys} query parameters allowed`
      );
    }

    // Apply custom parser first if provided
    if (queryConfig.customParser) {
      try {
        context.req.query = queryConfig.customParser(query) as Record<
          string,
          string | string[] | undefined
        >;
        return;
      } catch (error) {
        throw new ValidationError(
          'Query parameter parsing failed',
          error instanceof Error ? error.message : 'Custom parser error'
        );
      }
    }

    // Process each query parameter
    const processedQuery: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(query)) {
      processedQuery[key] = this.processQueryValue(
        value,
        queryConfig.parseArrays || false,
        queryConfig.parseNumbers || false,
        queryConfig.parseBooleans || false,
        queryConfig.arrayDelimiter || ','
      );
    }

    context.req.query = processedQuery as Record<
      string,
      string | string[] | undefined
    >;
  }

  private async parseBody(context: Context): Promise<void> {
    const parserConfig = this.config.parser!;
    const body = context.req.body;

    // Skip if no body or body is already parsed
    if (!body || context.req.parsedBody) {
      if (parserConfig.allowEmptyBody) {
        return;
      }
      throw new ValidationError('Request body is required');
    }

    // Apply custom parser if provided
    if (parserConfig.customParser) {
      try {
        context.req.parsedBody = await parserConfig.customParser(body);
        return;
      } catch (error) {
        throw new ValidationError(
          'Custom body parsing failed',
          error instanceof Error ? error.message : 'Custom parser error'
        );
      }
    }

    // Handle different body types
    if (typeof body === 'string') {
      await this.parseStringBody(context, body, parserConfig);
    } else if (typeof body === 'object' && body !== null) {
      // Handle PubSub messages if enabled
      if (parserConfig.supportPubSub && this.isPubSubMessage(body)) {
        await this.parsePubSubMessage(context, body, parserConfig);
      } else {
        // Already an object, store as is
        context.req.parsedBody = body;
      }
    } else {
      context.req.parsedBody = body;
    }
  }

  private async parseStringBody(
    context: Context,
    body: string,
    config: BodyParserConfig
  ): Promise<void> {
    // Check size limit
    if (config.maxSize && Buffer.byteLength(body, 'utf8') > config.maxSize) {
      throw new TooLargeError(
        `Request body size exceeds limit of ${config.maxSize} bytes`
      );
    }

    try {
      // Use async parsing for large payloads if enabled
      if (
        config.enableAsyncParsing &&
        body.length > (config.asyncThreshold || 10000)
      ) {
        context.req.parsedBody = await this.parseJsonAsync(body);
      } else {
        context.req.parsedBody = JSON.parse(body);
      }
    } catch (error) {
      throw new ValidationError(
        'Invalid JSON body',
        error instanceof Error ? error.message : 'JSON parsing failed'
      );
    }
  }

  private async parsePubSubMessage(
    context: Context,
    body: PubSubMessage,
    config: BodyParserConfig
  ): Promise<void> {
    try {
      const encodedData = body.message.data;

      // Validate base64 format
      this.validateBase64Format(encodedData);

      // Check size limit before decoding
      if (config.maxSize && encodedData.length > config.maxSize * 1.33) {
        // Account for base64 overhead
        throw new TooLargeError(
          `PubSub message size exceeds limit of ${config.maxSize} bytes`
        );
      }

      // Decode base64 data
      const decodedData = Buffer.from(encodedData, 'base64').toString('utf-8');

      // Parse JSON content
      context.req.parsedBody =
        config.enableAsyncParsing &&
        decodedData.length > (config.asyncThreshold || 10000)
          ? await this.parseJsonAsync(decodedData)
          : JSON.parse(decodedData);

      // Store PubSub metadata
      (
        context.req as NoonyRequest & {
          pubsubMetadata: {
            publishTime?: string;
            messageId?: string;
            attributes?: Record<string, string>;
          };
        }
      ).pubsubMetadata = {
        publishTime: body.message.publishTime,
        messageId: body.message.messageId,
        attributes: body.message.attributes,
      };
    } catch (error) {
      throw new ValidationError(
        'PubSub message parsing failed',
        error instanceof Error ? error.message : 'PubSub parsing error'
      );
    }
  }

  private processQueryValue(
    value: unknown,
    parseArrays: boolean,
    parseNumbers: boolean,
    parseBooleans: boolean,
    arrayDelimiter: string
  ): unknown {
    if (typeof value !== 'string') {
      return value; // Return as-is if not string
    }

    // Handle arrays
    if (parseArrays && value.includes(arrayDelimiter)) {
      return value
        .split(arrayDelimiter)
        .map((item) =>
          this.processQueryValue(
            item.trim(),
            false,
            parseNumbers,
            parseBooleans,
            arrayDelimiter
          )
        );
    }

    // Handle booleans
    if (parseBooleans) {
      const lowerValue = value.toLowerCase();
      if (lowerValue === 'true') return true;
      if (lowerValue === 'false') return false;
    }

    // Handle numbers
    if (parseNumbers && /^-?\d+(\.\d+)?$/.test(value)) {
      const numValue = Number(value);
      if (!isNaN(numValue)) return numValue;
    }

    return value; // Return as string if no parsing applied
  }

  private extractIPAddress(req: NoonyRequest, trustProxy: boolean): string {
    if (trustProxy) {
      // Check X-Forwarded-For headers
      const xForwardedFor =
        req.headers?.['x-forwarded-for'] || req.headers?.['X-Forwarded-For'];
      if (xForwardedFor) {
        const ips = Array.isArray(xForwardedFor)
          ? xForwardedFor[0]
          : xForwardedFor;
        return typeof ips === 'string' ? ips.split(',')[0].trim() : ips;
      }

      const xRealIP = req.headers?.['x-real-ip'] || req.headers?.['X-Real-IP'];
      if (xRealIP && typeof xRealIP === 'string') {
        return xRealIP;
      }
    }

    // Fallback to direct IP sources
    return (
      req.ip ||
      (req as NoonyRequest & { connection?: { remoteAddress?: string } })
        .connection?.remoteAddress ||
      (req as NoonyRequest & { socket?: { remoteAddress?: string } }).socket
        ?.remoteAddress ||
      (
        req as NoonyRequest & {
          requestContext?: { identity?: { sourceIp?: string } };
        }
      ).requestContext?.identity?.sourceIp ||
      'unknown'
    );
  }

  private extractUserAgent(req: NoonyRequest): string {
    const userAgent =
      req.headers?.['user-agent'] ||
      req.headers?.['User-Agent'] ||
      (
        req as NoonyRequest & { get?: (header: string) => string | undefined }
      ).get?.('user-agent') ||
      'unknown';

    return Array.isArray(userAgent) ? userAgent[0] : userAgent;
  }

  private extractContentLength(req: NoonyRequest): number | undefined {
    const contentLength =
      req.headers?.['content-length'] || req.headers?.['Content-Length'];
    const lengthValue = Array.isArray(contentLength)
      ? contentLength[0]
      : contentLength;
    return lengthValue ? parseInt(lengthValue, 10) : undefined;
  }

  private extractAcceptLanguage(req: NoonyRequest): string | undefined {
    const acceptLanguage =
      req.headers?.['accept-language'] || req.headers?.['Accept-Language'];
    return Array.isArray(acceptLanguage) ? acceptLanguage[0] : acceptLanguage;
  }

  private extractReferer(req: NoonyRequest): string | undefined {
    const referer =
      req.headers?.referer ||
      req.headers?.Referer ||
      req.headers?.referrer ||
      req.headers?.Referrer;

    return Array.isArray(referer) ? referer[0] : referer;
  }

  private isPubSubMessage(body: unknown): body is PubSubMessage {
    return (
      !!body &&
      typeof body === 'object' &&
      'message' in body &&
      typeof (body as PubSubMessage).message === 'object' &&
      'data' in (body as PubSubMessage).message &&
      typeof (body as PubSubMessage).message.data === 'string'
    );
  }

  private validateBase64Format(base64Data: string): void {
    // Basic base64 format validation
    const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;

    if (!base64Regex.test(base64Data)) {
      throw new ValidationError('Invalid base64 format in PubSub message');
    }

    if (base64Data.length % 4 !== 0) {
      throw new ValidationError(
        'Invalid base64 length - must be multiple of 4'
      );
    }
  }

  private async parseJsonAsync<T = unknown>(jsonString: string): Promise<T> {
    // Use setImmediate to make JSON parsing non-blocking for large payloads
    return new Promise((resolve, reject) => {
      setImmediate(() => {
        try {
          const result = JSON.parse(jsonString) as T;
          resolve(result);
        } catch (error) {
          reject(
            new ValidationError(
              'Invalid JSON body',
              error instanceof Error ? error.message : 'JSON parsing failed'
            )
          );
        }
      });
    });
  }
}

/**
 * Factory functions for creating ProcessingMiddleware with common configurations
 */
export const createProcessingMiddleware = {
  /**
   * API processing with JSON parsing and basic attributes
   */
  api: (): ProcessingMiddleware =>
    new ProcessingMiddleware({
      parser: { maxSize: 1024 * 1024, supportPubSub: false },
      query: { parseNumbers: true, parseBooleans: true, maxKeys: 100 },
      attributes: { extractIP: true, extractUserAgent: true },
    }),

  /**
   * PubSub processing with base64 decoding
   */
  pubsub: (): ProcessingMiddleware =>
    new ProcessingMiddleware({
      parser: {
        maxSize: 2 * 1024 * 1024,
        supportPubSub: true,
        enableAsyncParsing: true,
      },
      attributes: { extractIP: true, extractTimestamp: true },
    }),

  /**
   * Lightweight processing for simple endpoints
   */
  lightweight: (): ProcessingMiddleware =>
    new ProcessingMiddleware({
      parser: {
        maxSize: 64 * 1024,
        supportPubSub: false,
        enableAsyncParsing: false,
      },
      query: { parseNumbers: false, parseBooleans: false, maxKeys: 20 },
      attributes: { extractIP: false, extractUserAgent: false },
    }),

  /**
   * Full processing with all features enabled
   */
  complete: (): ProcessingMiddleware =>
    new ProcessingMiddleware({
      parser: {
        maxSize: 5 * 1024 * 1024,
        supportPubSub: true,
        enableAsyncParsing: true,
        asyncThreshold: 50000,
      },
      query: {
        parseArrays: true,
        parseNumbers: true,
        parseBooleans: true,
        maxKeys: 1000,
      },
      attributes: {
        extractIP: true,
        extractUserAgent: true,
        extractTimestamp: true,
        extractContentLength: true,
        extractAcceptLanguage: true,
        extractReferer: true,
        trustProxy: true,
      },
    }),
};
