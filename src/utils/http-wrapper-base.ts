/**
 * Shared HTTP Wrapper Utilities
 * Common logic for wrapping Noony handlers across different frameworks (Fastify, Express, GCP)
 * Eliminates duplication between wrapper-utils.ts and fastify-wrapper.ts
 */

import { logger } from '../core/logger';
import { HTTP_ERRORS } from '../core/constants';

/**
 * Check if error is the RESPONSE_ALREADY_SENT marker
 * Used to avoid handling errors when response has already been sent by middleware
 */
export function isResponseAlreadySent(error: unknown): boolean {
  return error instanceof Error && error.message === HTTP_ERRORS.RESPONSE_ALREADY_SENT;
}

/**
 * Standard internal server error response payload
 */
export const INTERNAL_ERROR_RESPONSE = Object.freeze({
  success: false,
  error: Object.freeze({
    code: 'INTERNAL_SERVER_ERROR',
    message: 'An unexpected error occurred',
  }),
});

/**
 * Log a handler error with context
 * @param functionName - Name of the handler for logging context
 * @param error - The error that occurred
 */
export function logHandlerError(functionName: string, error: unknown): void {
  logger.error(`${functionName} function error`, {
    error: error instanceof Error ? error.message : 'Unknown error',
    stack: error instanceof Error ? error.stack : undefined,
  });
}

/**
 * Check if response headers have already been sent
 * Works with both Express and Fastify replies
 */
export function hasHeadersBeenSent(response: { headersSent?: boolean; sent?: boolean }): boolean {
  return response.headersSent === true || response.sent === true;
}

/**
 * Send internal server error response
 * Works with Express/GCP Response objects
 */
export function sendInternalError(res: any): void {
  if (!hasHeadersBeenSent(res)) {
    res.status(500).json(INTERNAL_ERROR_RESPONSE);
  }
}

/**
 * Handle wrapper errors consistently across frameworks
 * @param error - The error to handle
 * @param functionName - Name for logging
 * @param response - Response object to send error to (if headers not sent)
 */
export function handleWrapperError(error: unknown, functionName: string, response: any): void {
  // Ignore RESPONSE_ALREADY_SENT marker errors (response already handled by middleware)
  if (isResponseAlreadySent(error)) {
    return;
  }

  // Log the real error
  logHandlerError(functionName, error);

  // Send error response only if headers haven't been sent yet
  sendInternalError(response);
}
