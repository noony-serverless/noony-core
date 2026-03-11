/**
 * Utility functions for Noony Core
 */

// Container utilities
export { getService } from './container.utils';

// Query parameter utilities
export {
  asString,
  asStringArray,
  asNumber,
  asBoolean,
} from './query-param.utils';

// Pub/Sub trace propagation utilities
export {
  isPubSubMessage,
  extractTraceContext,
  injectTraceContext,
  createParentContext,
  type PubSubMessage,
  type TraceContext,
} from './pubsub-trace.utils';

// OpenTelemetry logger integration utilities
export {
  createOTELMixin,
  getOTELContext,
  getOTELContextFromSpan,
  getOTELContextFromContext,
  formatTraceIdForCloudLogging,
  createCloudLoggingEntry,
  isOTELActive,
  isOTELInstalled,
  type OTELLogContext,
} from './otel.helper';

// HTTP wrapper base utilities (shared across frameworks)
export {
  isResponseAlreadySent,
  INTERNAL_ERROR_RESPONSE,
  logHandlerError,
  hasHeadersBeenSent,
  sendInternalError,
  handleWrapperError,
} from './http-wrapper-base';

// Wrapper utilities for GCP Functions, Express, and Fastify
export { createHttpFunction, wrapNoonyHandler } from './wrapper-utils';
export {
  createFastifyHandler,
  extractAndStoreRequestBody,
  CloudFunctionRequest,
} from './fastify-wrapper';
