/**
 * Central constants file for magic strings and numbers
 * Single source of truth for configuration values
 */

export const HTTP_ERRORS = {
  RESPONSE_ALREADY_SENT: 'RESPONSE_SENT',
} as const;

export const SIZE_LIMITS = {
  JSON_MAX_SIZE: 10000,
  BASE64_MAX_SIZE: 1024 * 1024 * 1.5,
  PAYLOAD_MAX_SIZE: 10 * 1024 * 1024, // 10MB
} as const;

export const CACHE = {
  PERMISSION_TTL_MS: 60 * 1000, // 1 minute
  RESULT_TTL_MS: 5 * 60 * 1000, // 5 minutes
  STATS_TTL_MS: 10 * 60 * 1000, // 10 minutes
} as const;

export const CONTAINER = {
  GLOBAL_ID: '__noony_global__',
  TOMBSTONE: Symbol('TOMBSTONE'),
} as const;

export const TELEMETRY = {
  DEFAULT_SERVICE_NAME: 'noony-service',
  DEFAULT_SERVICE_VERSION: '1.0.0',
  DEFAULT_ENVIRONMENT: 'production',
} as const;

export const ENV = {
  IS_DEVELOPMENT:
    process.env.NODE_ENV === 'development' || process.env.DEBUG === 'true',
  IS_TEST: process.env.NODE_ENV === 'test',
  DEBUG_API_RESPONSE: process.env.DEBUG_API_RESPONSE === 'true',
} as const;
