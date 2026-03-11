/**
 * Error Categorizer
 * Converts Error objects to standardized error categories with HTTP status codes
 * Reusable across middleware and applications
 */

export interface ErrorCategory {
  type: string;
  userMessage: string;
  httpStatus: number;
  retryable: boolean;
}

export interface ErrorMatcher {
  matches: (error: Error) => boolean;
  category: ErrorCategory;
}

// Pre-allocated static error categories
const DATABASE_ERROR: ErrorCategory = {
  type: 'DATABASE_ERROR',
  userMessage: 'Database temporarily unavailable. Please try again.',
  httpStatus: 503,
  retryable: true,
};

const TIMEOUT_ERROR: ErrorCategory = {
  type: 'TIMEOUT_ERROR',
  userMessage: 'Request took too long. Please try again.',
  httpStatus: 504,
  retryable: true,
};

const EXTERNAL_SERVICE_ERROR: ErrorCategory = {
  type: 'EXTERNAL_SERVICE_ERROR',
  userMessage: 'External service unavailable. Please try again later.',
  httpStatus: 502,
  retryable: true,
};

const INTERNAL_ERROR: ErrorCategory = {
  type: 'INTERNAL_ERROR',
  userMessage: 'An unexpected error occurred.',
  httpStatus: 500,
  retryable: false,
};

/**
 * Categorizes errors into standardized categories
 * Uses pattern matching for flexible error detection
 */
export class ErrorCategorizer {
  private patterns: Map<RegExp, ErrorCategory>;

  constructor() {
    this.patterns = new Map<RegExp, ErrorCategory>([
      // Timeout errors
      [/timeout|timed out/i, TIMEOUT_ERROR],
      [/deadline exceeded/i, TIMEOUT_ERROR],

      // Database errors
      [/mongodb|mongoose/i, DATABASE_ERROR],
      [/postgres|postgresql/i, DATABASE_ERROR],
      [/mysql/i, DATABASE_ERROR],
      [/database connection/i, DATABASE_ERROR],
      [/deadlock|locked/i, DATABASE_ERROR],

      // External service errors
      [/econnrefused|econnreset/i, EXTERNAL_SERVICE_ERROR],
      [/getaddrinfo|dns/i, EXTERNAL_SERVICE_ERROR],
      [/socket hang up/i, EXTERNAL_SERVICE_ERROR],
      [/too many requests|rate.?limit/i, EXTERNAL_SERVICE_ERROR],
    ]);
  }

  /**
   * Categorize an error using custom matchers first, then built-in patterns
   */
  categorize(error: Error, customMatchers?: ErrorMatcher[]): ErrorCategory {
    // Check custom matchers first (highest priority)
    if (customMatchers) {
      for (const matcher of customMatchers) {
        if (matcher.matches(error)) {
          return matcher.category;
        }
      }
    }

    // Check built-in patterns
    const message = error.message;
    for (const [pattern, category] of this.patterns) {
      if (pattern.test(message)) {
        return category;
      }
    }

    // Default fallback
    return INTERNAL_ERROR;
  }

  /**
   * Register a custom pattern for error categorization
   */
  addPattern(pattern: RegExp, category: ErrorCategory): void {
    this.patterns.set(pattern, category);
  }
}

// Singleton instance for reuse
export const defaultCategorizer = new ErrorCategorizer();
