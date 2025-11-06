/**
 * Query parameter utility functions for type-safe handling of query parameters
 * that can be string | string[] | undefined
 */

/**
 * Convert query parameter to single string
 * Takes the first value if array is provided
 *
 * @param value - Query parameter value
 * @returns First string value or undefined
 *
 * @example
 * ```typescript
 * const search = asString(context.req.query.search);
 * // If query.search = "hello" → "hello"
 * // If query.search = ["hello", "world"] → "hello"
 * // If query.search = undefined → undefined
 * ```
 */
export function asString(
  value: string | string[] | undefined
): string | undefined {
  if (Array.isArray(value)) {
    return value[0];
  }
  return value;
}

/**
 * Convert query parameter to string array
 * Returns array if single value is provided
 *
 * @param value - Query parameter value
 * @returns Array of strings or undefined
 *
 * @example
 * ```typescript
 * const tags = asStringArray(context.req.query.tags);
 * // If query.tags = "javascript" → ["javascript"]
 * // If query.tags = ["javascript", "typescript"] → ["javascript", "typescript"]
 * // If query.tags = undefined → undefined
 * ```
 */
export function asStringArray(
  value: string | string[] | undefined
): string[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (Array.isArray(value)) {
    return value;
  }
  return [value];
}

/**
 * Convert query parameter to number
 * Parses the value as integer (base 10)
 *
 * @param value - Query parameter value
 * @returns Parsed number or undefined if invalid
 *
 * @example
 * ```typescript
 * const page = asNumber(context.req.query.page) || 1;
 * // If query.page = "5" → 5
 * // If query.page = ["10", "20"] → 10 (first value)
 * // If query.page = "invalid" → undefined
 * // If query.page = undefined → undefined
 * ```
 */
export function asNumber(
  value: string | string[] | undefined
): number | undefined {
  const str = asString(value);
  if (!str) {
    return undefined;
  }
  const num = parseInt(str, 10);
  return isNaN(num) ? undefined : num;
}

/**
 * Convert query parameter to boolean
 * Treats "true" and "1" as true, everything else as false
 *
 * @param value - Query parameter value
 * @returns Boolean value or undefined if not provided
 *
 * @example
 * ```typescript
 * const isActive = asBoolean(context.req.query.active);
 * // If query.active = "true" → true
 * // If query.active = "1" → true
 * // If query.active = "false" → false
 * // If query.active = "0" → false
 * // If query.active = undefined → undefined
 * ```
 */
export function asBoolean(
  value: string | string[] | undefined
): boolean | undefined {
  const str = asString(value);
  if (str === undefined) {
    return undefined;
  }
  return str.toLowerCase() === 'true' || str === '1';
}
