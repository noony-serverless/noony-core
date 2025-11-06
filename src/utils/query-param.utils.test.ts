import {
  asString,
  asStringArray,
  asNumber,
  asBoolean,
} from './query-param.utils';

describe('Query Parameter Utilities', () => {
  describe('asString', () => {
    it('should return string value as-is', () => {
      expect(asString('hello')).toBe('hello');
    });

    it('should return first element of array', () => {
      expect(asString(['first', 'second', 'third'])).toBe('first');
    });

    it('should return undefined for undefined input', () => {
      expect(asString(undefined)).toBeUndefined();
    });

    it('should return undefined for empty array', () => {
      expect(asString([])).toBeUndefined();
    });

    it('should handle empty string', () => {
      expect(asString('')).toBe('');
    });

    it('should handle single-element array', () => {
      expect(asString(['only'])).toBe('only');
    });
  });

  describe('asStringArray', () => {
    it('should return array value as-is', () => {
      const arr = ['one', 'two', 'three'];
      expect(asStringArray(arr)).toEqual(arr);
    });

    it('should wrap single string in array', () => {
      expect(asStringArray('single')).toEqual(['single']);
    });

    it('should return undefined for undefined input', () => {
      expect(asStringArray(undefined)).toBeUndefined();
    });

    it('should handle empty string by wrapping it', () => {
      expect(asStringArray('')).toEqual(['']);
    });

    it('should handle empty array', () => {
      expect(asStringArray([])).toEqual([]);
    });
  });

  describe('asNumber', () => {
    it('should parse valid number string', () => {
      expect(asNumber('42')).toBe(42);
    });

    it('should parse negative numbers', () => {
      expect(asNumber('-10')).toBe(-10);
    });

    it('should parse zero', () => {
      expect(asNumber('0')).toBe(0);
    });

    it('should parse first element of array', () => {
      expect(asNumber(['123', '456'])).toBe(123);
    });

    it('should return undefined for invalid number string', () => {
      expect(asNumber('not-a-number')).toBeUndefined();
    });

    it('should return undefined for undefined input', () => {
      expect(asNumber(undefined)).toBeUndefined();
    });

    it('should return undefined for empty string', () => {
      expect(asNumber('')).toBeUndefined();
    });

    it('should parse integer from decimal string (truncates)', () => {
      expect(asNumber('42.7')).toBe(42);
    });

    it('should handle leading/trailing whitespace', () => {
      expect(asNumber(' 42 ')).toBe(42);
    });

    it('should return undefined for empty array', () => {
      expect(asNumber([])).toBeUndefined();
    });

    it('should handle very large numbers', () => {
      expect(asNumber('999999999')).toBe(999999999);
    });
  });

  describe('asBoolean', () => {
    it('should return true for "true" string', () => {
      expect(asBoolean('true')).toBe(true);
    });

    it('should return true for "1" string', () => {
      expect(asBoolean('1')).toBe(true);
    });

    it('should return true for "TRUE" (case insensitive)', () => {
      expect(asBoolean('TRUE')).toBe(true);
    });

    it('should return true for "True" (mixed case)', () => {
      expect(asBoolean('True')).toBe(true);
    });

    it('should return false for "false" string', () => {
      expect(asBoolean('false')).toBe(false);
    });

    it('should return false for "0" string', () => {
      expect(asBoolean('0')).toBe(false);
    });

    it('should return false for any other string', () => {
      expect(asBoolean('random')).toBe(false);
      expect(asBoolean('yes')).toBe(false);
      expect(asBoolean('no')).toBe(false);
    });

    it('should return undefined for undefined input', () => {
      expect(asBoolean(undefined)).toBeUndefined();
    });

    it('should return false for empty string', () => {
      expect(asBoolean('')).toBe(false);
    });

    it('should use first element of array', () => {
      expect(asBoolean(['true', 'false'])).toBe(true);
      expect(asBoolean(['false', 'true'])).toBe(false);
    });

    it('should return undefined for empty array', () => {
      expect(asBoolean([])).toBeUndefined();
    });
  });

  describe('Integration scenarios', () => {
    it('should handle typical pagination query params', () => {
      const mockQuery = {
        page: '2',
        limit: '10',
        sortBy: ['name', 'createdAt'],
      };

      expect(asNumber(mockQuery.page)).toBe(2);
      expect(asNumber(mockQuery.limit)).toBe(10);
      expect(asString(mockQuery.sortBy)).toBe('name');
      expect(asStringArray(mockQuery.sortBy)).toEqual(['name', 'createdAt']);
    });

    it('should handle filter query params', () => {
      const mockQuery = {
        active: 'true',
        search: 'test',
        tags: ['javascript', 'typescript'],
      };

      expect(asBoolean(mockQuery.active)).toBe(true);
      expect(asString(mockQuery.search)).toBe('test');
      expect(asStringArray(mockQuery.tags)).toEqual([
        'javascript',
        'typescript',
      ]);
    });

    it('should handle missing optional query params with defaults', () => {
      const mockQuery: Record<string, string | string[] | undefined> = {};

      expect(asNumber(mockQuery.page) || 1).toBe(1);
      expect(asNumber(mockQuery.limit) || 20).toBe(20);
      expect(asBoolean(mockQuery.active) ?? true).toBe(true);
    });
  });
});
