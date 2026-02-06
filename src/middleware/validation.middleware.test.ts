/**
 * Request Validation Middleware Tests
 * Task 6.11: Request Validation & Size Limits
 * 
 * Tests:
 * - Body size validation
 * - Content type validation
 * - JSON depth validation
 * - Array length validation
 * - String length validation
 * - Object key validation
 */

import * as fc from 'fast-check';
import {
  ValidationConfig,
  DEFAULT_VALIDATION_CONFIG,
  STRICT_VALIDATION_CONFIG,
  FILE_UPLOAD_CONFIG,
  validateBodySize,
  validateContentType,
  calculateJsonDepth,
  validateJsonDepth,
  validateArrayLengths,
  validateStringLengths,
  validateObjectKeys,
  parseAndValidateJson,
  validateRequest,
  sanitizeString,
  isValidEmail,
  isValidUUID,
  isValidRealmId
} from './validation.middleware';

describe('Validation Middleware - Unit Tests', () => {
  describe('DEFAULT_VALIDATION_CONFIG', () => {
    it('should have 1MB max body size', () => {
      expect(DEFAULT_VALIDATION_CONFIG.maxBodySize).toBe(1024 * 1024);
    });

    it('should have max JSON depth of 10', () => {
      expect(DEFAULT_VALIDATION_CONFIG.maxJsonDepth).toBe(10);
    });

    it('should have max array length of 1000', () => {
      expect(DEFAULT_VALIDATION_CONFIG.maxArrayLength).toBe(1000);
    });

    it('should have max string length of 10000', () => {
      expect(DEFAULT_VALIDATION_CONFIG.maxStringLength).toBe(10000);
    });

    it('should have max object keys of 100', () => {
      expect(DEFAULT_VALIDATION_CONFIG.maxObjectKeys).toBe(100);
    });

    it('should allow application/json', () => {
      expect(DEFAULT_VALIDATION_CONFIG.allowedContentTypes).toContain('application/json');
    });
  });

  describe('STRICT_VALIDATION_CONFIG', () => {
    it('should have 100KB max body size', () => {
      expect(STRICT_VALIDATION_CONFIG.maxBodySize).toBe(100 * 1024);
    });

    it('should have stricter limits than default', () => {
      expect(STRICT_VALIDATION_CONFIG.maxJsonDepth).toBeLessThan(DEFAULT_VALIDATION_CONFIG.maxJsonDepth);
      expect(STRICT_VALIDATION_CONFIG.maxArrayLength).toBeLessThan(DEFAULT_VALIDATION_CONFIG.maxArrayLength);
    });
  });

  describe('FILE_UPLOAD_CONFIG', () => {
    it('should have 5MB max body size', () => {
      expect(FILE_UPLOAD_CONFIG.maxBodySize).toBe(5 * 1024 * 1024);
    });

    it('should allow multipart/form-data', () => {
      expect(FILE_UPLOAD_CONFIG.allowedContentTypes).toContain('multipart/form-data');
    });
  });

  describe('validateBodySize', () => {
    it('should accept null body', () => {
      const result = validateBodySize(null);
      expect(result.valid).toBe(true);
    });

    it('should accept empty body', () => {
      const result = validateBodySize('');
      expect(result.valid).toBe(true);
    });

    it('should accept body within limit', () => {
      const body = 'a'.repeat(1000);
      const result = validateBodySize(body);
      expect(result.valid).toBe(true);
    });

    it('should reject body exceeding limit', () => {
      const body = 'a'.repeat(2 * 1024 * 1024); // 2MB
      const result = validateBodySize(body);
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('BODY_TOO_LARGE');
      expect(result.statusCode).toBe(413);
    });

    it('should use custom config', () => {
      const config: ValidationConfig = { ...DEFAULT_VALIDATION_CONFIG, maxBodySize: 100 };
      const body = 'a'.repeat(200);
      const result = validateBodySize(body, config);
      expect(result.valid).toBe(false);
    });
  });

  describe('validateContentType', () => {
    it('should accept application/json', () => {
      const result = validateContentType('application/json');
      expect(result.valid).toBe(true);
    });

    it('should accept application/json with charset', () => {
      const result = validateContentType('application/json; charset=utf-8');
      expect(result.valid).toBe(true);
    });

    it('should reject text/html', () => {
      const result = validateContentType('text/html');
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('INVALID_CONTENT_TYPE');
      expect(result.statusCode).toBe(415);
    });

    it('should reject missing content type when required', () => {
      const result = validateContentType(undefined);
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('MISSING_CONTENT_TYPE');
    });

    it('should accept missing content type when not required', () => {
      const config: ValidationConfig = { ...DEFAULT_VALIDATION_CONFIG, requireContentType: false };
      const result = validateContentType(undefined, config);
      expect(result.valid).toBe(true);
    });
  });

  describe('calculateJsonDepth', () => {
    it('should return 0 for primitives', () => {
      expect(calculateJsonDepth(null)).toBe(0);
      expect(calculateJsonDepth('string')).toBe(0);
      expect(calculateJsonDepth(123)).toBe(0);
      expect(calculateJsonDepth(true)).toBe(0);
    });

    it('should return 1 for flat object', () => {
      expect(calculateJsonDepth({ a: 1, b: 2 })).toBe(1);
    });

    it('should return 1 for flat array', () => {
      expect(calculateJsonDepth([1, 2, 3])).toBe(1);
    });

    it('should calculate nested depth correctly', () => {
      expect(calculateJsonDepth({ a: { b: { c: 1 } } })).toBe(3);
    });

    it('should handle mixed nesting', () => {
      expect(calculateJsonDepth({ a: [{ b: 1 }] })).toBe(3);
    });
  });

  describe('validateJsonDepth', () => {
    it('should accept shallow JSON', () => {
      const result = validateJsonDepth({ a: 1 });
      expect(result.valid).toBe(true);
    });

    it('should reject too deep JSON', () => {
      let deep: any = { value: 1 };
      for (let i = 0; i < 15; i++) {
        deep = { nested: deep };
      }
      const result = validateJsonDepth(deep);
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('JSON_TOO_DEEP');
    });
  });

  describe('validateArrayLengths', () => {
    it('should accept short arrays', () => {
      const result = validateArrayLengths([1, 2, 3]);
      expect(result.valid).toBe(true);
    });

    it('should reject too long arrays', () => {
      const longArray = new Array(2000).fill(1);
      const result = validateArrayLengths(longArray);
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('ARRAY_TOO_LONG');
    });

    it('should check nested arrays', () => {
      const nested = { data: new Array(2000).fill(1) };
      const result = validateArrayLengths(nested);
      expect(result.valid).toBe(false);
    });
  });

  describe('validateStringLengths', () => {
    it('should accept short strings', () => {
      const result = validateStringLengths('hello');
      expect(result.valid).toBe(true);
    });

    it('should reject too long strings', () => {
      const longString = 'a'.repeat(20000);
      const result = validateStringLengths(longString);
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('STRING_TOO_LONG');
    });

    it('should check nested strings', () => {
      const nested = { data: 'a'.repeat(20000) };
      const result = validateStringLengths(nested);
      expect(result.valid).toBe(false);
    });

    it('should check object keys', () => {
      const longKey = 'a'.repeat(20000);
      const obj = { [longKey]: 1 };
      const result = validateStringLengths(obj);
      expect(result.valid).toBe(false);
    });
  });

  describe('validateObjectKeys', () => {
    it('should accept objects with few keys', () => {
      const result = validateObjectKeys({ a: 1, b: 2, c: 3 });
      expect(result.valid).toBe(true);
    });

    it('should reject objects with too many keys', () => {
      const manyKeys: any = {};
      for (let i = 0; i < 200; i++) {
        manyKeys[`key${i}`] = i;
      }
      const result = validateObjectKeys(manyKeys);
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('TOO_MANY_KEYS');
    });

    it('should check nested objects', () => {
      const manyKeys: any = {};
      for (let i = 0; i < 200; i++) {
        manyKeys[`key${i}`] = i;
      }
      const nested = { data: manyKeys };
      const result = validateObjectKeys(nested);
      expect(result.valid).toBe(false);
    });
  });

  describe('parseAndValidateJson', () => {
    it('should parse valid JSON', () => {
      const result = parseAndValidateJson('{"a": 1}');
      expect(result.valid).toBe(true);
      expect(result.data).toEqual({ a: 1 });
    });

    it('should reject invalid JSON', () => {
      const result = parseAndValidateJson('not json');
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('INVALID_JSON');
    });

    it('should accept null body', () => {
      const result = parseAndValidateJson(null);
      expect(result.valid).toBe(true);
      expect(result.data).toBeNull();
    });

    it('should validate all constraints', () => {
      let deep: any = { value: 1 };
      for (let i = 0; i < 15; i++) {
        deep = { nested: deep };
      }
      const result = parseAndValidateJson(JSON.stringify(deep));
      expect(result.valid).toBe(false);
    });
  });

  describe('validateRequest', () => {
    it('should validate complete request', () => {
      const event = {
        body: '{"test": true}',
        headers: { 'content-type': 'application/json' }
      } as any;
      
      const result = validateRequest(event);
      expect(result.valid).toBe(true);
    });

    it('should reject large body', () => {
      const event = {
        body: 'a'.repeat(2 * 1024 * 1024),
        headers: { 'content-type': 'application/json' }
      } as any;
      
      const result = validateRequest(event);
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('BODY_TOO_LARGE');
    });

    it('should reject invalid content type', () => {
      const event = {
        body: '{"test": true}',
        headers: { 'content-type': 'text/html' }
      } as any;
      
      const result = validateRequest(event);
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('INVALID_CONTENT_TYPE');
    });
  });

  describe('sanitizeString', () => {
    it('should escape HTML tags', () => {
      expect(sanitizeString('<script>')).toBe('&lt;script&gt;');
    });

    it('should escape quotes', () => {
      expect(sanitizeString('"test"')).toBe('&quot;test&quot;');
    });

    it('should escape single quotes', () => {
      expect(sanitizeString("'test'")).toBe('&#x27;test&#x27;');
    });

    it('should escape slashes', () => {
      expect(sanitizeString('/')).toBe('&#x2F;');
    });

    it('should handle normal text', () => {
      expect(sanitizeString('hello world')).toBe('hello world');
    });
  });

  describe('isValidEmail', () => {
    it('should accept valid emails', () => {
      expect(isValidEmail('test@example.com')).toBe(true);
      expect(isValidEmail('user.name@domain.co.uk')).toBe(true);
    });

    it('should reject invalid emails', () => {
      expect(isValidEmail('notanemail')).toBe(false);
      expect(isValidEmail('@domain.com')).toBe(false);
      expect(isValidEmail('user@')).toBe(false);
    });

    it('should reject too long emails', () => {
      const longEmail = 'a'.repeat(250) + '@test.com';
      expect(isValidEmail(longEmail)).toBe(false);
    });
  });

  describe('isValidUUID', () => {
    it('should accept valid UUIDs', () => {
      expect(isValidUUID('123e4567-e89b-12d3-a456-426614174000')).toBe(true);
      expect(isValidUUID('550e8400-e29b-41d4-a716-446655440000')).toBe(true);
    });

    it('should reject invalid UUIDs', () => {
      expect(isValidUUID('not-a-uuid')).toBe(false);
      expect(isValidUUID('123')).toBe(false);
      expect(isValidUUID('')).toBe(false);
    });
  });

  describe('isValidRealmId', () => {
    it('should accept valid realm IDs', () => {
      expect(isValidRealmId('clinisyn-psychologists')).toBe(true);
      expect(isValidRealmId('my-company')).toBe(true);
      expect(isValidRealmId('test123')).toBe(true);
    });

    it('should reject invalid realm IDs', () => {
      expect(isValidRealmId('UPPERCASE')).toBe(false);
      expect(isValidRealmId('-starts-with-dash')).toBe(false);
      expect(isValidRealmId('ends-with-dash-')).toBe(false);
      expect(isValidRealmId('ab')).toBe(false); // Too short
    });
  });

  describe('Property-based tests', () => {
    describe('Body size validation', () => {
      it('should accept bodies within limit', () => {
        fc.assert(
          fc.property(
            fc.string({ minLength: 0, maxLength: 1000 }),
            (body) => {
              const result = validateBodySize(body);
              expect(result.valid).toBe(true);
              return true;
            }
          ),
          { numRuns: 50 }
        );
      });
    });

    describe('JSON depth calculation', () => {
      it('should always return non-negative depth', () => {
        fc.assert(
          fc.property(
            fc.jsonValue(),
            (value) => {
              const depth = calculateJsonDepth(value);
              expect(depth).toBeGreaterThanOrEqual(0);
              return true;
            }
          ),
          { numRuns: 50 }
        );
      });
    });

    describe('Email validation', () => {
      it('should handle any string without crashing', () => {
        fc.assert(
          fc.property(
            fc.string(),
            (email) => {
              const result = isValidEmail(email);
              expect(typeof result).toBe('boolean');
              return true;
            }
          ),
          { numRuns: 100 }
        );
      });
    });

    describe('UUID validation', () => {
      it('should handle any string without crashing', () => {
        fc.assert(
          fc.property(
            fc.string(),
            (uuid) => {
              const result = isValidUUID(uuid);
              expect(typeof result).toBe('boolean');
              return true;
            }
          ),
          { numRuns: 100 }
        );
      });
    });

    describe('Sanitization', () => {
      it('should never return original dangerous characters', () => {
        fc.assert(
          fc.property(
            fc.string(),
            (input) => {
              const sanitized = sanitizeString(input);
              expect(sanitized).not.toContain('<');
              expect(sanitized).not.toContain('>');
              return true;
            }
          ),
          { numRuns: 100 }
        );
      });
    });
  });
});
