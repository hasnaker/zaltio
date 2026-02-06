/**
 * Request Validation E2E Tests
 * Task 6.11: Request Validation & Size Limits
 * 
 * Tests:
 * - Large payload rejection
 * - Deep JSON rejection
 * - Long string rejection
 * - Content type validation
 * - Middleware integration
 */

import {
  validateRequest,
  validateBodySize,
  validateContentType,
  validateJsonDepth,
  validateArrayLengths,
  validateStringLengths,
  validateObjectKeys,
  parseAndValidateJson,
  withValidation,
  createValidationErrorResponse,
  sanitizeString,
  isValidEmail,
  isValidUUID,
  isValidRealmId,
  DEFAULT_VALIDATION_CONFIG,
  STRICT_VALIDATION_CONFIG,
  FILE_UPLOAD_CONFIG
} from '../../middleware/validation.middleware';
import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';

describe('Request Validation E2E Tests', () => {
  describe('Large Payload Rejection', () => {
    it('should reject payload larger than 1MB', () => {
      const largeBody = 'a'.repeat(2 * 1024 * 1024); // 2MB
      const result = validateBodySize(largeBody);
      
      expect(result.valid).toBe(false);
      expect(result.statusCode).toBe(413);
      expect(result.errorCode).toBe('BODY_TOO_LARGE');
    });

    it('should accept payload under 1MB', () => {
      const normalBody = 'a'.repeat(500 * 1024); // 500KB
      const result = validateBodySize(normalBody);
      
      expect(result.valid).toBe(true);
    });

    it('should use strict config for sensitive endpoints', () => {
      const body = 'a'.repeat(200 * 1024); // 200KB
      const result = validateBodySize(body, STRICT_VALIDATION_CONFIG);
      
      expect(result.valid).toBe(false);
      expect(result.statusCode).toBe(413);
    });

    it('should allow larger files with file upload config', () => {
      const body = 'a'.repeat(3 * 1024 * 1024); // 3MB
      const result = validateBodySize(body, FILE_UPLOAD_CONFIG);
      
      expect(result.valid).toBe(true);
    });
  });

  describe('Deep Nested JSON Rejection', () => {
    it('should reject JSON deeper than 10 levels', () => {
      let deep: any = { value: 1 };
      for (let i = 0; i < 15; i++) {
        deep = { nested: deep };
      }
      
      const result = validateJsonDepth(deep);
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('JSON_TOO_DEEP');
    });

    it('should accept JSON within depth limit', () => {
      const shallow = {
        level1: {
          level2: {
            level3: {
              value: 'ok'
            }
          }
        }
      };
      
      const result = validateJsonDepth(shallow);
      expect(result.valid).toBe(true);
    });

    it('should use strict config depth limit', () => {
      let deep: any = { value: 1 };
      for (let i = 0; i < 7; i++) {
        deep = { nested: deep };
      }
      
      const result = validateJsonDepth(deep, STRICT_VALIDATION_CONFIG);
      expect(result.valid).toBe(false);
    });
  });

  describe('Long String Rejection', () => {
    it('should reject strings longer than 10000 chars', () => {
      const longString = 'a'.repeat(20000);
      const result = validateStringLengths(longString);
      
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('STRING_TOO_LONG');
    });

    it('should accept strings within limit', () => {
      const normalString = 'a'.repeat(5000);
      const result = validateStringLengths(normalString);
      
      expect(result.valid).toBe(true);
    });

    it('should check nested strings', () => {
      const nested = {
        data: {
          content: 'a'.repeat(20000)
        }
      };
      
      const result = validateStringLengths(nested);
      expect(result.valid).toBe(false);
    });

    it('should check array element strings', () => {
      const array = ['short', 'a'.repeat(20000)];
      const result = validateStringLengths(array);
      
      expect(result.valid).toBe(false);
    });
  });

  describe('Long Array Rejection', () => {
    it('should reject arrays longer than 1000 items', () => {
      const longArray = new Array(2000).fill(1);
      const result = validateArrayLengths(longArray);
      
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('ARRAY_TOO_LONG');
    });

    it('should accept arrays within limit', () => {
      const normalArray = new Array(500).fill(1);
      const result = validateArrayLengths(normalArray);
      
      expect(result.valid).toBe(true);
    });

    it('should check nested arrays', () => {
      const nested = {
        items: new Array(2000).fill(1)
      };
      
      const result = validateArrayLengths(nested);
      expect(result.valid).toBe(false);
    });
  });

  describe('Too Many Object Keys Rejection', () => {
    it('should reject objects with more than 100 keys', () => {
      const manyKeys: any = {};
      for (let i = 0; i < 200; i++) {
        manyKeys[`key${i}`] = i;
      }
      
      const result = validateObjectKeys(manyKeys);
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('TOO_MANY_KEYS');
    });

    it('should accept objects within key limit', () => {
      const fewKeys: any = {};
      for (let i = 0; i < 50; i++) {
        fewKeys[`key${i}`] = i;
      }
      
      const result = validateObjectKeys(fewKeys);
      expect(result.valid).toBe(true);
    });
  });

  describe('Content Type Validation', () => {
    it('should accept application/json', () => {
      const result = validateContentType('application/json');
      expect(result.valid).toBe(true);
    });

    it('should accept application/json with charset', () => {
      const result = validateContentType('application/json; charset=utf-8');
      expect(result.valid).toBe(true);
    });

    it('should accept application/x-www-form-urlencoded', () => {
      const result = validateContentType('application/x-www-form-urlencoded');
      expect(result.valid).toBe(true);
    });

    it('should reject text/html', () => {
      const result = validateContentType('text/html');
      expect(result.valid).toBe(false);
      expect(result.statusCode).toBe(415);
    });

    it('should reject text/xml', () => {
      const result = validateContentType('text/xml');
      expect(result.valid).toBe(false);
    });

    it('should reject missing content type', () => {
      const result = validateContentType(undefined);
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('MISSING_CONTENT_TYPE');
    });
  });

  describe('Invalid JSON Rejection', () => {
    it('should reject malformed JSON', () => {
      const result = parseAndValidateJson('{"invalid": }');
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('INVALID_JSON');
    });

    it('should reject non-JSON strings', () => {
      const result = parseAndValidateJson('not json at all');
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('INVALID_JSON');
    });

    it('should accept valid JSON', () => {
      const result = parseAndValidateJson('{"valid": true, "count": 123}');
      expect(result.valid).toBe(true);
      expect(result.data).toEqual({ valid: true, count: 123 });
    });

    it('should accept null body', () => {
      const result = parseAndValidateJson(null);
      expect(result.valid).toBe(true);
    });
  });

  describe('Full Request Validation', () => {
    it('should validate complete valid request', () => {
      const event = {
        body: JSON.stringify({ email: 'test@example.com', password: 'secret123' }),
        headers: { 'content-type': 'application/json' }
      } as any;
      
      const result = validateRequest(event);
      expect(result.valid).toBe(true);
    });

    it('should reject request with large body', () => {
      const event = {
        body: 'a'.repeat(2 * 1024 * 1024),
        headers: { 'content-type': 'application/json' }
      } as any;
      
      const result = validateRequest(event);
      expect(result.valid).toBe(false);
      expect(result.statusCode).toBe(413);
    });

    it('should reject request with invalid content type', () => {
      const event = {
        body: '{"test": true}',
        headers: { 'content-type': 'text/html' }
      } as any;
      
      const result = validateRequest(event);
      expect(result.valid).toBe(false);
      expect(result.statusCode).toBe(415);
    });

    it('should reject request with invalid JSON', () => {
      const event = {
        body: 'not json',
        headers: { 'content-type': 'application/json' }
      } as any;
      
      const result = validateRequest(event);
      expect(result.valid).toBe(false);
      expect(result.statusCode).toBe(400);
    });
  });

  describe('Validation Middleware', () => {
    it('should pass valid requests to handler', async () => {
      const handler = jest.fn().mockResolvedValue({
        statusCode: 200,
        body: JSON.stringify({ success: true })
      });
      
      const wrappedHandler = withValidation(handler);
      
      const event = {
        body: '{"test": true}',
        headers: { 'content-type': 'application/json' }
      } as any;
      
      const result = await wrappedHandler(event);
      expect(handler).toHaveBeenCalled();
      expect(result.statusCode).toBe(200);
    });

    it('should reject invalid requests before handler', async () => {
      const handler = jest.fn();
      const wrappedHandler = withValidation(handler);
      
      const event = {
        body: 'a'.repeat(2 * 1024 * 1024),
        headers: { 'content-type': 'application/json' }
      } as any;
      
      const result = await wrappedHandler(event);
      expect(handler).not.toHaveBeenCalled();
      expect(result.statusCode).toBe(413);
    });
  });

  describe('Error Response Creation', () => {
    it('should create proper error response', () => {
      const validationResult = {
        valid: false,
        error: 'Request body too large',
        errorCode: 'BODY_TOO_LARGE' as const,
        statusCode: 413
      };
      
      const response = createValidationErrorResponse(validationResult);
      
      expect(response.statusCode).toBe(413);
      expect(response.headers?.['Content-Type']).toBe('application/json');
      
      const body = JSON.parse(response.body);
      expect(body.error).toBe('Request body too large');
      expect(body.code).toBe('BODY_TOO_LARGE');
    });
  });

  describe('Input Sanitization', () => {
    it('should sanitize XSS attempts', () => {
      const malicious = '<script>alert("xss")</script>';
      const sanitized = sanitizeString(malicious);
      
      expect(sanitized).not.toContain('<');
      expect(sanitized).not.toContain('>');
      expect(sanitized).toContain('&lt;');
      expect(sanitized).toContain('&gt;');
    });

    it('should sanitize SQL injection attempts', () => {
      const malicious = "'; DROP TABLE users; --";
      const sanitized = sanitizeString(malicious);
      
      expect(sanitized).toContain('&#x27;');
    });

    it('should preserve normal text', () => {
      const normal = 'Hello, World! This is a test.';
      const sanitized = sanitizeString(normal);
      
      expect(sanitized).toBe('Hello, World! This is a test.');
    });
  });

  describe('Email Validation', () => {
    it('should accept valid email formats', () => {
      expect(isValidEmail('user@example.com')).toBe(true);
      expect(isValidEmail('user.name@domain.co.uk')).toBe(true);
      expect(isValidEmail('user+tag@example.com')).toBe(true);
    });

    it('should reject invalid email formats', () => {
      expect(isValidEmail('notanemail')).toBe(false);
      expect(isValidEmail('@domain.com')).toBe(false);
      expect(isValidEmail('user@')).toBe(false);
      expect(isValidEmail('user@domain')).toBe(false);
      expect(isValidEmail('')).toBe(false);
    });
  });

  describe('UUID Validation', () => {
    it('should accept valid UUIDs', () => {
      expect(isValidUUID('123e4567-e89b-12d3-a456-426614174000')).toBe(true);
      expect(isValidUUID('550e8400-e29b-41d4-a716-446655440000')).toBe(true);
    });

    it('should reject invalid UUIDs', () => {
      expect(isValidUUID('not-a-uuid')).toBe(false);
      expect(isValidUUID('123')).toBe(false);
      expect(isValidUUID('')).toBe(false);
      expect(isValidUUID('123e4567-e89b-12d3-a456')).toBe(false);
    });
  });

  describe('Realm ID Validation', () => {
    it('should accept valid realm IDs', () => {
      expect(isValidRealmId('clinisyn-psychologists')).toBe(true);
      expect(isValidRealmId('my-company')).toBe(true);
      expect(isValidRealmId('test123')).toBe(true);
      expect(isValidRealmId('abc')).toBe(true);
    });

    it('should reject invalid realm IDs', () => {
      expect(isValidRealmId('UPPERCASE')).toBe(false);
      expect(isValidRealmId('-starts-with-dash')).toBe(false);
      expect(isValidRealmId('ends-with-dash-')).toBe(false);
      expect(isValidRealmId('ab')).toBe(false);
      expect(isValidRealmId('has spaces')).toBe(false);
      expect(isValidRealmId('special@chars')).toBe(false);
    });
  });

  describe('Security Attack Prevention', () => {
    it('should prevent JSON bomb attack', () => {
      // Create a deeply nested structure
      let bomb: any = { a: 1 };
      for (let i = 0; i < 20; i++) {
        bomb = { nested: bomb };
      }
      
      const result = validateJsonDepth(bomb);
      expect(result.valid).toBe(false);
    });

    it('should prevent billion laughs attack', () => {
      // Large array that could expand
      const laughs = new Array(10000).fill('ha');
      const result = validateArrayLengths(laughs);
      
      expect(result.valid).toBe(false);
    });

    it('should prevent hash collision attack', () => {
      // Many keys could cause hash collision
      const manyKeys: any = {};
      for (let i = 0; i < 500; i++) {
        manyKeys[`key_${i}`] = i;
      }
      
      const result = validateObjectKeys(manyKeys);
      expect(result.valid).toBe(false);
    });
  });
});
