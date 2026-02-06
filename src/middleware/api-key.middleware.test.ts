/**
 * API Key Middleware Tests
 * 
 * Validates: Requirements 5.2 (API Key validation)
 */

import { APIGatewayProxyEvent } from 'aws-lambda';

// Mock dependencies
const mockValidateAPIKey = jest.fn();
jest.mock('../repositories/api-key.repository', () => ({
  validateAPIKey: (...args: unknown[]) => mockValidateAPIKey(...args)
}));

const mockLogSecurityEvent = jest.fn();
jest.mock('../services/security-logger.service', () => ({
  logSecurityEvent: (...args: unknown[]) => mockLogSecurityEvent(...args)
}));

import {
  extractAPIKey,
  validateKeyFormat,
  validateAPIKeyMiddleware,
  requirePublishableKey,
  requireSecretKey,
  isTestEnvironment,
  isLiveEnvironment
} from './api-key.middleware';

describe('API Key Middleware', () => {
  const mockEvent = (headers: Record<string, string> = {}): APIGatewayProxyEvent => ({
    body: null,
    headers,
    multiValueHeaders: {},
    httpMethod: 'POST',
    isBase64Encoded: false,
    path: '/login',
    pathParameters: null,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: {
      accountId: '123456789012',
      apiId: 'api123',
      authorizer: null,
      protocol: 'HTTP/1.1',
      httpMethod: 'POST',
      identity: {
        sourceIp: '127.0.0.1',
        accessKey: null,
        accountId: null,
        apiKey: null,
        apiKeyId: null,
        caller: null,
        clientCert: null,
        cognitoAuthenticationProvider: null,
        cognitoAuthenticationType: null,
        cognitoIdentityId: null,
        cognitoIdentityPoolId: null,
        principalOrgId: null,
        user: null,
        userAgent: null,
        userArn: null
      },
      path: '/login',
      stage: 'prod',
      requestId: 'test-request-id',
      requestTimeEpoch: Date.now(),
      resourceId: 'resource123',
      resourcePath: '/login'
    },
    resource: '/login'
  });

  const mockAPIKey = {
    id: 'key_abc123',
    customer_id: 'customer_xyz789',
    realm_id: 'realm_def456',
    type: 'publishable' as const,
    environment: 'live' as const,
    key_prefix: 'pk_live_',
    key_hash: 'abc123hash',
    key_hint: '...XYZ1',
    name: 'Test Key',
    status: 'active' as const,
    usage_count: 10,
    created_at: '2026-01-25T10:00:00Z',
    updated_at: '2026-01-25T10:00:00Z'
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockLogSecurityEvent.mockResolvedValue(undefined);
  });

  describe('extractAPIKey', () => {
    it('should extract key from X-API-Key header', () => {
      const event = mockEvent({ 'X-API-Key': 'pk_live_mock_key_for_testing_only' });
      expect(extractAPIKey(event)).toBe('pk_live_mock_key_for_testing_only');
    });

    it('should extract key from lowercase x-api-key header', () => {
      const event = mockEvent({ 'x-api-key': 'pk_live_mock_key_for_testing_only' });
      expect(extractAPIKey(event)).toBe('pk_live_mock_key_for_testing_only');
    });

    it('should extract key from Bearer Authorization header', () => {
      const event = mockEvent({ Authorization: 'Bearer pk_live_mock_key_for_testing_only' });
      expect(extractAPIKey(event)).toBe('pk_live_mock_key_for_testing_only');
    });

    it('should extract key from ApiKey Authorization header', () => {
      const event = mockEvent({ Authorization: 'ApiKey pk_live_mock_key_for_testing_only' });
      expect(extractAPIKey(event)).toBe('pk_live_mock_key_for_testing_only');
    });

    it('should prefer X-API-Key over Authorization header', () => {
      const event = mockEvent({ 
        'X-API-Key': 'pk_live_mock_key_for_testing_0001',
        Authorization: 'Bearer pk_live_mock_key_for_testing_0002'
      });
      expect(extractAPIKey(event)).toBe('pk_live_mock_key_for_testing_0001');
    });

    it('should return null when no API key header present', () => {
      const event = mockEvent({});
      expect(extractAPIKey(event)).toBeNull();
    });

    it('should return null for invalid Authorization format', () => {
      const event = mockEvent({ Authorization: 'InvalidFormat' });
      expect(extractAPIKey(event)).toBeNull();
    });

    it('should return null for unsupported Authorization scheme', () => {
      const event = mockEvent({ Authorization: 'Basic dXNlcjpwYXNz' });
      expect(extractAPIKey(event)).toBeNull();
    });
  });

  describe('validateKeyFormat', () => {
    // Using FAKE_ prefix to avoid GitHub secret scanning false positives
    const FAKE_PK_LIVE = 'pk_live_mock_key_for_testing_only';
    const FAKE_SK_LIVE = 'sk_live_mock_key_for_testing_only';
    const FAKE_PK_TEST = 'pk_test_mock_key_for_testing_only';
    const FAKE_SK_TEST = 'sk_test_mock_key_for_testing_only';

    it('should validate correct publishable live key format', () => {
      const result = validateKeyFormat(FAKE_PK_LIVE);
      expect(result.valid).toBe(true);
    });

    it('should validate correct secret live key format', () => {
      const result = validateKeyFormat(FAKE_SK_LIVE);
      expect(result.valid).toBe(true);
    });

    it('should validate correct publishable test key format', () => {
      const result = validateKeyFormat(FAKE_PK_TEST);
      expect(result.valid).toBe(true);
    });

    it('should validate correct secret test key format', () => {
      const result = validateKeyFormat(FAKE_SK_TEST);
      expect(result.valid).toBe(true);
    });

    it('should reject invalid key format', () => {
      const result = validateKeyFormat('invalid_key');
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('INVALID_KEY_FORMAT');
    });

    it('should reject key with wrong length', () => {
      const result = validateKeyFormat('pk_live_SHORT');
      expect(result.valid).toBe(false);
    });

    it('should enforce publishable key requirement', () => {
      const result = validateKeyFormat(
        FAKE_SK_LIVE,
        { requiredType: 'publishable' }
      );
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('INVALID_KEY_TYPE');
    });

    it('should enforce secret key requirement', () => {
      const result = validateKeyFormat(
        FAKE_PK_LIVE,
        { requiredType: 'secret' }
      );
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('INVALID_KEY_TYPE');
    });

    it('should enforce live environment requirement', () => {
      const result = validateKeyFormat(
        FAKE_PK_TEST,
        { requiredEnvironment: 'live' }
      );
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('INVALID_KEY_ENVIRONMENT');
    });

    it('should enforce test environment requirement', () => {
      const result = validateKeyFormat(
        FAKE_PK_LIVE,
        { requiredEnvironment: 'test' }
      );
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('INVALID_KEY_ENVIRONMENT');
    });

    it('should allow both environments when configured', () => {
      const result = validateKeyFormat(
        FAKE_PK_TEST,
        { requiredEnvironment: 'live', allowBothEnvironments: true }
      );
      expect(result.valid).toBe(true);
    });
  });


  describe('validateAPIKeyMiddleware', () => {
    it('should return valid when skipValidation is true', async () => {
      const event = mockEvent({});
      const result = await validateAPIKeyMiddleware(event, { skipValidation: true });
      
      expect(result.valid).toBe(true);
      expect(result.apiKey).toBeUndefined();
    });

    it('should return error when API key is missing', async () => {
      const event = mockEvent({});
      const result = await validateAPIKeyMiddleware(event);
      
      expect(result.valid).toBe(false);
      expect(result.response?.statusCode).toBe(401);
      const body = JSON.parse(result.response!.body);
      expect(body.error.code).toBe('MISSING_API_KEY');
    });

    it('should return error for invalid key format', async () => {
      const event = mockEvent({ 'X-API-Key': 'invalid_key' });
      const result = await validateAPIKeyMiddleware(event);
      
      expect(result.valid).toBe(false);
      expect(result.response?.statusCode).toBe(403);
      const body = JSON.parse(result.response!.body);
      expect(body.error.code).toBe('INVALID_KEY_FORMAT');
    });

    it('should return error when key not found in database', async () => {
      mockValidateAPIKey.mockResolvedValue(null);
      
      const event = mockEvent({ 'X-API-Key': FAKE_PK_LIVE });
      const result = await validateAPIKeyMiddleware(event);
      
      expect(result.valid).toBe(false);
      expect(result.response?.statusCode).toBe(403);
      const body = JSON.parse(result.response!.body);
      expect(body.error.code).toBe('INVALID_API_KEY');
    });

    it('should return valid with apiKey when validation succeeds', async () => {
      mockValidateAPIKey.mockResolvedValue(mockAPIKey);
      
      const event = mockEvent({ 'X-API-Key': FAKE_PK_LIVE });
      const result = await validateAPIKeyMiddleware(event);
      
      expect(result.valid).toBe(true);
      expect(result.apiKey).toEqual(mockAPIKey);
    });

    it('should log security event on successful validation', async () => {
      mockValidateAPIKey.mockResolvedValue(mockAPIKey);
      
      const event = mockEvent({ 'X-API-Key': FAKE_PK_LIVE });
      await validateAPIKeyMiddleware(event);
      
      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'api_key_validated'
        })
      );
    });

    it('should log security event on missing key', async () => {
      const event = mockEvent({});
      await validateAPIKeyMiddleware(event);
      
      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'api_key_missing'
        })
      );
    });

    it('should log security event on failed validation', async () => {
      mockValidateAPIKey.mockResolvedValue(null);
      
      const event = mockEvent({ 'X-API-Key': FAKE_PK_LIVE });
      await validateAPIKeyMiddleware(event);
      
      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'api_key_validation_failed'
        })
      );
    });

    it('should enforce publishable key type', async () => {
      const event = mockEvent({ 'X-API-Key': FAKE_SK_LIVE });
      const result = await validateAPIKeyMiddleware(event, { requiredType: 'publishable' });
      
      expect(result.valid).toBe(false);
      const body = JSON.parse(result.response!.body);
      expect(body.error.code).toBe('INVALID_KEY_TYPE');
    });

    it('should enforce secret key type', async () => {
      const event = mockEvent({ 'X-API-Key': FAKE_PK_LIVE });
      const result = await validateAPIKeyMiddleware(event, { requiredType: 'secret' });
      
      expect(result.valid).toBe(false);
      const body = JSON.parse(result.response!.body);
      expect(body.error.code).toBe('INVALID_KEY_TYPE');
    });
  });

  describe('requirePublishableKey wrapper', () => {
    it('should call handler with apiKey when validation succeeds', async () => {
      mockValidateAPIKey.mockResolvedValue(mockAPIKey);
      
      const mockHandler = jest.fn().mockResolvedValue({
        statusCode: 200,
        body: JSON.stringify({ success: true })
      });
      
      const wrappedHandler = requirePublishableKey(mockHandler);
      const event = mockEvent({ 'X-API-Key': 'pk_live_mock_key_for_testing_only' });
      
      const result = await wrappedHandler(event);
      
      expect(result.statusCode).toBe(200);
      expect(mockHandler).toHaveBeenCalledWith(event, mockAPIKey);
    });

    it('should return error response when validation fails', async () => {
      const mockHandler = jest.fn();
      
      const wrappedHandler = requirePublishableKey(mockHandler);
      const event = mockEvent({ 'X-API-Key': 'sk_live_mock_key_for_testing_only' });
      
      const result = await wrappedHandler(event);
      
      expect(result.statusCode).toBe(403);
      expect(mockHandler).not.toHaveBeenCalled();
    });
  });

  describe('requireSecretKey wrapper', () => {
    it('should call handler with apiKey when validation succeeds', async () => {
      const secretKey = { ...mockAPIKey, type: 'secret' as const, key_prefix: 'sk_live_' };
      mockValidateAPIKey.mockResolvedValue(secretKey);
      
      const mockHandler = jest.fn().mockResolvedValue({
        statusCode: 200,
        body: JSON.stringify({ success: true })
      });
      
      const wrappedHandler = requireSecretKey(mockHandler);
      const event = mockEvent({ 'X-API-Key': 'sk_live_mock_key_for_testing_only' });
      
      const result = await wrappedHandler(event);
      
      expect(result.statusCode).toBe(200);
      expect(mockHandler).toHaveBeenCalledWith(event, secretKey);
    });

    it('should return error response when publishable key used', async () => {
      const mockHandler = jest.fn();
      
      const wrappedHandler = requireSecretKey(mockHandler);
      const event = mockEvent({ 'X-API-Key': 'pk_live_mock_key_for_testing_only' });
      
      const result = await wrappedHandler(event);
      
      expect(result.statusCode).toBe(403);
      expect(mockHandler).not.toHaveBeenCalled();
    });
  });

  describe('Environment helpers', () => {
    it('isTestEnvironment should return true for test keys', () => {
      const testKey = { ...mockAPIKey, environment: 'test' as const };
      expect(isTestEnvironment(testKey)).toBe(true);
    });

    it('isTestEnvironment should return false for live keys', () => {
      expect(isTestEnvironment(mockAPIKey)).toBe(false);
    });

    it('isLiveEnvironment should return true for live keys', () => {
      expect(isLiveEnvironment(mockAPIKey)).toBe(true);
    });

    it('isLiveEnvironment should return false for test keys', () => {
      const testKey = { ...mockAPIKey, environment: 'test' as const };
      expect(isLiveEnvironment(testKey)).toBe(false);
    });
  });

  describe('Security Headers', () => {
    it('should include security headers in error response', async () => {
      const event = mockEvent({});
      const result = await validateAPIKeyMiddleware(event);
      
      expect(result.response?.headers?.['X-Content-Type-Options']).toBe('nosniff');
      expect(result.response?.headers?.['X-Frame-Options']).toBe('DENY');
      expect(result.response?.headers?.['Content-Type']).toBe('application/json');
    });
  });
});
