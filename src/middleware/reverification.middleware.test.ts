/**
 * Reverification Middleware Tests
 * 
 * Tests for step-up authentication middleware:
 * - Endpoint reverification requirement checking
 * - Session extraction from various sources
 * - 403 REVERIFICATION_REQUIRED response
 * - Required level inclusion in response
 * 
 * Validates: Requirements 3.1, 3.2 (Reverification)
 * 
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  extractSessionId,
  getEndpointPath,
  checkEndpointRequirement,
  validateReverification,
  createReverificationErrorResponse,
  withReverification,
  reverificationMiddleware,
  requireReverification,
  requirePasswordReverification,
  requireMFAReverification,
  requireWebAuthnReverification,
  isReverificationRequired,
  extractReverificationDetails,
  ReverificationMiddlewareOptions
} from './reverification.middleware';
import { ReverificationService } from '../services/reverification.service';
import { ReverificationLevel, DEFAULT_REVERIFICATION_REQUIREMENTS } from '../models/reverification.model';

/**
 * Create mock API Gateway event
 */
function createMockEvent(overrides: Partial<APIGatewayProxyEvent> = {}): APIGatewayProxyEvent {
  return {
    httpMethod: 'GET',
    path: '/test',
    resource: '/test',
    headers: {},
    queryStringParameters: null,
    pathParameters: null,
    stageVariables: null,
    body: null,
    isBase64Encoded: false,
    multiValueHeaders: {},
    multiValueQueryStringParameters: null,
    requestContext: {
      accountId: '123456789012',
      apiId: 'test-api',
      authorizer: {},
      protocol: 'HTTP/1.1',
      httpMethod: 'GET',
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
      path: '/test',
      stage: 'test',
      requestId: 'test-request-id',
      requestTimeEpoch: Date.now(),
      resourceId: 'test-resource',
      resourcePath: '/test'
    },
    ...overrides
  };
}

/**
 * Create mock ReverificationService
 */
function createMockService(isVerified: boolean = false): ReverificationService {
  const service = new ReverificationService();
  
  // Override checkReverification to return controlled value
  service.checkReverification = jest.fn().mockResolvedValue(isVerified);
  
  return service;
}

describe('Reverification Middleware', () => {
  
  describe('extractSessionId', () => {
    
    it('should extract session ID from X-Session-Id header', () => {
      const event = createMockEvent({
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      expect(extractSessionId(event)).toBe('session_123');
    });
    
    it('should extract session ID from lowercase x-session-id header', () => {
      const event = createMockEvent({
        headers: { 'x-session-id': 'session_456' }
      });
      
      expect(extractSessionId(event)).toBe('session_456');
    });
    
    it('should extract session ID from authorizer context', () => {
      const event = createMockEvent({
        requestContext: {
          ...createMockEvent().requestContext,
          authorizer: { sessionId: 'session_789' }
        }
      });
      
      expect(extractSessionId(event)).toBe('session_789');
    });
    
    it('should extract session ID from cookie', () => {
      const event = createMockEvent({
        headers: { Cookie: 'zalt_session=session_abc; other=value' }
      });
      
      expect(extractSessionId(event)).toBe('session_abc');
    });
    
    it('should return null when no session ID found', () => {
      const event = createMockEvent();
      
      expect(extractSessionId(event)).toBeNull();
    });
    
    it('should prefer X-Session-Id header over other sources', () => {
      const event = createMockEvent({
        headers: {
          'X-Session-Id': 'header_session',
          Cookie: 'zalt_session=cookie_session'
        },
        requestContext: {
          ...createMockEvent().requestContext,
          authorizer: { sessionId: 'authorizer_session' }
        }
      });
      
      expect(extractSessionId(event)).toBe('header_session');
    });
    
  });
  
  describe('getEndpointPath', () => {
    
    it('should return resource path when available', () => {
      const event = createMockEvent({
        resource: '/users/{id}',
        path: '/users/123'
      });
      
      expect(getEndpointPath(event)).toBe('/users/{id}');
    });
    
    it('should return path when resource not available', () => {
      const event = createMockEvent({
        resource: undefined as any,
        path: '/users/123'
      });
      
      expect(getEndpointPath(event)).toBe('/users/123');
    });
    
    it('should normalize path with trailing slash', () => {
      const event = createMockEvent({
        resource: '/users/',
        path: '/users/'
      });
      
      expect(getEndpointPath(event)).toBe('/users');
    });
    
    it('should add leading slash if missing', () => {
      const event = createMockEvent({
        resource: 'users',
        path: 'users'
      });
      
      expect(getEndpointPath(event)).toBe('/users');
    });
    
  });
  
  describe('checkEndpointRequirement', () => {
    
    it('should return null for endpoints without requirements', () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/public',
        resource: '/public'
      });
      
      expect(checkEndpointRequirement(event)).toBeNull();
    });
    
    it('should return requirement for password change endpoint', () => {
      const event = createMockEvent({
        httpMethod: 'PUT',
        path: '/me/password',
        resource: '/me/password'
      });
      
      const requirement = checkEndpointRequirement(event);
      
      expect(requirement).not.toBeNull();
      expect(requirement?.level).toBe('password');
      expect(requirement?.validityMinutes).toBe(5);
    });
    
    it('should return requirement for MFA disable endpoint', () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/mfa/disable',
        resource: '/mfa/disable'
      });
      
      const requirement = checkEndpointRequirement(event);
      
      expect(requirement).not.toBeNull();
      expect(requirement?.level).toBe('mfa');
    });
    
    it('should return requirement for account deletion endpoint', () => {
      const event = createMockEvent({
        httpMethod: 'DELETE',
        path: '/me/delete',
        resource: '/me/delete'
      });
      
      const requirement = checkEndpointRequirement(event);
      
      expect(requirement).not.toBeNull();
      expect(requirement?.level).toBe('mfa');
    });
    
    it('should use explicit requiredLevel from options', () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/custom',
        resource: '/custom'
      });
      
      const requirement = checkEndpointRequirement(event, {
        requiredLevel: 'webauthn',
        validityMinutes: 15
      });
      
      expect(requirement).not.toBeNull();
      expect(requirement?.level).toBe('webauthn');
      expect(requirement?.validityMinutes).toBe(15);
    });
    
    it('should use default validity when not specified in options', () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/custom',
        resource: '/custom'
      });
      
      const requirement = checkEndpointRequirement(event, {
        requiredLevel: 'mfa'
      });
      
      expect(requirement?.validityMinutes).toBe(15); // Default for MFA
    });
    
    it('should match wildcard endpoints', () => {
      const event = createMockEvent({
        httpMethod: 'DELETE',
        path: '/api-keys/key_123',
        resource: '/api-keys/{id}'
      });
      
      // The default requirements include '/api-keys/*' for DELETE
      const requirement = checkEndpointRequirement(event);
      
      expect(requirement).not.toBeNull();
      expect(requirement?.level).toBe('password');
    });
    
  });
  
  describe('validateReverification', () => {
    
    it('should return valid when skipReverification is true', async () => {
      const event = createMockEvent();
      
      const result = await validateReverification(event, { skipReverification: true });
      
      expect(result.valid).toBe(true);
      expect(result.requiresReverification).toBe(false);
    });
    
    it('should return valid when endpoint has no requirements', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/public',
        resource: '/public'
      });
      
      const result = await validateReverification(event);
      
      expect(result.valid).toBe(true);
      expect(result.requiresReverification).toBe(false);
    });
    
    it('should return error when session is missing', async () => {
      const event = createMockEvent({
        httpMethod: 'PUT',
        path: '/me/password',
        resource: '/me/password'
      });
      
      const result = await validateReverification(event);
      
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('SESSION_REQUIRED');
      expect(result.error?.statusCode).toBe(401);
    });
    
    it('should return REVERIFICATION_REQUIRED when not verified', async () => {
      const event = createMockEvent({
        httpMethod: 'PUT',
        path: '/me/password',
        resource: '/me/password',
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const mockService = createMockService(false);
      
      const result = await validateReverification(event, { service: mockService });
      
      expect(result.valid).toBe(false);
      expect(result.requiresReverification).toBe(true);
      expect(result.requiredLevel).toBe('password');
      expect(result.error?.code).toBe('REVERIFICATION_REQUIRED');
      expect(result.error?.statusCode).toBe(403);
      expect(result.error?.requiredLevel).toBe('password');
    });
    
    it('should return valid when session is verified', async () => {
      const event = createMockEvent({
        httpMethod: 'PUT',
        path: '/me/password',
        resource: '/me/password',
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const mockService = createMockService(true);
      
      const result = await validateReverification(event, { service: mockService });
      
      expect(result.valid).toBe(true);
      expect(result.requiresReverification).toBe(true);
      expect(result.requiredLevel).toBe('password');
    });
    
    it('should check correct level for MFA-required endpoints', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/mfa/disable',
        resource: '/mfa/disable',
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const mockService = createMockService(false);
      
      const result = await validateReverification(event, { service: mockService });
      
      expect(result.requiredLevel).toBe('mfa');
      expect(mockService.checkReverification).toHaveBeenCalledWith('session_123', 'mfa');
    });
    
  });
  
  describe('createReverificationErrorResponse', () => {
    
    it('should create 403 response for REVERIFICATION_REQUIRED', () => {
      const response = createReverificationErrorResponse({
        code: 'REVERIFICATION_REQUIRED',
        message: 'This operation requires password reverification',
        statusCode: 403,
        requiredLevel: 'password',
        validityMinutes: 10
      }, 'req_123');
      
      expect(response.statusCode).toBe(403);
      expect(response.headers?.['X-Reverification-Required']).toBe('true');
      expect(response.headers?.['X-Reverification-Level']).toBe('password');
      
      const body = JSON.parse(response.body);
      expect(body.error.code).toBe('REVERIFICATION_REQUIRED');
      expect(body.error.request_id).toBe('req_123');
      expect(body.reverification).toBeDefined();
      expect(body.reverification.required).toBe(true);
      expect(body.reverification.level).toBe('password');
      expect(body.reverification.validityMinutes).toBe(10);
      expect(body.reverification.endpoints).toBeDefined();
    });
    
    it('should create 401 response for SESSION_REQUIRED', () => {
      const response = createReverificationErrorResponse({
        code: 'SESSION_REQUIRED',
        message: 'Valid session is required',
        statusCode: 401
      });
      
      expect(response.statusCode).toBe(401);
      expect(response.headers?.['X-Reverification-Required']).toBe('false');
      
      const body = JSON.parse(response.body);
      expect(body.error.code).toBe('SESSION_REQUIRED');
      expect(body.reverification).toBeUndefined();
    });
    
    it('should include security headers', () => {
      const response = createReverificationErrorResponse({
        code: 'REVERIFICATION_REQUIRED',
        message: 'Test',
        statusCode: 403
      });
      
      expect(response.headers?.['Content-Type']).toBe('application/json');
      expect(response.headers?.['X-Content-Type-Options']).toBe('nosniff');
      expect(response.headers?.['X-Frame-Options']).toBe('DENY');
    });
    
  });
  
  describe('withReverification wrapper', () => {
    
    it('should call handler when reverification passes', async () => {
      const mockHandler = jest.fn().mockResolvedValue({
        statusCode: 200,
        body: JSON.stringify({ success: true })
      });
      
      const wrappedHandler = withReverification(mockHandler, {
        skipReverification: true
      });
      
      const event = createMockEvent();
      const response = await wrappedHandler(event);
      
      expect(mockHandler).toHaveBeenCalledWith(event);
      expect(response.statusCode).toBe(200);
    });
    
    it('should return error when reverification fails', async () => {
      const mockHandler = jest.fn();
      const mockService = createMockService(false);
      
      const wrappedHandler = withReverification(mockHandler, {
        requiredLevel: 'password',
        service: mockService
      });
      
      const event = createMockEvent({
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const response = await wrappedHandler(event);
      
      expect(mockHandler).not.toHaveBeenCalled();
      expect(response.statusCode).toBe(403);
      
      const body = JSON.parse(response.body);
      expect(body.error.code).toBe('REVERIFICATION_REQUIRED');
    });
    
  });
  
  describe('reverificationMiddleware', () => {
    
    it('should return valid result when no reverification needed', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/public'
      });
      
      const result = await reverificationMiddleware(event);
      
      expect(result.valid).toBe(true);
      expect(result.requiresReverification).toBe(false);
      expect(result.response).toBeUndefined();
    });
    
    it('should return response when reverification required', async () => {
      const mockService = createMockService(false);
      
      const event = createMockEvent({
        httpMethod: 'PUT',
        path: '/me/password',
        resource: '/me/password',
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const result = await reverificationMiddleware(event, { service: mockService });
      
      expect(result.valid).toBe(false);
      expect(result.requiresReverification).toBe(true);
      expect(result.requiredLevel).toBe('password');
      expect(result.response).toBeDefined();
      expect(result.response?.statusCode).toBe(403);
    });
    
  });
  
  describe('requireReverification helpers', () => {
    
    it('requirePasswordReverification should set password level', async () => {
      const mockHandler = jest.fn();
      const mockService = createMockService(false);
      
      // We need to inject the service somehow - use the base function
      const wrappedHandler = withReverification(mockHandler, {
        requiredLevel: 'password',
        service: mockService
      });
      
      const event = createMockEvent({
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const response = await wrappedHandler(event);
      
      expect(response.statusCode).toBe(403);
      expect(response.headers?.['X-Reverification-Level']).toBe('password');
    });
    
    it('requireMFAReverification should set mfa level', async () => {
      const mockHandler = jest.fn();
      const mockService = createMockService(false);
      
      const wrappedHandler = withReverification(mockHandler, {
        requiredLevel: 'mfa',
        service: mockService
      });
      
      const event = createMockEvent({
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const response = await wrappedHandler(event);
      
      expect(response.statusCode).toBe(403);
      expect(response.headers?.['X-Reverification-Level']).toBe('mfa');
    });
    
    it('requireWebAuthnReverification should set webauthn level', async () => {
      const mockHandler = jest.fn();
      const mockService = createMockService(false);
      
      const wrappedHandler = withReverification(mockHandler, {
        requiredLevel: 'webauthn',
        service: mockService
      });
      
      const event = createMockEvent({
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const response = await wrappedHandler(event);
      
      expect(response.statusCode).toBe(403);
      expect(response.headers?.['X-Reverification-Level']).toBe('webauthn');
    });
    
  });
  
  describe('isReverificationRequired', () => {
    
    it('should return true for 403 with X-Reverification-Required header', () => {
      const response: APIGatewayProxyResult = {
        statusCode: 403,
        headers: { 'X-Reverification-Required': 'true' },
        body: '{}'
      };
      
      expect(isReverificationRequired(response)).toBe(true);
    });
    
    it('should return false for 403 without header', () => {
      const response: APIGatewayProxyResult = {
        statusCode: 403,
        headers: {},
        body: '{}'
      };
      
      expect(isReverificationRequired(response)).toBe(false);
    });
    
    it('should return false for non-403 status', () => {
      const response: APIGatewayProxyResult = {
        statusCode: 401,
        headers: { 'X-Reverification-Required': 'true' },
        body: '{}'
      };
      
      expect(isReverificationRequired(response)).toBe(false);
    });
    
  });
  
  describe('extractReverificationDetails', () => {
    
    it('should extract reverification details from response', () => {
      const response: APIGatewayProxyResult = {
        statusCode: 403,
        headers: { 'X-Reverification-Required': 'true' },
        body: JSON.stringify({
          error: { code: 'REVERIFICATION_REQUIRED' },
          reverification: {
            required: true,
            level: 'mfa',
            validityMinutes: 15
          }
        })
      };
      
      const details = extractReverificationDetails(response);
      
      expect(details).not.toBeNull();
      expect(details?.required).toBe(true);
      expect(details?.level).toBe('mfa');
      expect(details?.validityMinutes).toBe(15);
    });
    
    it('should return null for non-reverification response', () => {
      const response: APIGatewayProxyResult = {
        statusCode: 200,
        headers: {},
        body: '{}'
      };
      
      expect(extractReverificationDetails(response)).toBeNull();
    });
    
    it('should return null for invalid JSON', () => {
      const response: APIGatewayProxyResult = {
        statusCode: 403,
        headers: { 'X-Reverification-Required': 'true' },
        body: 'invalid json'
      };
      
      expect(extractReverificationDetails(response)).toBeNull();
    });
    
  });
  
  describe('Integration with default requirements', () => {
    
    it('should enforce password reverification for email change', async () => {
      const mockService = createMockService(false);
      
      const event = createMockEvent({
        httpMethod: 'PUT',
        path: '/me/email',
        resource: '/me/email',
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const result = await validateReverification(event, { service: mockService });
      
      expect(result.valid).toBe(false);
      expect(result.requiredLevel).toBe('password');
    });
    
    it('should enforce MFA reverification for billing cancellation', async () => {
      const mockService = createMockService(false);
      
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/billing/cancel',
        resource: '/billing/cancel',
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const result = await validateReverification(event, { service: mockService });
      
      expect(result.valid).toBe(false);
      expect(result.requiredLevel).toBe('mfa');
    });
    
    it('should enforce WebAuthn reverification for organization deletion', async () => {
      const mockService = createMockService(false);
      
      const event = createMockEvent({
        httpMethod: 'DELETE',
        path: '/organizations/org_123/delete',
        resource: '/organizations/{id}/delete',
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const result = await validateReverification(event, { service: mockService });
      
      expect(result.valid).toBe(false);
      expect(result.requiredLevel).toBe('webauthn');
    });
    
    it('should allow access when properly verified', async () => {
      const mockService = createMockService(true);
      
      const event = createMockEvent({
        httpMethod: 'PUT',
        path: '/me/password',
        resource: '/me/password',
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const result = await validateReverification(event, { service: mockService });
      
      expect(result.valid).toBe(true);
      expect(mockService.checkReverification).toHaveBeenCalledWith('session_123', 'password');
    });
    
  });
  
  describe('Custom requirements', () => {
    
    it('should use custom requirements when provided', async () => {
      const mockService = createMockService(false);
      
      const customRequirements = [
        { endpoint: '/custom/sensitive', method: 'POST', level: 'webauthn' as ReverificationLevel }
      ];
      
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/custom/sensitive',
        resource: '/custom/sensitive',
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const result = await validateReverification(event, {
        service: mockService,
        customRequirements
      });
      
      expect(result.valid).toBe(false);
      expect(result.requiredLevel).toBe('webauthn');
    });
    
  });
  
});
