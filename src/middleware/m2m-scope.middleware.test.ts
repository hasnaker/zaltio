/**
 * M2M Scope Middleware Tests
 * Tests for M2M token validation and scope enforcement
 * 
 * Validates: Requirements 1.7 (M2M scope enforcement)
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';

// Mock MachineAuthService
const mockValidateM2MToken = jest.fn();

jest.mock('../services/machine-auth.service', () => ({
  MachineAuthService: jest.fn().mockImplementation(() => ({
    validateM2MToken: mockValidateM2MToken
  })),
  MachineAuthError: class MachineAuthError extends Error {
    code: string;
    constructor(code: string, message: string) {
      super(message);
      this.code = code;
    }
  }
}));

import {
  extractM2MToken,
  validateM2MToken,
  createM2MErrorResponse,
  withM2MAuth,
  isValidM2MScope,
  getScopeDescription,
  injectM2MContext,
  ENDPOINT_SCOPES
} from './m2m-scope.middleware';
import { MachineAuthError } from '../services/machine-auth.service';
import { M2MToken } from '../models/machine.model';

describe('M2M Scope Middleware', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });
  
  const createEvent = (overrides: Partial<APIGatewayProxyEvent> = {}): APIGatewayProxyEvent => ({
    httpMethod: 'GET',
    path: '/users',
    headers: {
      'Authorization': 'Bearer valid_token'
    },
    queryStringParameters: null,
    pathParameters: null,
    body: null,
    isBase64Encoded: false,
    requestContext: {} as any,
    ...overrides
  } as APIGatewayProxyEvent);
  
  const mockM2MToken: M2MToken = {
    machine_id: 'machine_123',
    realm_id: 'realm_test',
    scopes: ['read:users', 'write:sessions'],
    target_machines: [],
    type: 'm2m',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    iss: 'https://api.zalt.io',
    jti: 'unique_id'
  };
  
  describe('extractM2MToken', () => {
    it('should extract token from Bearer header', () => {
      const event = createEvent({
        headers: { 'Authorization': 'Bearer my_token_123' }
      });
      
      const token = extractM2MToken(event);
      
      expect(token).toBe('my_token_123');
    });
    
    it('should extract token from lowercase header', () => {
      const event = createEvent({
        headers: { 'authorization': 'Bearer my_token_123' }
      });
      
      const token = extractM2MToken(event);
      
      expect(token).toBe('my_token_123');
    });
    
    it('should return null for missing header', () => {
      const event = createEvent({
        headers: {}
      });
      
      const token = extractM2MToken(event);
      
      expect(token).toBeNull();
    });
    
    it('should return null for non-Bearer token', () => {
      const event = createEvent({
        headers: { 'Authorization': 'Basic abc123' }
      });
      
      const token = extractM2MToken(event);
      
      expect(token).toBeNull();
    });
  });
  
  describe('validateM2MToken', () => {
    it('should validate token and return success', async () => {
      mockValidateM2MToken.mockResolvedValueOnce(mockM2MToken);
      
      const event = createEvent();
      const result = await validateM2MToken(event, { requiredScope: 'read:users' });
      
      expect(result.valid).toBe(true);
      expect(result.token).toEqual(mockM2MToken);
    });
    
    it('should skip validation when configured', async () => {
      const event = createEvent({ headers: {} });
      const result = await validateM2MToken(event, { skipValidation: true });
      
      expect(result.valid).toBe(true);
      expect(mockValidateM2MToken).not.toHaveBeenCalled();
    });
    
    it('should return error for missing token', async () => {
      const event = createEvent({ headers: {} });
      const result = await validateM2MToken(event);
      
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('MISSING_TOKEN');
      expect(result.error?.statusCode).toBe(401);
    });
    
    it('should return error for insufficient scope', async () => {
      mockValidateM2MToken.mockResolvedValueOnce(mockM2MToken);
      
      const event = createEvent();
      const result = await validateM2MToken(event, { requiredScope: 'delete:users' });
      
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('INSUFFICIENT_SCOPE');
      expect(result.error?.statusCode).toBe(403);
    });
    
    it('should allow admin:all scope for any requirement', async () => {
      const adminToken = { ...mockM2MToken, scopes: ['admin:all'] };
      mockValidateM2MToken.mockResolvedValueOnce(adminToken);
      
      const event = createEvent();
      const result = await validateM2MToken(event, { requiredScope: 'delete:users' });
      
      expect(result.valid).toBe(true);
    });
    
    it('should handle expired token error', async () => {
      mockValidateM2MToken.mockRejectedValueOnce(
        new MachineAuthError('TOKEN_EXPIRED', 'Token has expired')
      );
      
      const event = createEvent();
      const result = await validateM2MToken(event);
      
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('TOKEN_EXPIRED');
      expect(result.error?.statusCode).toBe(401);
    });
    
    it('should handle invalid token error', async () => {
      mockValidateM2MToken.mockRejectedValueOnce(
        new MachineAuthError('INVALID_TOKEN', 'Invalid token')
      );
      
      const event = createEvent();
      const result = await validateM2MToken(event);
      
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('INVALID_TOKEN');
    });
    
    it('should check multiple scopes with OR logic', async () => {
      mockValidateM2MToken.mockResolvedValueOnce(mockM2MToken);
      
      const event = createEvent();
      const result = await validateM2MToken(event, {
        requiredScopes: ['delete:users', 'read:users']  // Has read:users
      });
      
      expect(result.valid).toBe(true);
    });
    
    it('should check multiple scopes with AND logic', async () => {
      mockValidateM2MToken.mockResolvedValueOnce(mockM2MToken);
      
      const event = createEvent();
      const result = await validateM2MToken(event, {
        requiredScopes: ['read:users', 'delete:users'],
        requireAllScopes: true
      });
      
      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('INSUFFICIENT_SCOPE');
    });
    
    it('should use endpoint mapping for scope requirements', async () => {
      mockValidateM2MToken.mockResolvedValueOnce(mockM2MToken);
      
      const event = createEvent({
        httpMethod: 'GET',
        path: '/users'
      });
      
      const result = await validateM2MToken(event);
      
      expect(result.valid).toBe(true);  // Has read:users
    });
  });
  
  describe('createM2MErrorResponse', () => {
    it('should create 401 response with WWW-Authenticate header', () => {
      const response = createM2MErrorResponse({
        code: 'MISSING_TOKEN',
        message: 'Token required',
        statusCode: 401
      });
      
      expect(response.statusCode).toBe(401);
      expect(response.headers?.['WWW-Authenticate']).toBe('Bearer');
      
      const body = JSON.parse(response.body);
      expect(body.error.code).toBe('MISSING_TOKEN');
    });
    
    it('should create 403 response without WWW-Authenticate', () => {
      const response = createM2MErrorResponse({
        code: 'INSUFFICIENT_SCOPE',
        message: 'Scope required',
        statusCode: 403
      });
      
      expect(response.statusCode).toBe(403);
      expect(response.headers?.['WWW-Authenticate']).toBeUndefined();
    });
  });
  
  describe('withM2MAuth', () => {
    it('should call handler with valid token', async () => {
      mockValidateM2MToken.mockResolvedValueOnce(mockM2MToken);
      
      const mockHandler = jest.fn().mockResolvedValue({
        statusCode: 200,
        body: JSON.stringify({ success: true })
      });
      
      const wrappedHandler = withM2MAuth(mockHandler, { requiredScope: 'read:users' });
      const event = createEvent();
      
      const result = await wrappedHandler(event);
      
      expect(result.statusCode).toBe(200);
      expect(mockHandler).toHaveBeenCalledWith(event, mockM2MToken);
    });
    
    it('should return error without calling handler for invalid token', async () => {
      mockValidateM2MToken.mockRejectedValueOnce(
        new MachineAuthError('INVALID_TOKEN', 'Invalid token')
      );
      
      const mockHandler = jest.fn();
      const wrappedHandler = withM2MAuth(mockHandler);
      const event = createEvent();
      
      const result = await wrappedHandler(event);
      
      expect(result.statusCode).toBe(401);
      expect(mockHandler).not.toHaveBeenCalled();
    });
  });
  
  describe('isValidM2MScope', () => {
    it('should return true for valid scopes', () => {
      expect(isValidM2MScope('read:users')).toBe(true);
      expect(isValidM2MScope('write:sessions')).toBe(true);
      expect(isValidM2MScope('admin:all')).toBe(true);
    });
    
    it('should return false for invalid scopes', () => {
      expect(isValidM2MScope('invalid:scope')).toBe(false);
      expect(isValidM2MScope('random')).toBe(false);
    });
  });
  
  describe('getScopeDescription', () => {
    it('should return description for valid scope', () => {
      expect(getScopeDescription('read:users')).toBe('Read user information');
    });
    
    it('should return unknown for invalid scope', () => {
      expect(getScopeDescription('invalid:scope')).toBe('Unknown scope');
    });
  });
  
  describe('injectM2MContext', () => {
    it('should inject M2M context into event', () => {
      const event = createEvent();
      const enrichedEvent = injectM2MContext(event, mockM2MToken);
      
      expect(enrichedEvent.requestContext.authorizer?.m2m).toBe(true);
      expect(enrichedEvent.requestContext.authorizer?.machineId).toBe('machine_123');
      expect(enrichedEvent.requestContext.authorizer?.realmId).toBe('realm_test');
      expect(enrichedEvent.requestContext.authorizer?.scopes).toBe('read:users write:sessions');
    });
  });
  
  describe('ENDPOINT_SCOPES', () => {
    it('should have scope mappings for common endpoints', () => {
      expect(ENDPOINT_SCOPES['GET /users']).toBe('read:users');
      expect(ENDPOINT_SCOPES['POST /users']).toBe('write:users');
      expect(ENDPOINT_SCOPES['DELETE /users']).toBe('delete:users');
      expect(ENDPOINT_SCOPES['GET /sessions']).toBe('read:sessions');
    });
  });
});
