/**
 * Machine Handler Tests
 * Tests for M2M authentication Lambda handler
 * 
 * Validates: Requirements 1.7, 1.8 (M2M Authentication)
 */

import { APIGatewayProxyEvent } from 'aws-lambda';

// Mock MachineAuthService
const mockCreateMachine = jest.fn();
const mockAuthenticateMachine = jest.fn();
const mockListMachines = jest.fn();
const mockGetMachine = jest.fn();
const mockDeleteMachine = jest.fn();
const mockRotateCredentials = jest.fn();

jest.mock('../services/machine-auth.service', () => ({
  MachineAuthService: jest.fn().mockImplementation(() => ({
    createMachine: mockCreateMachine,
    authenticateMachine: mockAuthenticateMachine,
    listMachines: mockListMachines,
    getMachine: mockGetMachine,
    deleteMachine: mockDeleteMachine,
    rotateCredentials: mockRotateCredentials
  })),
  MachineAuthError: class MachineAuthError extends Error {
    code: string;
    constructor(code: string, message: string) {
      super(message);
      this.code = code;
    }
  }
}));

// Mock rate limit service
jest.mock('../services/ratelimit.service', () => ({
  checkRateLimit: jest.fn().mockResolvedValue({ allowed: true })
}));

import { handler } from './machine-handler';
import { MachineAuthError } from '../services/machine-auth.service';

describe('Machine Handler', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });
  
  const createEvent = (overrides: Partial<APIGatewayProxyEvent> = {}): APIGatewayProxyEvent => ({
    httpMethod: 'GET',
    path: '/machines',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer test_token'
    },
    queryStringParameters: null,
    pathParameters: null,
    body: null,
    isBase64Encoded: false,
    requestContext: {
      authorizer: {
        userId: 'admin_123',
        realmId: 'realm_test'
      }
    } as any,
    ...overrides
  } as APIGatewayProxyEvent);
  
  describe('OPTIONS (CORS)', () => {
    it('should return 200 for OPTIONS request', async () => {
      const event = createEvent({ httpMethod: 'OPTIONS' });
      
      const result = await handler(event);
      
      expect(result.statusCode).toBe(200);
      expect(result.headers?.['Access-Control-Allow-Origin']).toBe('*');
    });
  });
  
  describe('POST /machines/token', () => {
    it('should return token for valid credentials (JSON)', async () => {
      const mockToken = {
        access_token: 'mock_token',
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 'read:users'
      };
      
      mockAuthenticateMachine.mockResolvedValueOnce(mockToken);
      
      const event = createEvent({
        httpMethod: 'POST',
        path: '/machines/token',
        body: JSON.stringify({
          client_id: 'zalt_m2m_abc123def456789012345678',
          client_secret: 'test_secret',
          scope: 'read:users'
        })
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(200);
      expect(body.access_token).toBe('mock_token');
      expect(body.token_type).toBe('Bearer');
    });
    
    it('should return token for valid credentials (form-urlencoded)', async () => {
      const mockToken = {
        access_token: 'mock_token',
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 'read:users'
      };
      
      mockAuthenticateMachine.mockResolvedValueOnce(mockToken);
      
      const event = createEvent({
        httpMethod: 'POST',
        path: '/machines/token',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: 'grant_type=client_credentials&client_id=zalt_m2m_abc123def456789012345678&client_secret=test_secret&scope=read:users'
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(200);
      expect(body.access_token).toBe('mock_token');
    });
    
    it('should reject unsupported grant type', async () => {
      const event = createEvent({
        httpMethod: 'POST',
        path: '/machines/token',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: 'grant_type=password&client_id=test&client_secret=test'
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('UNSUPPORTED_GRANT_TYPE');
    });
    
    it('should reject missing credentials', async () => {
      const event = createEvent({
        httpMethod: 'POST',
        path: '/machines/token',
        body: JSON.stringify({})
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REQUEST');
    });
    
    it('should handle invalid credentials error', async () => {
      mockAuthenticateMachine.mockRejectedValueOnce(
        new MachineAuthError('INVALID_CREDENTIALS', 'Invalid client credentials')
      );
      
      const event = createEvent({
        httpMethod: 'POST',
        path: '/machines/token',
        body: JSON.stringify({
          client_id: 'zalt_m2m_abc123def456789012345678',
          client_secret: 'wrong_secret'
        })
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(401);
      expect(body.error.code).toBe('INVALID_CREDENTIALS');
    });
  });
  
  describe('POST /machines', () => {
    it('should create machine with valid input', async () => {
      const mockResult = {
        machine: {
          id: 'machine_123',
          name: 'Test Machine',
          client_id: 'zalt_m2m_abc123',
          scopes: ['read:users'],
          status: 'active'
        },
        client_secret: 'secret_123'
      };
      
      mockCreateMachine.mockResolvedValueOnce(mockResult);
      
      const event = createEvent({
        httpMethod: 'POST',
        path: '/machines',
        body: JSON.stringify({
          realm_id: 'realm_test',
          name: 'Test Machine',
          scopes: ['read:users']
        })
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(201);
      expect(body.message).toBe('Machine created successfully');
      expect(body.machine.name).toBe('Test Machine');
      expect(body.client_secret).toBe('secret_123');
    });
    
    it('should reject missing realm_id', async () => {
      const event = createEvent({
        httpMethod: 'POST',
        path: '/machines',
        body: JSON.stringify({
          name: 'Test Machine',
          scopes: ['read:users']
        })
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('VALIDATION_ERROR');
    });
    
    it('should reject missing name', async () => {
      const event = createEvent({
        httpMethod: 'POST',
        path: '/machines',
        body: JSON.stringify({
          realm_id: 'realm_test',
          scopes: ['read:users']
        })
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('VALIDATION_ERROR');
    });
    
    it('should reject missing scopes', async () => {
      const event = createEvent({
        httpMethod: 'POST',
        path: '/machines',
        body: JSON.stringify({
          realm_id: 'realm_test',
          name: 'Test Machine'
        })
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('VALIDATION_ERROR');
    });
    
    it('should reject unauthorized request', async () => {
      const event = createEvent({
        httpMethod: 'POST',
        path: '/machines',
        headers: {},  // No Authorization header
        requestContext: {} as any,
        body: JSON.stringify({
          realm_id: 'realm_test',
          name: 'Test Machine',
          scopes: ['read:users']
        })
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });
  });
  
  describe('GET /machines', () => {
    it('should list machines', async () => {
      const mockMachines = [
        { id: 'machine_1', name: 'Machine 1' },
        { id: 'machine_2', name: 'Machine 2' }
      ];
      
      mockListMachines.mockResolvedValueOnce(mockMachines);
      
      const event = createEvent({
        httpMethod: 'GET',
        path: '/machines',
        queryStringParameters: { realm_id: 'realm_test' }
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(200);
      expect(body.machines).toHaveLength(2);
    });
    
    it('should use realm from authorizer if not in query', async () => {
      mockListMachines.mockResolvedValueOnce([]);
      
      const event = createEvent({
        httpMethod: 'GET',
        path: '/machines'
      });
      
      const result = await handler(event);
      
      expect(result.statusCode).toBe(200);
      expect(mockListMachines).toHaveBeenCalledWith('realm_test');
    });
  });
  
  describe('GET /machines/{id}', () => {
    it('should return machine details', async () => {
      const mockMachine = {
        id: 'machine_123',
        name: 'Test Machine',
        client_id: 'zalt_m2m_abc123',
        client_secret_hash: 'should_be_removed',
        scopes: ['read:users'],
        status: 'active'
      };
      
      mockGetMachine.mockResolvedValueOnce(mockMachine);
      
      const event = createEvent({
        httpMethod: 'GET',
        path: '/machines/machine_123',
        queryStringParameters: { realm_id: 'realm_test' }
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(200);
      expect(body.machine.id).toBe('machine_123');
      expect(body.machine.client_secret_hash).toBeUndefined();
    });
    
    it('should return 404 for non-existent machine', async () => {
      mockGetMachine.mockResolvedValueOnce(null);
      
      const event = createEvent({
        httpMethod: 'GET',
        path: '/machines/nonexistent',
        queryStringParameters: { realm_id: 'realm_test' }
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(404);
      expect(body.error.code).toBe('NOT_FOUND');
    });
  });
  
  describe('DELETE /machines/{id}', () => {
    it('should delete machine', async () => {
      mockDeleteMachine.mockResolvedValueOnce(true);
      
      const event = createEvent({
        httpMethod: 'DELETE',
        path: '/machines/machine_123',
        queryStringParameters: { realm_id: 'realm_test' }
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(200);
      expect(body.message).toBe('Machine deleted successfully');
    });
    
    it('should return 404 for non-existent machine', async () => {
      mockDeleteMachine.mockResolvedValueOnce(false);
      
      const event = createEvent({
        httpMethod: 'DELETE',
        path: '/machines/nonexistent',
        queryStringParameters: { realm_id: 'realm_test' }
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(404);
      expect(body.error.code).toBe('NOT_FOUND');
    });
  });
  
  describe('POST /machines/{id}/rotate', () => {
    it('should rotate credentials', async () => {
      mockRotateCredentials.mockResolvedValueOnce({
        clientId: 'zalt_m2m_abc123',
        clientSecret: 'new_secret_123'
      });
      
      const event = createEvent({
        httpMethod: 'POST',
        path: '/machines/machine_123/rotate',
        queryStringParameters: { realm_id: 'realm_test' }
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(200);
      expect(body.message).toBe('Credentials rotated successfully');
      expect(body.client_secret).toBe('new_secret_123');
    });
    
    it('should handle machine not found error', async () => {
      mockRotateCredentials.mockRejectedValueOnce(
        new MachineAuthError('MACHINE_NOT_FOUND', 'Machine not found')
      );
      
      const event = createEvent({
        httpMethod: 'POST',
        path: '/machines/nonexistent/rotate',
        queryStringParameters: { realm_id: 'realm_test' }
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(404);
      expect(body.error.code).toBe('MACHINE_NOT_FOUND');
    });
  });
  
  describe('Unknown endpoint', () => {
    it('should return 404 for unknown path', async () => {
      const event = createEvent({
        httpMethod: 'GET',
        path: '/unknown'
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(404);
      expect(body.error.code).toBe('NOT_FOUND');
    });
  });
});
