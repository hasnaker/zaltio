/**
 * Session Task Blocking Middleware Tests
 * 
 * Tests for session task blocking middleware:
 * - Blocking task detection
 * - 403 SESSION_TASK_PENDING response
 * - Whitelisted endpoint bypass
 * - X-Session-Task-Pending header
 * 
 * Validates: Requirements 4.2 (Session Task Blocking)
 * 
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  extractSessionId,
  getEndpointPath,
  matchEndpoint,
  isEndpointWhitelisted,
  validateSessionTaskBlocking,
  createSessionTaskBlockingErrorResponse,
  withSessionTaskBlocking,
  sessionTaskBlockingMiddleware,
  isSessionTaskPending,
  extractSessionTaskDetails,
  addToWhitelist,
  createWhitelist,
  DEFAULT_WHITELISTED_ENDPOINTS,
  SessionTaskBlockingMiddlewareOptions,
  WhitelistedEndpoint
} from './session-task-blocking.middleware';
import { SessionTasksService } from '../services/session-tasks.service';
import { SessionTaskResponse } from '../models/session-task.model';

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
 * Create mock SessionTasksService
 */
function createMockService(
  hasBlocking: boolean = false,
  blockingTasks: SessionTaskResponse[] = []
): SessionTasksService {
  const service = new SessionTasksService();
  
  // Override methods to return controlled values
  service.hasBlockingTasks = jest.fn().mockResolvedValue(hasBlocking);
  service.getBlockingTasks = jest.fn().mockResolvedValue(
    blockingTasks.map(t => ({
      ...t,
      user_id: 'user_123',
      realm_id: 'realm_123',
      created_at: new Date().toISOString()
    }))
  );
  
  return service;
}

/**
 * Create mock blocking task
 */
function createMockBlockingTask(
  type: string = 'reset_password',
  id: string = 'task_123'
): SessionTaskResponse {
  return {
    id,
    session_id: 'session_123',
    type: type as any,
    status: 'pending',
    priority: 1,
    blocking: true,
    created_at: new Date().toISOString(),
    metadata: {
      reason: 'compromised',
      message: 'Your password must be reset'
    }
  };
}

describe('Session Task Blocking Middleware', () => {
  
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
    
    it('should extract session ID from authorizer context sessionId', () => {
      const event = createMockEvent({
        requestContext: {
          ...createMockEvent().requestContext,
          authorizer: { sessionId: 'session_789' }
        }
      });
      
      expect(extractSessionId(event)).toBe('session_789');
    });
    
    it('should extract session ID from authorizer context jti', () => {
      const event = createMockEvent({
        requestContext: {
          ...createMockEvent().requestContext,
          authorizer: { jti: 'session_jti' }
        }
      });
      
      expect(extractSessionId(event)).toBe('session_jti');
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
  
  describe('matchEndpoint', () => {
    
    it('should match exact endpoints', () => {
      expect(matchEndpoint('/session/tasks', '/session/tasks')).toBe(true);
      expect(matchEndpoint('/logout', '/logout')).toBe(true);
    });
    
    it('should not match different endpoints', () => {
      expect(matchEndpoint('/session/tasks', '/users')).toBe(false);
      expect(matchEndpoint('/logout', '/login')).toBe(false);
    });
    
    it('should match wildcard patterns', () => {
      expect(matchEndpoint('/session/tasks/task_123/complete', '/session/tasks/*/complete')).toBe(true);
      expect(matchEndpoint('/health/db', '/health/*')).toBe(true);
    });
    
    it('should not match partial wildcards incorrectly', () => {
      expect(matchEndpoint('/session/tasks/task_123/other', '/session/tasks/*/complete')).toBe(false);
      expect(matchEndpoint('/health/db/status', '/health/*')).toBe(false);
    });
    
  });
  
  describe('isEndpointWhitelisted', () => {
    
    it('should whitelist session task endpoints', () => {
      const getTasksEvent = createMockEvent({
        httpMethod: 'GET',
        path: '/session/tasks',
        resource: '/session/tasks'
      });
      expect(isEndpointWhitelisted(getTasksEvent)).toBe(true);
      
      const completeTaskEvent = createMockEvent({
        httpMethod: 'POST',
        path: '/session/tasks/task_123/complete',
        resource: '/session/tasks/*/complete'
      });
      expect(isEndpointWhitelisted(completeTaskEvent)).toBe(true);
    });
    
    it('should whitelist logout endpoints', () => {
      const logoutEvent = createMockEvent({
        httpMethod: 'POST',
        path: '/logout',
        resource: '/logout'
      });
      expect(isEndpointWhitelisted(logoutEvent)).toBe(true);
      
      const authLogoutEvent = createMockEvent({
        httpMethod: 'POST',
        path: '/auth/logout',
        resource: '/auth/logout'
      });
      expect(isEndpointWhitelisted(authLogoutEvent)).toBe(true);
    });
    
    it('should whitelist password reset endpoints', () => {
      const passwordEvent = createMockEvent({
        httpMethod: 'PUT',
        path: '/me/password',
        resource: '/me/password'
      });
      expect(isEndpointWhitelisted(passwordEvent)).toBe(true);
    });
    
    it('should whitelist MFA setup endpoints', () => {
      const mfaSetupEvent = createMockEvent({
        httpMethod: 'POST',
        path: '/mfa/setup',
        resource: '/mfa/setup'
      });
      expect(isEndpointWhitelisted(mfaSetupEvent)).toBe(true);
    });
    
    it('should whitelist health check endpoints', () => {
      const healthEvent = createMockEvent({
        httpMethod: 'GET',
        path: '/health',
        resource: '/health'
      });
      expect(isEndpointWhitelisted(healthEvent)).toBe(true);
    });
    
    it('should whitelist user info endpoint', () => {
      const meEvent = createMockEvent({
        httpMethod: 'GET',
        path: '/me',
        resource: '/me'
      });
      expect(isEndpointWhitelisted(meEvent)).toBe(true);
    });
    
    it('should NOT whitelist regular API endpoints', () => {
      const usersEvent = createMockEvent({
        httpMethod: 'GET',
        path: '/users',
        resource: '/users'
      });
      expect(isEndpointWhitelisted(usersEvent)).toBe(false);
      
      const dataEvent = createMockEvent({
        httpMethod: 'POST',
        path: '/api/data',
        resource: '/api/data'
      });
      expect(isEndpointWhitelisted(dataEvent)).toBe(false);
    });
    
    it('should support custom whitelist', () => {
      const customWhitelist: WhitelistedEndpoint[] = [
        { endpoint: '/custom/endpoint', method: 'POST' }
      ];
      
      const customEvent = createMockEvent({
        httpMethod: 'POST',
        path: '/custom/endpoint',
        resource: '/custom/endpoint'
      });
      
      expect(isEndpointWhitelisted(customEvent, customWhitelist)).toBe(true);
    });
    
    it('should check method for whitelisted endpoints', () => {
      // GET /session/tasks is whitelisted
      const getEvent = createMockEvent({
        httpMethod: 'GET',
        path: '/session/tasks',
        resource: '/session/tasks'
      });
      expect(isEndpointWhitelisted(getEvent)).toBe(true);
      
      // POST /session/tasks is NOT whitelisted (only GET is)
      const postEvent = createMockEvent({
        httpMethod: 'POST',
        path: '/session/tasks',
        resource: '/session/tasks'
      });
      expect(isEndpointWhitelisted(postEvent)).toBe(false);
    });
    
  });

  
  describe('validateSessionTaskBlocking', () => {
    
    it('should return valid when skipBlockingCheck is true', async () => {
      const event = createMockEvent({
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const result = await validateSessionTaskBlocking(event, { skipBlockingCheck: true });
      
      expect(result.valid).toBe(true);
      expect(result.isBlocked).toBe(false);
    });
    
    it('should return valid when endpoint is whitelisted', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/session/tasks',
        resource: '/session/tasks',
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const mockService = createMockService(true, [createMockBlockingTask()]);
      
      const result = await validateSessionTaskBlocking(event, { service: mockService });
      
      expect(result.valid).toBe(true);
      expect(result.isBlocked).toBe(false);
      // Service should not be called for whitelisted endpoints
      expect(mockService.hasBlockingTasks).not.toHaveBeenCalled();
    });
    
    it('should return valid when no session ID present', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/api/data',
        resource: '/api/data'
      });
      
      const result = await validateSessionTaskBlocking(event);
      
      expect(result.valid).toBe(true);
      expect(result.isBlocked).toBe(false);
    });
    
    it('should return valid when no blocking tasks', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/api/data',
        resource: '/api/data',
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const mockService = createMockService(false);
      
      const result = await validateSessionTaskBlocking(event, { service: mockService });
      
      expect(result.valid).toBe(true);
      expect(result.isBlocked).toBe(false);
      expect(mockService.hasBlockingTasks).toHaveBeenCalledWith('session_123');
    });
    
    it('should return SESSION_TASK_PENDING when blocking tasks exist', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/api/data',
        resource: '/api/data',
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const blockingTask = createMockBlockingTask('reset_password', 'task_abc');
      const mockService = createMockService(true, [blockingTask]);
      
      const result = await validateSessionTaskBlocking(event, { service: mockService });
      
      expect(result.valid).toBe(false);
      expect(result.isBlocked).toBe(true);
      expect(result.blockingTasks).toHaveLength(1);
      expect(result.blockingTasks![0].id).toBe('task_abc');
      expect(result.blockingTasks![0].type).toBe('reset_password');
      expect(result.error?.code).toBe('SESSION_TASK_PENDING');
      expect(result.error?.statusCode).toBe(403);
    });
    
    it('should return multiple blocking tasks when present', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/api/data',
        resource: '/api/data',
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const tasks = [
        createMockBlockingTask('reset_password', 'task_1'),
        createMockBlockingTask('setup_mfa', 'task_2')
      ];
      const mockService = createMockService(true, tasks);
      
      const result = await validateSessionTaskBlocking(event, { service: mockService });
      
      expect(result.valid).toBe(false);
      expect(result.blockingTasks).toHaveLength(2);
      expect(result.error?.tasks).toHaveLength(2);
    });
    
  });
  
  describe('createSessionTaskBlockingErrorResponse', () => {
    
    it('should create 403 response with SESSION_TASK_PENDING', () => {
      const tasks = [createMockBlockingTask('reset_password', 'task_123')];
      
      const response = createSessionTaskBlockingErrorResponse({
        code: 'SESSION_TASK_PENDING',
        message: 'You have pending tasks',
        statusCode: 403,
        tasks
      }, 'req_123');
      
      expect(response.statusCode).toBe(403);
      expect(response.headers?.['X-Session-Task-Pending']).toBe('true');
      expect(response.headers?.['X-Session-Task-Count']).toBe('1');
      
      const body = JSON.parse(response.body);
      expect(body.error.code).toBe('SESSION_TASK_PENDING');
      expect(body.error.request_id).toBe('req_123');
      expect(body.session_tasks).toBeDefined();
      expect(body.session_tasks.pending).toBe(true);
      expect(body.session_tasks.count).toBe(1);
      expect(body.session_tasks.tasks).toHaveLength(1);
      expect(body.session_tasks.endpoints).toBeDefined();
    });
    
    it('should include task details in response', () => {
      const tasks = [
        createMockBlockingTask('reset_password', 'task_1'),
        createMockBlockingTask('setup_mfa', 'task_2')
      ];
      
      const response = createSessionTaskBlockingErrorResponse({
        code: 'SESSION_TASK_PENDING',
        message: 'You have pending tasks',
        statusCode: 403,
        tasks
      });
      
      const body = JSON.parse(response.body);
      expect(body.session_tasks.tasks[0].id).toBe('task_1');
      expect(body.session_tasks.tasks[0].type).toBe('reset_password');
      expect(body.session_tasks.tasks[1].id).toBe('task_2');
      expect(body.session_tasks.tasks[1].type).toBe('setup_mfa');
    });
    
    it('should include security headers', () => {
      const response = createSessionTaskBlockingErrorResponse({
        code: 'SESSION_TASK_PENDING',
        message: 'Test',
        statusCode: 403,
        tasks: []
      });
      
      expect(response.headers?.['Content-Type']).toBe('application/json');
      expect(response.headers?.['X-Content-Type-Options']).toBe('nosniff');
      expect(response.headers?.['X-Frame-Options']).toBe('DENY');
    });
    
    it('should include endpoint information for task completion', () => {
      const response = createSessionTaskBlockingErrorResponse({
        code: 'SESSION_TASK_PENDING',
        message: 'Test',
        statusCode: 403,
        tasks: [createMockBlockingTask()]
      });
      
      const body = JSON.parse(response.body);
      expect(body.session_tasks.endpoints.list).toBe('/session/tasks');
      expect(body.session_tasks.endpoints.complete).toBe('/session/tasks/{id}/complete');
      expect(body.session_tasks.endpoints.skip).toBe('/session/tasks/{id}/skip');
    });
    
  });
  
  describe('withSessionTaskBlocking wrapper', () => {
    
    it('should call handler when no blocking tasks', async () => {
      const mockHandler = jest.fn().mockResolvedValue({
        statusCode: 200,
        headers: {},
        body: JSON.stringify({ success: true })
      });
      
      const mockService = createMockService(false);
      
      const wrappedHandler = withSessionTaskBlocking(mockHandler, { service: mockService });
      
      const event = createMockEvent({
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const response = await wrappedHandler(event);
      
      expect(mockHandler).toHaveBeenCalledWith(event);
      expect(response.statusCode).toBe(200);
      expect(response.headers?.['X-Session-Task-Pending']).toBe('false');
    });
    
    it('should return error when blocking tasks exist', async () => {
      const mockHandler = jest.fn();
      const mockService = createMockService(true, [createMockBlockingTask()]);
      
      const wrappedHandler = withSessionTaskBlocking(mockHandler, { service: mockService });
      
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/api/data',
        resource: '/api/data',
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const response = await wrappedHandler(event);
      
      expect(mockHandler).not.toHaveBeenCalled();
      expect(response.statusCode).toBe(403);
      expect(response.headers?.['X-Session-Task-Pending']).toBe('true');
      
      const body = JSON.parse(response.body);
      expect(body.error.code).toBe('SESSION_TASK_PENDING');
    });
    
    it('should allow whitelisted endpoints even with blocking tasks', async () => {
      const mockHandler = jest.fn().mockResolvedValue({
        statusCode: 200,
        headers: {},
        body: JSON.stringify({ tasks: [] })
      });
      
      const mockService = createMockService(true, [createMockBlockingTask()]);
      
      const wrappedHandler = withSessionTaskBlocking(mockHandler, { service: mockService });
      
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/session/tasks',
        resource: '/session/tasks',
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const response = await wrappedHandler(event);
      
      expect(mockHandler).toHaveBeenCalled();
      expect(response.statusCode).toBe(200);
    });
    
  });
  
  describe('sessionTaskBlockingMiddleware', () => {
    
    it('should return valid result when no blocking', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/api/data',
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const mockService = createMockService(false);
      
      const result = await sessionTaskBlockingMiddleware(event, { service: mockService });
      
      expect(result.valid).toBe(true);
      expect(result.isBlocked).toBe(false);
      expect(result.response).toBeUndefined();
    });
    
    it('should return response when blocked', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/api/data',
        resource: '/api/data',
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const mockService = createMockService(true, [createMockBlockingTask()]);
      
      const result = await sessionTaskBlockingMiddleware(event, { service: mockService });
      
      expect(result.valid).toBe(false);
      expect(result.isBlocked).toBe(true);
      expect(result.blockingTasks).toHaveLength(1);
      expect(result.response).toBeDefined();
      expect(result.response?.statusCode).toBe(403);
    });
    
  });
  
  describe('isSessionTaskPending', () => {
    
    it('should return true for 403 with X-Session-Task-Pending header', () => {
      const response: APIGatewayProxyResult = {
        statusCode: 403,
        headers: { 'X-Session-Task-Pending': 'true' },
        body: '{}'
      };
      
      expect(isSessionTaskPending(response)).toBe(true);
    });
    
    it('should return false for 403 without header', () => {
      const response: APIGatewayProxyResult = {
        statusCode: 403,
        headers: {},
        body: '{}'
      };
      
      expect(isSessionTaskPending(response)).toBe(false);
    });
    
    it('should return false for non-403 status', () => {
      const response: APIGatewayProxyResult = {
        statusCode: 401,
        headers: { 'X-Session-Task-Pending': 'true' },
        body: '{}'
      };
      
      expect(isSessionTaskPending(response)).toBe(false);
    });
    
    it('should return false for 200 with header', () => {
      const response: APIGatewayProxyResult = {
        statusCode: 200,
        headers: { 'X-Session-Task-Pending': 'false' },
        body: '{}'
      };
      
      expect(isSessionTaskPending(response)).toBe(false);
    });
    
  });
  
  describe('extractSessionTaskDetails', () => {
    
    it('should extract session task details from response', () => {
      const response: APIGatewayProxyResult = {
        statusCode: 403,
        headers: { 'X-Session-Task-Pending': 'true' },
        body: JSON.stringify({
          error: { code: 'SESSION_TASK_PENDING' },
          session_tasks: {
            pending: true,
            count: 2,
            tasks: [
              { id: 'task_1', type: 'reset_password', priority: 1 },
              { id: 'task_2', type: 'setup_mfa', priority: 2 }
            ]
          }
        })
      };
      
      const details = extractSessionTaskDetails(response);
      
      expect(details).not.toBeNull();
      expect(details?.pending).toBe(true);
      expect(details?.count).toBe(2);
      expect(details?.tasks).toHaveLength(2);
      expect(details?.tasks[0].type).toBe('reset_password');
    });
    
    it('should return null for non-blocking response', () => {
      const response: APIGatewayProxyResult = {
        statusCode: 200,
        headers: {},
        body: '{}'
      };
      
      expect(extractSessionTaskDetails(response)).toBeNull();
    });
    
    it('should return null for invalid JSON', () => {
      const response: APIGatewayProxyResult = {
        statusCode: 403,
        headers: { 'X-Session-Task-Pending': 'true' },
        body: 'invalid json'
      };
      
      expect(extractSessionTaskDetails(response)).toBeNull();
    });
    
  });
  
  describe('addToWhitelist', () => {
    
    it('should add endpoint to whitelist', () => {
      const whitelist: WhitelistedEndpoint[] = [];
      const newWhitelist = addToWhitelist(whitelist, '/custom/endpoint', 'POST');
      
      expect(newWhitelist).toHaveLength(1);
      expect(newWhitelist[0].endpoint).toBe('/custom/endpoint');
      expect(newWhitelist[0].method).toBe('POST');
    });
    
    it('should default method to wildcard', () => {
      const whitelist: WhitelistedEndpoint[] = [];
      const newWhitelist = addToWhitelist(whitelist, '/custom/endpoint');
      
      expect(newWhitelist[0].method).toBe('*');
    });
    
    it('should not modify original whitelist', () => {
      const whitelist: WhitelistedEndpoint[] = [{ endpoint: '/existing', method: 'GET' }];
      const newWhitelist = addToWhitelist(whitelist, '/new', 'POST');
      
      expect(whitelist).toHaveLength(1);
      expect(newWhitelist).toHaveLength(2);
    });
    
  });
  
  describe('createWhitelist', () => {
    
    it('should create whitelist from array', () => {
      const whitelist = createWhitelist([
        { endpoint: '/endpoint1', method: 'GET' },
        { endpoint: '/endpoint2', method: 'POST' },
        { endpoint: '/endpoint3' }
      ]);
      
      expect(whitelist).toHaveLength(3);
      expect(whitelist[0].method).toBe('GET');
      expect(whitelist[1].method).toBe('POST');
      expect(whitelist[2].method).toBe('*');
    });
    
  });
  
  describe('Integration scenarios', () => {
    
    it('should block API access when reset_password task is pending', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/api/users',
        resource: '/api/users',
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const mockService = createMockService(true, [
        createMockBlockingTask('reset_password', 'task_reset')
      ]);
      
      const result = await validateSessionTaskBlocking(event, { service: mockService });
      
      expect(result.valid).toBe(false);
      expect(result.blockingTasks![0].type).toBe('reset_password');
    });
    
    it('should allow password change endpoint when reset_password task is pending', async () => {
      const event = createMockEvent({
        httpMethod: 'PUT',
        path: '/me/password',
        resource: '/me/password',
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const mockService = createMockService(true, [
        createMockBlockingTask('reset_password', 'task_reset')
      ]);
      
      const result = await validateSessionTaskBlocking(event, { service: mockService });
      
      expect(result.valid).toBe(true);
      expect(result.isBlocked).toBe(false);
    });
    
    it('should block API access when setup_mfa task is pending', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/api/data',
        resource: '/api/data',
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const mockService = createMockService(true, [
        createMockBlockingTask('setup_mfa', 'task_mfa')
      ]);
      
      const result = await validateSessionTaskBlocking(event, { service: mockService });
      
      expect(result.valid).toBe(false);
      expect(result.blockingTasks![0].type).toBe('setup_mfa');
    });
    
    it('should allow MFA setup endpoint when setup_mfa task is pending', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/mfa/setup',
        resource: '/mfa/setup',
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const mockService = createMockService(true, [
        createMockBlockingTask('setup_mfa', 'task_mfa')
      ]);
      
      const result = await validateSessionTaskBlocking(event, { service: mockService });
      
      expect(result.valid).toBe(true);
    });
    
    it('should always allow logout even with blocking tasks', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/logout',
        resource: '/logout',
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const mockService = createMockService(true, [
        createMockBlockingTask('reset_password'),
        createMockBlockingTask('setup_mfa')
      ]);
      
      const result = await validateSessionTaskBlocking(event, { service: mockService });
      
      expect(result.valid).toBe(true);
    });
    
    it('should allow task completion endpoint', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/session/tasks/task_123/complete',
        resource: '/session/tasks/*/complete',
        headers: { 'X-Session-Id': 'session_123' }
      });
      
      const mockService = createMockService(true, [createMockBlockingTask()]);
      
      const result = await validateSessionTaskBlocking(event, { service: mockService });
      
      expect(result.valid).toBe(true);
    });
    
  });
  
  describe('DEFAULT_WHITELISTED_ENDPOINTS', () => {
    
    it('should include essential task completion endpoints', () => {
      const endpoints = DEFAULT_WHITELISTED_ENDPOINTS.map(e => e.endpoint);
      
      expect(endpoints).toContain('/session/tasks');
      expect(endpoints).toContain('/session/tasks/*/complete');
      expect(endpoints).toContain('/session/tasks/*/skip');
    });
    
    it('should include logout endpoints', () => {
      const endpoints = DEFAULT_WHITELISTED_ENDPOINTS.map(e => e.endpoint);
      
      expect(endpoints).toContain('/logout');
      expect(endpoints).toContain('/auth/logout');
    });
    
    it('should include password reset endpoints', () => {
      const endpoints = DEFAULT_WHITELISTED_ENDPOINTS.map(e => e.endpoint);
      
      expect(endpoints).toContain('/me/password');
      expect(endpoints).toContain('/password/reset');
    });
    
    it('should include MFA setup endpoints', () => {
      const endpoints = DEFAULT_WHITELISTED_ENDPOINTS.map(e => e.endpoint);
      
      expect(endpoints).toContain('/mfa/setup');
      expect(endpoints).toContain('/mfa/totp/setup');
      expect(endpoints).toContain('/mfa/webauthn/setup');
    });
    
    it('should include organization selection endpoints', () => {
      const endpoints = DEFAULT_WHITELISTED_ENDPOINTS.map(e => e.endpoint);
      
      expect(endpoints).toContain('/organizations/select');
      expect(endpoints).toContain('/organizations/switch');
    });
    
    it('should include terms acceptance endpoints', () => {
      const endpoints = DEFAULT_WHITELISTED_ENDPOINTS.map(e => e.endpoint);
      
      expect(endpoints).toContain('/terms/accept');
    });
    
    it('should include health check endpoints', () => {
      const endpoints = DEFAULT_WHITELISTED_ENDPOINTS.map(e => e.endpoint);
      
      expect(endpoints).toContain('/health');
      expect(endpoints).toContain('/health/*');
    });
    
  });
  
});
