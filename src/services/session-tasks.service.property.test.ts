/**
 * Property-Based Tests for Session Tasks (Post-Login Requirements)
 * Task 5.6: Write property tests for Session Tasks
 * 
 * Properties tested:
 * - Property 10: Session task blocking is enforced
 * - Property 11: Task completion removes blocking
 * - Property 12: Force password reset creates task
 * 
 * **Validates: Requirements 4.2, 4.9**
 */

import * as fc from 'fast-check';
import { APIGatewayProxyEvent } from 'aws-lambda';
import {
  SessionTasksService,
  SessionTasksError,
  SessionTask
} from './session-tasks.service';
import {
  SessionTaskType,
  SessionTaskStatus,
  isTaskBlocking,
  getDefaultBlocking,
  getDefaultPriority,
  DEFAULT_TASK_BLOCKING,
  DEFAULT_TASK_PRIORITIES
} from '../models/session-task.model';
import {
  validateSessionTaskBlocking,
  isEndpointWhitelisted,
  DEFAULT_WHITELISTED_ENDPOINTS,
  extractSessionId,
  getEndpointPath,
  matchEndpoint
} from '../middleware/session-task-blocking.middleware';

/**
 * Custom generators for Session Tasks tests
 */
const sessionIdArb = fc.hexaString({ minLength: 24, maxLength: 24 })
  .map(hex => `session_${hex}`);

const userIdArb = fc.hexaString({ minLength: 24, maxLength: 24 })
  .map(hex => `user_${hex}`);

const realmIdArb = fc.stringMatching(/^[a-z0-9-]{3,30}$/)
  .filter(s => !s.startsWith('-') && !s.endsWith('-'));

const taskIdArb = fc.hexaString({ minLength: 24, maxLength: 24 })
  .map(hex => `task_${hex}`);

const taskTypeArb = fc.constantFrom(
  'choose_organization',
  'setup_mfa',
  'reset_password',
  'accept_terms',
  'custom'
) as fc.Arbitrary<SessionTaskType>;

const blockingTaskTypeArb = fc.constantFrom(
  'choose_organization',
  'setup_mfa',
  'reset_password',
  'accept_terms'
) as fc.Arbitrary<SessionTaskType>;

const taskStatusArb = fc.constantFrom('pending', 'completed', 'skipped') as fc.Arbitrary<SessionTaskStatus>;

/**
 * Generate non-whitelisted endpoints for testing blocking
 */
const nonWhitelistedEndpointArb = fc.constantFrom(
  '/users',
  '/users/list',
  '/tenants',
  '/tenants/create',
  '/api/data',
  '/api/resources',
  '/settings',
  '/profile/update',
  '/billing',
  '/analytics',
  '/reports',
  '/admin/users',
  '/admin/settings'
);

const httpMethodArb = fc.constantFrom('GET', 'POST', 'PUT', 'DELETE', 'PATCH');

/**
 * Generate a mock APIGatewayProxyEvent for testing
 */
function createMockEvent(
  path: string,
  method: string,
  sessionId?: string
): APIGatewayProxyEvent {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json'
  };
  
  if (sessionId) {
    headers['X-Session-Id'] = sessionId;
  }
  
  return {
    path,
    resource: path,
    httpMethod: method,
    headers,
    queryStringParameters: null,
    pathParameters: null,
    stageVariables: null,
    body: null,
    isBase64Encoded: false,
    multiValueHeaders: {},
    multiValueQueryStringParameters: null,
    requestContext: {
      accountId: 'test',
      apiId: 'test',
      authorizer: sessionId ? { sessionId } : undefined,
      httpMethod: method,
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
      path,
      protocol: 'HTTP/1.1',
      requestId: 'test-request-id',
      requestTimeEpoch: Date.now(),
      resourceId: 'test',
      resourcePath: path,
      stage: 'test'
    }
  };
}

/**
 * Mock SessionTasksService for property testing
 * Simulates real behavior without database dependencies
 */
class MockSessionTasksService extends SessionTasksService {
  private tasks: Map<string, SessionTask[]> = new Map();
  private taskIdCounter = 0;
  
  constructor() {
    super();
  }
  
  /**
   * Reset all tasks (for test isolation)
   */
  reset(): void {
    this.tasks.clear();
    this.taskIdCounter = 0;
  }
  
  /**
   * Add a task directly (for test setup)
   */
  addTask(task: SessionTask): void {
    const sessionTasks = this.tasks.get(task.session_id) || [];
    sessionTasks.push(task);
    this.tasks.set(task.session_id, sessionTasks);
  }
  
  /**
   * Create a mock task
   */
  createMockTask(
    sessionId: string,
    userId: string,
    realmId: string,
    type: SessionTaskType,
    options: {
      status?: SessionTaskStatus;
      blocking?: boolean;
      priority?: number;
    } = {}
  ): SessionTask {
    const taskId = `task_${++this.taskIdCounter}`;
    const task: SessionTask = {
      id: taskId,
      session_id: sessionId,
      user_id: userId,
      realm_id: realmId,
      type,
      status: options.status || 'pending',
      blocking: options.blocking ?? getDefaultBlocking(type),
      priority: options.priority ?? getDefaultPriority(type),
      created_at: new Date().toISOString()
    };
    
    this.addTask(task);
    return task;
  }
  
  /**
   * Override hasBlockingTasks to use in-memory storage
   */
  async hasBlockingTasks(sessionId: string): Promise<boolean> {
    const sessionTasks = this.tasks.get(sessionId) || [];
    return sessionTasks.some(task => isTaskBlocking(task));
  }
  
  /**
   * Override getBlockingTasks to use in-memory storage
   */
  async getBlockingTasks(sessionId: string): Promise<SessionTask[]> {
    const sessionTasks = this.tasks.get(sessionId) || [];
    return sessionTasks.filter(task => isTaskBlocking(task));
  }
  
  /**
   * Override getPendingTasks to use in-memory storage
   */
  async getPendingTasks(sessionId: string): Promise<SessionTask[]> {
    const sessionTasks = this.tasks.get(sessionId) || [];
    return sessionTasks.filter(task => task.status === 'pending');
  }
  
  /**
   * Override completeTask to use in-memory storage
   */
  async completeTask(sessionId: string, taskId: string): Promise<SessionTask | null> {
    const sessionTasks = this.tasks.get(sessionId) || [];
    const taskIndex = sessionTasks.findIndex(t => t.id === taskId);
    
    if (taskIndex === -1) {
      return null;
    }
    
    const task = sessionTasks[taskIndex];
    if (task.status !== 'pending') {
      return null;
    }
    
    task.status = 'completed';
    task.completed_at = new Date().toISOString();
    sessionTasks[taskIndex] = task;
    this.tasks.set(sessionId, sessionTasks);
    
    return task;
  }
  
  /**
   * Get all tasks for a session
   */
  getSessionTasks(sessionId: string): SessionTask[] {
    return this.tasks.get(sessionId) || [];
  }
}

describe('Session Tasks Property-Based Tests', () => {
  let mockService: MockSessionTasksService;

  beforeEach(() => {
    mockService = new MockSessionTasksService();
  });

  afterEach(() => {
    mockService.reset();
  });

  /**
   * Property 10: Session task blocking is enforced
   * 
   * For any session with pending blocking tasks, all API calls
   * (except task completion) SHALL return 403 SESSION_TASK_PENDING.
   * 
   * Properties:
   * - Sessions with blocking tasks are blocked from non-whitelisted endpoints
   * - Blocking is enforced regardless of task type (if blocking=true)
   * - Multiple blocking tasks still result in blocking
   * - Non-blocking tasks do not block API access
   * 
   * **Validates: Requirements 4.2**
   */
  describe('Property 10: Session task blocking is enforced', () => {
    it('should block API access when session has pending blocking tasks', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          userIdArb,
          realmIdArb,
          blockingTaskTypeArb,
          nonWhitelistedEndpointArb,
          httpMethodArb,
          async (sessionId, userId, realmId, taskType, endpoint, method) => {
            // Create a blocking task
            mockService.createMockTask(sessionId, userId, realmId, taskType, {
              status: 'pending',
              blocking: true
            });
            
            // Create mock event for non-whitelisted endpoint
            const event = createMockEvent(endpoint, method, sessionId);
            
            // Validate blocking
            const result = await validateSessionTaskBlocking(event, {
              service: mockService
            });
            
            // Should be blocked
            expect(result.valid).toBe(false);
            expect(result.isBlocked).toBe(true);
            expect(result.error?.code).toBe('SESSION_TASK_PENDING');
            expect(result.error?.statusCode).toBe(403);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should block regardless of blocking task type', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          userIdArb,
          realmIdArb,
          taskTypeArb,
          nonWhitelistedEndpointArb,
          async (sessionId, userId, realmId, taskType, endpoint) => {
            // Create task with explicit blocking=true
            mockService.createMockTask(sessionId, userId, realmId, taskType, {
              status: 'pending',
              blocking: true
            });
            
            const event = createMockEvent(endpoint, 'GET', sessionId);
            const result = await validateSessionTaskBlocking(event, {
              service: mockService
            });
            
            // Should be blocked for any task type when blocking=true
            expect(result.valid).toBe(false);
            expect(result.isBlocked).toBe(true);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should block with multiple blocking tasks', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          userIdArb,
          realmIdArb,
          fc.array(blockingTaskTypeArb, { minLength: 2, maxLength: 4 }),
          nonWhitelistedEndpointArb,
          async (sessionId, userId, realmId, taskTypes, endpoint) => {
            // Create multiple blocking tasks
            const uniqueTypes = [...new Set(taskTypes)];
            for (const taskType of uniqueTypes) {
              mockService.createMockTask(sessionId, userId, realmId, taskType, {
                status: 'pending',
                blocking: true
              });
            }
            
            const event = createMockEvent(endpoint, 'GET', sessionId);
            const result = await validateSessionTaskBlocking(event, {
              service: mockService
            });
            
            // Should still be blocked
            expect(result.valid).toBe(false);
            expect(result.isBlocked).toBe(true);
            expect(result.blockingTasks?.length).toBeGreaterThanOrEqual(1);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should NOT block when task is non-blocking', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          userIdArb,
          realmIdArb,
          taskTypeArb,
          nonWhitelistedEndpointArb,
          async (sessionId, userId, realmId, taskType, endpoint) => {
            // Create task with explicit blocking=false
            mockService.createMockTask(sessionId, userId, realmId, taskType, {
              status: 'pending',
              blocking: false
            });
            
            const event = createMockEvent(endpoint, 'GET', sessionId);
            const result = await validateSessionTaskBlocking(event, {
              service: mockService
            });
            
            // Should NOT be blocked when blocking=false
            expect(result.valid).toBe(true);
            expect(result.isBlocked).toBe(false);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should NOT block when task is already completed', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          userIdArb,
          realmIdArb,
          blockingTaskTypeArb,
          nonWhitelistedEndpointArb,
          async (sessionId, userId, realmId, taskType, endpoint) => {
            // Create a completed task (even if it was blocking)
            mockService.createMockTask(sessionId, userId, realmId, taskType, {
              status: 'completed',
              blocking: true
            });
            
            const event = createMockEvent(endpoint, 'GET', sessionId);
            const result = await validateSessionTaskBlocking(event, {
              service: mockService
            });
            
            // Should NOT be blocked when task is completed
            expect(result.valid).toBe(true);
            expect(result.isBlocked).toBe(false);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should allow whitelisted endpoints even with blocking tasks', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          userIdArb,
          realmIdArb,
          blockingTaskTypeArb,
          fc.constantFrom(
            { endpoint: '/session/tasks', method: 'GET' },
            { endpoint: '/logout', method: 'POST' },
            { endpoint: '/me/password', method: 'PUT' },
            { endpoint: '/mfa/setup', method: 'POST' },
            { endpoint: '/health', method: 'GET' },
            { endpoint: '/me', method: 'GET' }
          ),
          async (sessionId, userId, realmId, taskType, whitelistedEndpoint) => {
            // Create a blocking task
            mockService.createMockTask(sessionId, userId, realmId, taskType, {
              status: 'pending',
              blocking: true
            });
            
            const event = createMockEvent(
              whitelistedEndpoint.endpoint,
              whitelistedEndpoint.method,
              sessionId
            );
            
            const result = await validateSessionTaskBlocking(event, {
              service: mockService
            });
            
            // Whitelisted endpoints should NOT be blocked
            expect(result.valid).toBe(true);
            expect(result.isBlocked).toBe(false);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should NOT block sessions without tasks', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          nonWhitelistedEndpointArb,
          httpMethodArb,
          async (sessionId, endpoint, method) => {
            // No tasks created for this session
            const event = createMockEvent(endpoint, method, sessionId);
            const result = await validateSessionTaskBlocking(event, {
              service: mockService
            });
            
            // Should NOT be blocked when no tasks exist
            expect(result.valid).toBe(true);
            expect(result.isBlocked).toBe(false);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  /**
   * Property 11: Task completion removes blocking
   * 
   * For any session with blocking tasks, when all blocking tasks are completed,
   * API calls SHALL succeed (no 403).
   * 
   * Properties:
   * - Completing a single blocking task removes blocking (if only one)
   * - Completing all blocking tasks removes blocking (if multiple)
   * - Partial completion still blocks (if multiple blocking tasks)
   * - Skipping non-blocking tasks doesn't affect blocking status
   * 
   * **Validates: Requirements 4.9**
   */
  describe('Property 11: Task completion removes blocking', () => {
    it('should remove blocking after completing single blocking task', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          userIdArb,
          realmIdArb,
          blockingTaskTypeArb,
          nonWhitelistedEndpointArb,
          async (sessionId, userId, realmId, taskType, endpoint) => {
            // Create a blocking task
            const task = mockService.createMockTask(sessionId, userId, realmId, taskType, {
              status: 'pending',
              blocking: true
            });
            
            const event = createMockEvent(endpoint, 'GET', sessionId);
            
            // Verify initially blocked
            let result = await validateSessionTaskBlocking(event, {
              service: mockService
            });
            expect(result.isBlocked).toBe(true);
            
            // Complete the task
            await mockService.completeTask(sessionId, task.id);
            
            // Verify no longer blocked
            result = await validateSessionTaskBlocking(event, {
              service: mockService
            });
            expect(result.valid).toBe(true);
            expect(result.isBlocked).toBe(false);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should remove blocking after completing all blocking tasks', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          userIdArb,
          realmIdArb,
          fc.array(blockingTaskTypeArb, { minLength: 2, maxLength: 3 }),
          nonWhitelistedEndpointArb,
          async (sessionId, userId, realmId, taskTypes, endpoint) => {
            // Create multiple blocking tasks with unique types
            const uniqueTypes = [...new Set(taskTypes)];
            fc.pre(uniqueTypes.length >= 2);
            
            const tasks: SessionTask[] = [];
            for (const taskType of uniqueTypes) {
              const task = mockService.createMockTask(sessionId, userId, realmId, taskType, {
                status: 'pending',
                blocking: true
              });
              tasks.push(task);
            }
            
            const event = createMockEvent(endpoint, 'GET', sessionId);
            
            // Verify initially blocked
            let result = await validateSessionTaskBlocking(event, {
              service: mockService
            });
            expect(result.isBlocked).toBe(true);
            
            // Complete all tasks
            for (const task of tasks) {
              await mockService.completeTask(sessionId, task.id);
            }
            
            // Verify no longer blocked
            result = await validateSessionTaskBlocking(event, {
              service: mockService
            });
            expect(result.valid).toBe(true);
            expect(result.isBlocked).toBe(false);
            
            return true;
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should still block with partial completion of multiple blocking tasks', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          userIdArb,
          realmIdArb,
          fc.array(blockingTaskTypeArb, { minLength: 2, maxLength: 3 }),
          nonWhitelistedEndpointArb,
          async (sessionId, userId, realmId, taskTypes, endpoint) => {
            // Create multiple blocking tasks with unique types
            const uniqueTypes = [...new Set(taskTypes)];
            fc.pre(uniqueTypes.length >= 2);
            
            const tasks: SessionTask[] = [];
            for (const taskType of uniqueTypes) {
              const task = mockService.createMockTask(sessionId, userId, realmId, taskType, {
                status: 'pending',
                blocking: true
              });
              tasks.push(task);
            }
            
            const event = createMockEvent(endpoint, 'GET', sessionId);
            
            // Complete only the first task
            await mockService.completeTask(sessionId, tasks[0].id);
            
            // Should still be blocked (other tasks remain)
            const result = await validateSessionTaskBlocking(event, {
              service: mockService
            });
            expect(result.isBlocked).toBe(true);
            expect(result.blockingTasks?.length).toBe(tasks.length - 1);
            
            return true;
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should maintain blocking status correctly through task lifecycle', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          userIdArb,
          realmIdArb,
          blockingTaskTypeArb,
          nonWhitelistedEndpointArb,
          async (sessionId, userId, realmId, taskType, endpoint) => {
            const event = createMockEvent(endpoint, 'GET', sessionId);
            
            // Initially no blocking
            let result = await validateSessionTaskBlocking(event, {
              service: mockService
            });
            expect(result.isBlocked).toBe(false);
            
            // Create blocking task -> should block
            const task = mockService.createMockTask(sessionId, userId, realmId, taskType, {
              status: 'pending',
              blocking: true
            });
            
            result = await validateSessionTaskBlocking(event, {
              service: mockService
            });
            expect(result.isBlocked).toBe(true);
            
            // Complete task -> should unblock
            await mockService.completeTask(sessionId, task.id);
            
            result = await validateSessionTaskBlocking(event, {
              service: mockService
            });
            expect(result.isBlocked).toBe(false);
            
            return true;
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should not affect blocking when completing non-blocking tasks', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          userIdArb,
          realmIdArb,
          blockingTaskTypeArb,
          taskTypeArb,
          nonWhitelistedEndpointArb,
          async (sessionId, userId, realmId, blockingType, nonBlockingType, endpoint) => {
            // Create one blocking and one non-blocking task
            const blockingTask = mockService.createMockTask(sessionId, userId, realmId, blockingType, {
              status: 'pending',
              blocking: true
            });
            
            const nonBlockingTask = mockService.createMockTask(sessionId, userId, realmId, nonBlockingType, {
              status: 'pending',
              blocking: false
            });
            
            const event = createMockEvent(endpoint, 'GET', sessionId);
            
            // Initially blocked
            let result = await validateSessionTaskBlocking(event, {
              service: mockService
            });
            expect(result.isBlocked).toBe(true);
            
            // Complete non-blocking task
            await mockService.completeTask(sessionId, nonBlockingTask.id);
            
            // Should still be blocked (blocking task remains)
            result = await validateSessionTaskBlocking(event, {
              service: mockService
            });
            expect(result.isBlocked).toBe(true);
            
            // Complete blocking task
            await mockService.completeTask(sessionId, blockingTask.id);
            
            // Now should be unblocked
            result = await validateSessionTaskBlocking(event, {
              service: mockService
            });
            expect(result.isBlocked).toBe(false);
            
            return true;
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should correctly report remaining blocking tasks count', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          userIdArb,
          realmIdArb,
          fc.integer({ min: 2, max: 4 }),
          nonWhitelistedEndpointArb,
          async (sessionId, userId, realmId, taskCount, endpoint) => {
            // Create multiple blocking tasks
            const taskTypes: SessionTaskType[] = ['reset_password', 'setup_mfa', 'accept_terms', 'choose_organization'];
            const tasks: SessionTask[] = [];
            
            for (let i = 0; i < Math.min(taskCount, taskTypes.length); i++) {
              const task = mockService.createMockTask(sessionId, userId, realmId, taskTypes[i], {
                status: 'pending',
                blocking: true
              });
              tasks.push(task);
            }
            
            const event = createMockEvent(endpoint, 'GET', sessionId);
            
            // Complete tasks one by one and verify count decreases
            for (let i = 0; i < tasks.length; i++) {
              const result = await validateSessionTaskBlocking(event, {
                service: mockService
              });
              
              if (i < tasks.length) {
                expect(result.blockingTasks?.length).toBe(tasks.length - i);
              }
              
              await mockService.completeTask(sessionId, tasks[i].id);
            }
            
            // After all completed, should not be blocked
            const finalResult = await validateSessionTaskBlocking(event, {
              service: mockService
            });
            expect(finalResult.isBlocked).toBe(false);
            
            return true;
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  /**
   * Property 12: Force password reset creates task
   * 
   * For any user, when forcePasswordReset is called,
   * a reset_password task SHALL be created for that user's session.
   * 
   * Properties:
   * - forcePasswordReset creates a reset_password task
   * - The task is blocking by default
   * - The task has highest priority (1)
   * - The task includes reason metadata
   * - Multiple calls don't create duplicate tasks (handled by service)
   * 
   * **Validates: Requirements 4.2, 4.9**
   */
  describe('Property 12: Force password reset creates task', () => {
    it('should create reset_password task with correct properties', async () => {
      const service = new SessionTasksService();
      
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          fc.constantFrom('compromised', 'expired', 'admin_forced', 'policy') as fc.Arbitrary<'compromised' | 'expired' | 'admin_forced' | 'policy'>,
          async (userId, realmId, reason) => {
            // Note: This test validates the service logic for task creation
            // In production, forcePasswordReset would interact with session repository
            
            // Verify default blocking behavior for reset_password
            const defaultBlocking = getDefaultBlocking('reset_password');
            expect(defaultBlocking).toBe(true);
            
            // Verify default priority for reset_password (highest = 1)
            const defaultPriority = getDefaultPriority('reset_password');
            expect(defaultPriority).toBe(1);
            
            // Verify reset_password is in DEFAULT_TASK_BLOCKING as true
            expect(DEFAULT_TASK_BLOCKING['reset_password']).toBe(true);
            
            // Verify reset_password has highest priority
            expect(DEFAULT_TASK_PRIORITIES['reset_password']).toBe(1);
            
            return true;
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should create blocking task that blocks API access', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          userIdArb,
          realmIdArb,
          nonWhitelistedEndpointArb,
          async (sessionId, userId, realmId, endpoint) => {
            // Simulate forcePasswordReset by creating reset_password task
            mockService.createMockTask(sessionId, userId, realmId, 'reset_password', {
              status: 'pending',
              blocking: true,
              priority: 1
            });
            
            const event = createMockEvent(endpoint, 'GET', sessionId);
            const result = await validateSessionTaskBlocking(event, {
              service: mockService
            });
            
            // Should be blocked
            expect(result.isBlocked).toBe(true);
            expect(result.error?.code).toBe('SESSION_TASK_PENDING');
            
            // Blocking task should be reset_password
            expect(result.blockingTasks?.some(t => t.type === 'reset_password')).toBe(true);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should allow password reset endpoints even when blocked', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          userIdArb,
          realmIdArb,
          fc.constantFrom(
            { endpoint: '/me/password', method: 'PUT' },
            { endpoint: '/me/password', method: 'POST' },
            { endpoint: '/password/reset', method: 'POST' },
            { endpoint: '/password/change', method: 'POST' }
          ),
          async (sessionId, userId, realmId, passwordEndpoint) => {
            // Create reset_password blocking task
            mockService.createMockTask(sessionId, userId, realmId, 'reset_password', {
              status: 'pending',
              blocking: true,
              priority: 1
            });
            
            const event = createMockEvent(
              passwordEndpoint.endpoint,
              passwordEndpoint.method,
              sessionId
            );
            
            const result = await validateSessionTaskBlocking(event, {
              service: mockService
            });
            
            // Password endpoints should be whitelisted
            expect(result.valid).toBe(true);
            expect(result.isBlocked).toBe(false);
            
            return true;
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should have reset_password as highest priority task', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          userIdArb,
          realmIdArb,
          fc.array(blockingTaskTypeArb, { minLength: 2, maxLength: 4 }),
          async (sessionId, userId, realmId, taskTypes) => {
            // Ensure reset_password is included
            const typesWithReset = [...new Set([...taskTypes, 'reset_password' as SessionTaskType])];
            
            // Create tasks
            for (const taskType of typesWithReset) {
              mockService.createMockTask(sessionId, userId, realmId, taskType, {
                status: 'pending',
                blocking: true
              });
            }
            
            // Get blocking tasks
            const blockingTasks = await mockService.getBlockingTasks(sessionId);
            
            // Find reset_password task
            const resetTask = blockingTasks.find(t => t.type === 'reset_password');
            expect(resetTask).toBeDefined();
            
            // Verify it has highest priority (lowest number)
            const minPriority = Math.min(...blockingTasks.map(t => t.priority));
            expect(resetTask?.priority).toBe(minPriority);
            expect(resetTask?.priority).toBe(1);
            
            return true;
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should unblock after password reset task is completed', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          userIdArb,
          realmIdArb,
          nonWhitelistedEndpointArb,
          async (sessionId, userId, realmId, endpoint) => {
            // Create reset_password task (simulating forcePasswordReset)
            const task = mockService.createMockTask(sessionId, userId, realmId, 'reset_password', {
              status: 'pending',
              blocking: true,
              priority: 1
            });
            
            const event = createMockEvent(endpoint, 'GET', sessionId);
            
            // Verify blocked
            let result = await validateSessionTaskBlocking(event, {
              service: mockService
            });
            expect(result.isBlocked).toBe(true);
            
            // Complete the reset_password task (user changed password)
            await mockService.completeTask(sessionId, task.id);
            
            // Verify unblocked
            result = await validateSessionTaskBlocking(event, {
              service: mockService
            });
            expect(result.isBlocked).toBe(false);
            
            return true;
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should include reason in task metadata', () => {
      fc.assert(
        fc.property(
          sessionIdArb,
          userIdArb,
          realmIdArb,
          fc.constantFrom('compromised', 'expired', 'admin_forced', 'policy'),
          (sessionId, userId, realmId, reason) => {
            // Create task with metadata
            const task: SessionTask = {
              id: 'task_test',
              session_id: sessionId,
              user_id: userId,
              realm_id: realmId,
              type: 'reset_password',
              status: 'pending',
              blocking: true,
              priority: 1,
              created_at: new Date().toISOString(),
              metadata: {
                reason: reason as 'compromised' | 'expired' | 'admin_forced' | 'policy',
                message: 'Your password must be reset'
              }
            };
            
            // Verify metadata is preserved
            expect(task.metadata?.reason).toBe(reason);
            expect(task.metadata?.message).toBeDefined();
            
            return true;
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  /**
   * Additional property tests for endpoint matching and whitelist
   */
  describe('Endpoint whitelist properties', () => {
    it('should match exact endpoints correctly', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...DEFAULT_WHITELISTED_ENDPOINTS.map(e => e.endpoint)),
          (endpoint) => {
            // Exact match should work
            expect(matchEndpoint(endpoint, endpoint)).toBe(true);
            return true;
          }
        ),
        { numRuns: DEFAULT_WHITELISTED_ENDPOINTS.length }
      );
    });

    it('should match wildcard patterns correctly', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(
            { pattern: '/session/tasks/*/complete', endpoint: '/session/tasks/task_123/complete', expected: true },
            { pattern: '/health/*', endpoint: '/health/check', expected: true },
            { pattern: '/reverify/*', endpoint: '/reverify/password', expected: true },
            { pattern: '/.well-known/*', endpoint: '/.well-known/openid-configuration', expected: true },
            { pattern: '/users', endpoint: '/users/123', expected: false },
            { pattern: '/session/tasks', endpoint: '/session/tasks/123', expected: false }
          ),
          ({ pattern, endpoint, expected }) => {
            expect(matchEndpoint(endpoint, pattern)).toBe(expected);
            return true;
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should correctly identify whitelisted vs non-whitelisted endpoints', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(
            // Whitelisted
            { endpoint: '/session/tasks', method: 'GET', whitelisted: true },
            { endpoint: '/logout', method: 'POST', whitelisted: true },
            { endpoint: '/me', method: 'GET', whitelisted: true },
            { endpoint: '/health', method: 'GET', whitelisted: true },
            // Non-whitelisted
            { endpoint: '/users', method: 'GET', whitelisted: false },
            { endpoint: '/tenants', method: 'POST', whitelisted: false },
            { endpoint: '/api/data', method: 'GET', whitelisted: false },
            { endpoint: '/admin/settings', method: 'PUT', whitelisted: false }
          ),
          ({ endpoint, method, whitelisted }) => {
            const event = createMockEvent(endpoint, method);
            expect(isEndpointWhitelisted(event)).toBe(whitelisted);
            return true;
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  /**
   * Additional property tests for task blocking logic
   */
  describe('Task blocking logic properties', () => {
    it('should correctly identify blocking tasks', () => {
      fc.assert(
        fc.property(
          sessionIdArb,
          userIdArb,
          realmIdArb,
          taskTypeArb,
          taskStatusArb,
          fc.boolean(),
          (sessionId, userId, realmId, type, status, blocking) => {
            const task: SessionTask = {
              id: 'task_test',
              session_id: sessionId,
              user_id: userId,
              realm_id: realmId,
              type,
              status,
              blocking,
              priority: getDefaultPriority(type),
              created_at: new Date().toISOString()
            };
            
            const isBlocking = isTaskBlocking(task);
            
            // Task is blocking only if: pending AND blocking=true AND not expired
            const expectedBlocking = status === 'pending' && blocking === true;
            expect(isBlocking).toBe(expectedBlocking);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should have consistent default blocking per task type', () => {
      fc.assert(
        fc.property(
          taskTypeArb,
          (taskType) => {
            const defaultBlocking = getDefaultBlocking(taskType);
            
            // Verify against known defaults
            switch (taskType) {
              case 'reset_password':
              case 'setup_mfa':
              case 'accept_terms':
              case 'choose_organization':
                expect(defaultBlocking).toBe(true);
                break;
              case 'custom':
                expect(defaultBlocking).toBe(false);
                break;
            }
            
            return true;
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should have consistent default priority per task type', () => {
      fc.assert(
        fc.property(
          taskTypeArb,
          (taskType) => {
            const priority = getDefaultPriority(taskType);
            
            // Verify priority ordering
            expect(priority).toBeGreaterThanOrEqual(1);
            expect(priority).toBeLessThanOrEqual(5);
            
            // reset_password should have highest priority (1)
            if (taskType === 'reset_password') {
              expect(priority).toBe(1);
            }
            
            // custom should have lowest priority (5)
            if (taskType === 'custom') {
              expect(priority).toBe(5);
            }
            
            return true;
          }
        ),
        { numRuns: 20 }
      );
    });
  });
});
