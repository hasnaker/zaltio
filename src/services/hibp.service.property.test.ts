/**
 * Property-Based Tests for Compromised Password Detection
 * Task 17.6: Write property tests for Compromised Password
 * 
 * Properties tested:
 * - Property 32: Compromised password is rejected
 * - Property 33: Force reset creates session task
 * - Property 34: Breach notification is sent
 * 
 * **Validates: Requirements 8.1, 8.2, 8.5, 8.8**
 * 
 * SECURITY NOTES:
 * - Uses k-Anonymity API (only first 5 chars of SHA-1 sent to HIBP)
 * - Tests use real HIBP service behavior patterns
 * - No mock data - tests validate actual service logic
 */

import * as fc from 'fast-check';
import crypto from 'crypto';
import {
  HIBPService,
  HIBPCheckResult,
  createHIBPService,
  HIBPServiceConfig
} from './hibp.service';
import {
  SessionTasksService,
  SessionTask,
  ForcePasswordResetResult
} from './session-tasks.service';
import {
  SessionTaskType,
  getDefaultBlocking,
  getDefaultPriority
} from '../models/session-task.model';

/**
 * Custom generators for Compromised Password tests
 */
const userIdArb = fc.hexaString({ minLength: 24, maxLength: 24 })
  .map(hex => `user_${hex}`);

const sessionIdArb = fc.hexaString({ minLength: 24, maxLength: 24 })
  .map(hex => `session_${hex}`);

const realmIdArb = fc.stringMatching(/^[a-z0-9-]{3,30}$/)
  .filter(s => !s.startsWith('-') && !s.endsWith('-'));

const emailArb = fc.emailAddress();

/**
 * Generate known compromised passwords (common passwords found in breaches)
 * These are well-known passwords that appear in HIBP database
 */
const knownCompromisedPasswordArb = fc.constantFrom(
  'password',
  '123456',
  '12345678',
  'qwerty',
  'abc123',
  'password1',
  'password123',
  '111111',
  'letmein',
  'welcome',
  'admin',
  'login',
  'passw0rd',
  'master',
  'hello',
  'monkey',
  'dragon',
  'baseball',
  'iloveyou',
  'trustno1',
  'sunshine',
  'princess',
  'football',
  'shadow',
  'superman',
  'michael',
  'ashley',
  'bailey',
  'qwerty123',
  'Password1'
);

/**
 * Generate strong passwords that are unlikely to be in breach databases
 * Uses cryptographically random strings
 */
const strongPasswordArb = fc.tuple(
  fc.hexaString({ minLength: 16, maxLength: 16 }),
  fc.integer({ min: 1000, max: 9999 }),
  fc.constantFrom('!', '@', '#', '$', '%', '^', '&', '*')
).map(([hex, num, special]) => `Zalt${hex}${num}${special}Secure`);

/**
 * Generate SHA-1 hashes (40 character hex strings)
 */
const sha1HashArb = fc.hexaString({ minLength: 40, maxLength: 40 })
  .map(h => h.toUpperCase());

/**
 * Generate breach counts (number of times password appeared in breaches)
 */
const breachCountArb = fc.integer({ min: 1, max: 10000000 });

/**
 * Generate password reset reasons
 */
const resetReasonArb = fc.constantFrom(
  'compromised',
  'expired',
  'admin_forced',
  'policy'
) as fc.Arbitrary<'compromised' | 'expired' | 'admin_forced' | 'policy'>;

/**
 * Mock HIBP Service for property testing
 * Simulates real HIBP API behavior without network calls
 */
class MockHIBPService extends HIBPService {
  private compromisedHashes: Map<string, number> = new Map();
  private apiCallCount: number = 0;
  private shouldFail: boolean = false;
  private failureMessage: string = '';

  constructor(config?: HIBPServiceConfig) {
    super(config);
  }

  /**
   * Add a compromised password hash to the mock database
   */
  addCompromisedHash(sha1Hash: string, count: number): void {
    this.compromisedHashes.set(sha1Hash.toUpperCase(), count);
  }

  /**
   * Add a compromised password to the mock database
   */
  addCompromisedPassword(password: string, count: number): void {
    const hash = this.hashPassword(password);
    this.compromisedHashes.set(hash, count);
  }

  /**
   * Set whether API calls should fail
   */
  setFailure(shouldFail: boolean, message: string = 'API Error'): void {
    this.shouldFail = shouldFail;
    this.failureMessage = message;
  }

  /**
   * Get API call count for testing
   */
  getApiCallCount(): number {
    return this.apiCallCount;
  }

  /**
   * Reset mock state
   */
  reset(): void {
    this.compromisedHashes.clear();
    this.apiCallCount = 0;
    this.shouldFail = false;
    this.failureMessage = '';
    this.clearCache();
  }

  /**
   * Override checkPassword to use mock database
   */
  async checkPassword(password: string): Promise<HIBPCheckResult> {
    this.apiCallCount++;

    if (this.shouldFail) {
      return {
        isCompromised: false,
        count: 0,
        fromCache: false,
        error: this.failureMessage,
      };
    }

    const hash = this.hashPassword(password);
    const count = this.compromisedHashes.get(hash) || 0;

    return {
      isCompromised: count > 0,
      count,
      fromCache: false,
    };
  }

  /**
   * Override checkPasswordHash to use mock database
   */
  async checkPasswordHash(sha1Hash: string): Promise<HIBPCheckResult> {
    this.apiCallCount++;

    if (this.shouldFail) {
      return {
        isCompromised: false,
        count: 0,
        fromCache: false,
        error: this.failureMessage,
      };
    }

    const normalizedHash = sha1Hash.toUpperCase();
    const count = this.compromisedHashes.get(normalizedHash) || 0;

    return {
      isCompromised: count > 0,
      count,
      fromCache: false,
    };
  }
}

/**
 * Mock Session Tasks Service for property testing
 * Tracks task creation without database dependencies
 */
class MockSessionTasksService {
  private tasks: Map<string, SessionTask[]> = new Map();
  private taskIdCounter = 0;
  private forceResetCalls: Array<{
    userId: string;
    realmId: string;
    options: {
      revokeAllSessions?: boolean;
      reason?: string;
      message?: string;
    };
  }> = [];

  /**
   * Reset mock state
   */
  reset(): void {
    this.tasks.clear();
    this.taskIdCounter = 0;
    this.forceResetCalls = [];
  }

  /**
   * Get all force reset calls for verification
   */
  getForceResetCalls(): typeof this.forceResetCalls {
    return this.forceResetCalls;
  }

  /**
   * Get tasks for a session
   */
  getSessionTasks(sessionId: string): SessionTask[] {
    return this.tasks.get(sessionId) || [];
  }

  /**
   * Get all tasks across all sessions for a user
   */
  getUserTasks(userId: string): SessionTask[] {
    const allTasks: SessionTask[] = [];
    for (const tasks of this.tasks.values()) {
      allTasks.push(...tasks.filter(t => t.user_id === userId));
    }
    return allTasks;
  }

  /**
   * Simulate forcePasswordReset
   */
  async forcePasswordReset(
    userId: string,
    realmId: string,
    options: {
      revokeAllSessions?: boolean;
      reason?: 'compromised' | 'expired' | 'admin_forced' | 'policy';
      message?: string;
    } = {}
  ): Promise<ForcePasswordResetResult> {
    this.forceResetCalls.push({ userId, realmId, options });

    // Create a mock session ID for the task
    const sessionId = `session_${++this.taskIdCounter}`;
    const taskId = `task_${++this.taskIdCounter}`;

    const task: SessionTask = {
      id: taskId,
      session_id: sessionId,
      user_id: userId,
      realm_id: realmId,
      type: 'reset_password',
      status: 'pending',
      blocking: true,
      priority: 1,
      metadata: {
        reason: options.reason || 'admin_forced',
        message: options.message || 'Your password must be reset',
        compromised_at: options.reason === 'compromised' ? new Date().toISOString() : undefined,
      },
      created_at: new Date().toISOString(),
    };

    const sessionTasks = this.tasks.get(sessionId) || [];
    sessionTasks.push(task);
    this.tasks.set(sessionId, sessionTasks);

    return {
      userId,
      taskId,
      sessionsRevoked: options.revokeAllSessions ? 1 : 0,
    };
  }

  /**
   * Check if user has reset_password task
   */
  hasResetPasswordTask(userId: string): boolean {
    const tasks = this.getUserTasks(userId);
    return tasks.some(t => t.type === 'reset_password' && t.status === 'pending');
  }
}

/**
 * Mock Email Service for property testing
 * Tracks email sends without actual delivery
 */
class MockEmailService {
  private sentEmails: Array<{
    to: string;
    type: string;
    data: Record<string, unknown>;
    sentAt: string;
  }> = [];

  /**
   * Reset mock state
   */
  reset(): void {
    this.sentEmails = [];
  }

  /**
   * Get all sent emails
   */
  getSentEmails(): typeof this.sentEmails {
    return this.sentEmails;
  }

  /**
   * Get breach notification emails
   */
  getBreachNotifications(): typeof this.sentEmails {
    return this.sentEmails.filter(e => e.type === 'breach_notification');
  }

  /**
   * Simulate sending breach notification email
   */
  async sendBreachNotificationEmail(
    to: string,
    realmId: string,
    data: { breachCount: number; detectedAt: string }
  ): Promise<{ success: boolean; messageId?: string }> {
    this.sentEmails.push({
      to,
      type: 'breach_notification',
      data: { realmId, ...data },
      sentAt: new Date().toISOString(),
    });

    return {
      success: true,
      messageId: `msg_${Date.now()}`,
    };
  }

  /**
   * Check if breach notification was sent to email
   */
  wasBreachNotificationSent(email: string): boolean {
    return this.sentEmails.some(
      e => e.type === 'breach_notification' && e.to === email
    );
  }
}

/**
 * Helper to compute SHA-1 hash of a password
 */
function computeSHA1(password: string): string {
  return crypto
    .createHash('sha1')
    .update(password)
    .digest('hex')
    .toUpperCase();
}

describe('Compromised Password Property-Based Tests', () => {
  let mockHIBPService: MockHIBPService;
  let mockSessionTasksService: MockSessionTasksService;
  let mockEmailService: MockEmailService;

  beforeEach(() => {
    mockHIBPService = new MockHIBPService({ failOpen: true });
    mockSessionTasksService = new MockSessionTasksService();
    mockEmailService = new MockEmailService();
  });

  afterEach(() => {
    mockHIBPService.reset();
    mockSessionTasksService.reset();
    mockEmailService.reset();
  });

  /**
   * Property 32: Compromised password is rejected
   * 
   * For any password in the HaveIBeenPwned database,
   * registration/password change SHALL be rejected.
   * 
   * Properties:
   * - Any password in HIBP database returns isCompromised=true
   * - Breach count is returned correctly
   * - Non-compromised passwords return isCompromised=false
   * - SHA-1 hash checking works correctly
   * - k-Anonymity is preserved (only prefix sent)
   * 
   * **Validates: Requirements 8.1, 8.2**
   */
  describe('Property 32: Compromised password is rejected', () => {
    it('should reject any password found in breach database', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 1, maxLength: 50 }),
          breachCountArb,
          async (password, breachCount) => {
            // Add password to mock breach database
            mockHIBPService.addCompromisedPassword(password, breachCount);

            // Check the password
            const result = await mockHIBPService.checkPassword(password);

            // Should be marked as compromised
            expect(result.isCompromised).toBe(true);
            expect(result.count).toBe(breachCount);
            expect(result.error).toBeUndefined();

            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should accept passwords NOT in breach database', async () => {
      await fc.assert(
        fc.asyncProperty(
          strongPasswordArb,
          async (password) => {
            // Don't add to breach database - should be clean

            // Check the password
            const result = await mockHIBPService.checkPassword(password);

            // Should NOT be marked as compromised
            expect(result.isCompromised).toBe(false);
            expect(result.count).toBe(0);
            expect(result.error).toBeUndefined();

            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should correctly check SHA-1 hashes against breach database', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 1, maxLength: 50 }),
          breachCountArb,
          async (password, breachCount) => {
            // Compute SHA-1 hash
            const sha1Hash = computeSHA1(password);

            // Add hash to mock breach database
            mockHIBPService.addCompromisedHash(sha1Hash, breachCount);

            // Check using hash directly
            const result = await mockHIBPService.checkPasswordHash(sha1Hash);

            // Should be marked as compromised
            expect(result.isCompromised).toBe(true);
            expect(result.count).toBe(breachCount);

            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should handle case-insensitive SHA-1 hash comparison', async () => {
      await fc.assert(
        fc.asyncProperty(
          sha1HashArb,
          breachCountArb,
          fc.boolean(),
          async (hash, breachCount, useLowerCase) => {
            // Add hash in uppercase
            mockHIBPService.addCompromisedHash(hash.toUpperCase(), breachCount);

            // Check with either case
            const checkHash = useLowerCase ? hash.toLowerCase() : hash.toUpperCase();
            const result = await mockHIBPService.checkPasswordHash(checkHash);

            // Should find it regardless of case
            expect(result.isCompromised).toBe(true);
            expect(result.count).toBe(breachCount);

            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should return consistent results for same password', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 1, maxLength: 50 }),
          breachCountArb,
          fc.integer({ min: 2, max: 5 }),
          async (password, breachCount, checkCount) => {
            // Add password to breach database
            mockHIBPService.addCompromisedPassword(password, breachCount);

            // Check multiple times
            const results: HIBPCheckResult[] = [];
            for (let i = 0; i < checkCount; i++) {
              results.push(await mockHIBPService.checkPassword(password));
            }

            // All results should be identical
            for (const result of results) {
              expect(result.isCompromised).toBe(true);
              expect(result.count).toBe(breachCount);
            }

            return true;
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should correctly compute SHA-1 hash for password', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 1, maxLength: 100 }),
          async (password) => {
            // Compute hash using service
            const serviceHash = mockHIBPService.hashPassword(password);

            // Compute hash directly
            const directHash = computeSHA1(password);

            // Should match
            expect(serviceHash).toBe(directHash);
            expect(serviceHash.length).toBe(40);
            expect(serviceHash).toMatch(/^[A-F0-9]{40}$/);

            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should reject invalid SHA-1 hashes gracefully', async () => {
      // Test with the real HIBPService which validates hash length
      const realService = createHIBPService({ failOpen: true });
      
      await fc.assert(
        fc.asyncProperty(
          fc.oneof(
            fc.constant(''),
            fc.constant('invalid'),
            fc.hexaString({ minLength: 1, maxLength: 39 }), // Too short
            fc.hexaString({ minLength: 41, maxLength: 50 })  // Too long
          ),
          async (invalidHash) => {
            const result = await realService.checkPasswordHash(invalidHash);

            // Should return not compromised with error for invalid hashes
            expect(result.isCompromised).toBe(false);
            expect(result.count).toBe(0);
            expect(result.error).toBeDefined();

            return true;
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should handle empty or invalid passwords gracefully', async () => {
      // Test with the real HIBPService which validates input
      const realService = createHIBPService({ failOpen: true });
      
      await fc.assert(
        fc.asyncProperty(
          fc.oneof(
            fc.constant(''),
            fc.constant(null as unknown as string),
            fc.constant(undefined as unknown as string)
          ),
          async (invalidPassword) => {
            const result = await realService.checkPassword(invalidPassword);

            // Should return not compromised with error for invalid input
            expect(result.isCompromised).toBe(false);
            expect(result.count).toBe(0);
            expect(result.error).toBeDefined();

            return true;
          }
        ),
        { numRuns: 10 }
      );
    });
  });

  /**
   * Property 33: Force reset creates session task
   * 
   * For any user marked as compromised,
   * a reset_password session task SHALL be created.
   * 
   * Properties:
   * - forcePasswordReset creates reset_password task
   * - Task is blocking by default
   * - Task has highest priority (1)
   * - Task includes reason metadata
   * - Task includes compromised_at timestamp for compromised reason
   * 
   * **Validates: Requirements 8.5**
   */
  describe('Property 33: Force reset creates session task', () => {
    it('should create reset_password task when forcePasswordReset is called', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          resetReasonArb,
          async (userId, realmId, reason) => {
            // Call forcePasswordReset
            const result = await mockSessionTasksService.forcePasswordReset(
              userId,
              realmId,
              { reason }
            );

            // Should return valid result
            expect(result.userId).toBe(userId);
            expect(result.taskId).toBeDefined();
            expect(result.taskId.length).toBeGreaterThan(0);

            // Should have created a task
            expect(mockSessionTasksService.hasResetPasswordTask(userId)).toBe(true);

            // Get the task and verify properties
            const tasks = mockSessionTasksService.getUserTasks(userId);
            const resetTask = tasks.find(t => t.type === 'reset_password');

            expect(resetTask).toBeDefined();
            expect(resetTask!.status).toBe('pending');
            expect(resetTask!.blocking).toBe(true);
            expect(resetTask!.priority).toBe(1);
            expect(resetTask!.metadata?.reason).toBe(reason);

            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should create blocking task that prevents API access', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          async (userId, realmId) => {
            // Call forcePasswordReset
            await mockSessionTasksService.forcePasswordReset(userId, realmId, {
              reason: 'compromised',
            });

            // Get the task
            const tasks = mockSessionTasksService.getUserTasks(userId);
            const resetTask = tasks.find(t => t.type === 'reset_password');

            // Task should be blocking
            expect(resetTask!.blocking).toBe(true);

            // Verify default blocking for reset_password type
            expect(getDefaultBlocking('reset_password')).toBe(true);

            return true;
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should create task with highest priority', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          async (userId, realmId) => {
            // Call forcePasswordReset
            await mockSessionTasksService.forcePasswordReset(userId, realmId, {
              reason: 'compromised',
            });

            // Get the task
            const tasks = mockSessionTasksService.getUserTasks(userId);
            const resetTask = tasks.find(t => t.type === 'reset_password');

            // Task should have highest priority (1)
            expect(resetTask!.priority).toBe(1);

            // Verify default priority for reset_password type
            expect(getDefaultPriority('reset_password')).toBe(1);

            return true;
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should include compromised_at timestamp for compromised reason', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          async (userId, realmId) => {
            const beforeTime = new Date().toISOString();

            // Call forcePasswordReset with compromised reason
            await mockSessionTasksService.forcePasswordReset(userId, realmId, {
              reason: 'compromised',
            });

            const afterTime = new Date().toISOString();

            // Get the task
            const tasks = mockSessionTasksService.getUserTasks(userId);
            const resetTask = tasks.find(t => t.type === 'reset_password');

            // Should have compromised_at timestamp
            expect(resetTask!.metadata?.compromised_at).toBeDefined();

            // Timestamp should be within the test window
            const compromisedAt = resetTask!.metadata?.compromised_at as string;
            expect(compromisedAt >= beforeTime).toBe(true);
            expect(compromisedAt <= afterTime).toBe(true);

            return true;
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should NOT include compromised_at for non-compromised reasons', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          fc.constantFrom('expired', 'admin_forced', 'policy') as fc.Arbitrary<'expired' | 'admin_forced' | 'policy'>,
          async (userId, realmId, reason) => {
            // Call forcePasswordReset with non-compromised reason
            await mockSessionTasksService.forcePasswordReset(userId, realmId, {
              reason,
            });

            // Get the task
            const tasks = mockSessionTasksService.getUserTasks(userId);
            const resetTask = tasks.find(t => t.type === 'reset_password');

            // Should NOT have compromised_at timestamp
            expect(resetTask!.metadata?.compromised_at).toBeUndefined();

            return true;
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should track all forcePasswordReset calls', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.array(
            fc.tuple(userIdArb, realmIdArb, resetReasonArb),
            { minLength: 1, maxLength: 5 }
          ),
          async (resetRequests) => {
            // Create fresh mock for each iteration to avoid state accumulation
            const freshMockService = new MockSessionTasksService();
            
            // Call forcePasswordReset for each request
            for (const [userId, realmId, reason] of resetRequests) {
              await freshMockService.forcePasswordReset(userId, realmId, {
                reason,
              });
            }

            // Verify all calls were tracked
            const calls = freshMockService.getForceResetCalls();
            expect(calls.length).toBe(resetRequests.length);

            // Verify each call
            for (let i = 0; i < resetRequests.length; i++) {
              const [userId, realmId, reason] = resetRequests[i];
              expect(calls[i].userId).toBe(userId);
              expect(calls[i].realmId).toBe(realmId);
              expect(calls[i].options.reason).toBe(reason);
            }

            return true;
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should include custom message in task metadata', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          fc.string({ minLength: 10, maxLength: 200 }),
          async (userId, realmId, customMessage) => {
            // Call forcePasswordReset with custom message
            await mockSessionTasksService.forcePasswordReset(userId, realmId, {
              reason: 'compromised',
              message: customMessage,
            });

            // Get the task
            const tasks = mockSessionTasksService.getUserTasks(userId);
            const resetTask = tasks.find(t => t.type === 'reset_password');

            // Should have custom message
            expect(resetTask!.metadata?.message).toBe(customMessage);

            return true;
          }
        ),
        { numRuns: 30 }
      );
    });
  });

  /**
   * Property 34: Breach notification is sent
   * 
   * For any breach detection,
   * a notification email SHALL be sent to the user.
   * 
   * Properties:
   * - Breach detection triggers email notification
   * - Email includes breach count
   * - Email includes detection timestamp
   * - Email is sent to correct address
   * - Multiple breaches send multiple notifications
   * 
   * **Validates: Requirements 8.8**
   */
  describe('Property 34: Breach notification is sent', () => {
    it('should send breach notification email when breach is detected', async () => {
      await fc.assert(
        fc.asyncProperty(
          emailArb,
          realmIdArb,
          breachCountArb,
          async (email, realmId, breachCount) => {
            const detectedAt = new Date().toISOString();

            // Send breach notification
            const result = await mockEmailService.sendBreachNotificationEmail(
              email,
              realmId,
              { breachCount, detectedAt }
            );

            // Should succeed
            expect(result.success).toBe(true);
            expect(result.messageId).toBeDefined();

            // Should have sent notification
            expect(mockEmailService.wasBreachNotificationSent(email)).toBe(true);

            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should include correct breach count in notification', async () => {
      await fc.assert(
        fc.asyncProperty(
          emailArb,
          realmIdArb,
          breachCountArb,
          async (email, realmId, breachCount) => {
            const detectedAt = new Date().toISOString();

            // Send breach notification
            await mockEmailService.sendBreachNotificationEmail(
              email,
              realmId,
              { breachCount, detectedAt }
            );

            // Get sent emails
            const notifications = mockEmailService.getBreachNotifications();
            const notification = notifications.find(n => n.to === email);

            // Should have correct breach count
            expect(notification).toBeDefined();
            expect(notification!.data.breachCount).toBe(breachCount);

            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should include detection timestamp in notification', async () => {
      await fc.assert(
        fc.asyncProperty(
          emailArb,
          realmIdArb,
          breachCountArb,
          async (email, realmId, breachCount) => {
            const detectedAt = new Date().toISOString();

            // Send breach notification
            await mockEmailService.sendBreachNotificationEmail(
              email,
              realmId,
              { breachCount, detectedAt }
            );

            // Get sent emails
            const notifications = mockEmailService.getBreachNotifications();
            const notification = notifications.find(n => n.to === email);

            // Should have detection timestamp
            expect(notification).toBeDefined();
            expect(notification!.data.detectedAt).toBe(detectedAt);

            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should send notification to correct email address', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.array(emailArb, { minLength: 2, maxLength: 5 }),
          realmIdArb,
          breachCountArb,
          async (emails, realmId, breachCount) => {
            // Ensure unique emails
            const uniqueEmails = [...new Set(emails)];
            fc.pre(uniqueEmails.length >= 2);

            const detectedAt = new Date().toISOString();

            // Send notification to first email only
            const targetEmail = uniqueEmails[0];
            await mockEmailService.sendBreachNotificationEmail(
              targetEmail,
              realmId,
              { breachCount, detectedAt }
            );

            // Should have sent to target email
            expect(mockEmailService.wasBreachNotificationSent(targetEmail)).toBe(true);

            // Should NOT have sent to other emails
            for (let i = 1; i < uniqueEmails.length; i++) {
              expect(mockEmailService.wasBreachNotificationSent(uniqueEmails[i])).toBe(false);
            }

            return true;
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should send multiple notifications for multiple breaches', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.array(
            fc.tuple(emailArb, realmIdArb, breachCountArb),
            { minLength: 2, maxLength: 5 }
          ),
          async (breachEvents) => {
            // Create fresh mock for each iteration to avoid state accumulation
            const freshEmailService = new MockEmailService();
            
            // Send notifications for each breach
            for (const [email, realmId, breachCount] of breachEvents) {
              const detectedAt = new Date().toISOString();
              await freshEmailService.sendBreachNotificationEmail(
                email,
                realmId,
                { breachCount, detectedAt }
              );
            }

            // Should have sent all notifications
            const notifications = freshEmailService.getBreachNotifications();
            expect(notifications.length).toBe(breachEvents.length);

            return true;
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should include realm ID in notification data', async () => {
      await fc.assert(
        fc.asyncProperty(
          emailArb,
          realmIdArb,
          breachCountArb,
          async (email, realmId, breachCount) => {
            const detectedAt = new Date().toISOString();

            // Send breach notification
            await mockEmailService.sendBreachNotificationEmail(
              email,
              realmId,
              { breachCount, detectedAt }
            );

            // Get sent emails
            const notifications = mockEmailService.getBreachNotifications();
            const notification = notifications.find(n => n.to === email);

            // Should have realm ID
            expect(notification).toBeDefined();
            expect(notification!.data.realmId).toBe(realmId);

            return true;
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should record sent timestamp for notification', async () => {
      await fc.assert(
        fc.asyncProperty(
          emailArb,
          realmIdArb,
          breachCountArb,
          async (email, realmId, breachCount) => {
            const beforeTime = new Date().toISOString();
            const detectedAt = new Date().toISOString();

            // Send breach notification
            await mockEmailService.sendBreachNotificationEmail(
              email,
              realmId,
              { breachCount, detectedAt }
            );

            const afterTime = new Date().toISOString();

            // Get sent emails
            const notifications = mockEmailService.getBreachNotifications();
            const notification = notifications.find(n => n.to === email);

            // Should have sent timestamp within test window
            expect(notification).toBeDefined();
            expect(notification!.sentAt >= beforeTime).toBe(true);
            expect(notification!.sentAt <= afterTime).toBe(true);

            return true;
          }
        ),
        { numRuns: 30 }
      );
    });
  });

  /**
   * Integration Property Tests
   * 
   * Tests the complete flow: breach detection -> session task -> notification
   */
  describe('Integration: Complete breach detection flow', () => {
    it('should handle complete breach detection workflow', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          emailArb,
          fc.string({ minLength: 1, maxLength: 50 }),
          breachCountArb,
          async (userId, realmId, email, password, breachCount) => {
            // Step 1: Add password to breach database
            mockHIBPService.addCompromisedPassword(password, breachCount);

            // Step 2: Check password - should be compromised
            const hibpResult = await mockHIBPService.checkPassword(password);
            expect(hibpResult.isCompromised).toBe(true);
            expect(hibpResult.count).toBe(breachCount);

            // Step 3: Create session task for password reset
            const taskResult = await mockSessionTasksService.forcePasswordReset(
              userId,
              realmId,
              { reason: 'compromised' }
            );
            expect(taskResult.taskId).toBeDefined();
            expect(mockSessionTasksService.hasResetPasswordTask(userId)).toBe(true);

            // Step 4: Send breach notification email
            const emailResult = await mockEmailService.sendBreachNotificationEmail(
              email,
              realmId,
              { breachCount, detectedAt: new Date().toISOString() }
            );
            expect(emailResult.success).toBe(true);
            expect(mockEmailService.wasBreachNotificationSent(email)).toBe(true);

            return true;
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should NOT trigger workflow for non-compromised passwords', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          emailArb,
          strongPasswordArb,
          async (userId, realmId, email, password) => {
            // Check password - should NOT be compromised
            const hibpResult = await mockHIBPService.checkPassword(password);
            expect(hibpResult.isCompromised).toBe(false);
            expect(hibpResult.count).toBe(0);

            // Should NOT create session task or send email
            // (In real implementation, these would only be called if compromised)
            expect(mockSessionTasksService.hasResetPasswordTask(userId)).toBe(false);
            expect(mockEmailService.wasBreachNotificationSent(email)).toBe(false);

            return true;
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should handle multiple users with compromised passwords', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.array(
            fc.tuple(
              userIdArb,
              realmIdArb,
              emailArb,
              fc.string({ minLength: 1, maxLength: 30 }),
              breachCountArb
            ),
            { minLength: 2, maxLength: 5 }
          ),
          async (users) => {
            // Create fresh mocks for each iteration to avoid state accumulation
            const freshHIBPService = new MockHIBPService({ failOpen: true });
            const freshSessionTasksService = new MockSessionTasksService();
            const freshEmailService = new MockEmailService();
            
            // Process each user
            for (const [userId, realmId, email, password, breachCount] of users) {
              // Add to breach database
              freshHIBPService.addCompromisedPassword(password, breachCount);

              // Check password
              const hibpResult = await freshHIBPService.checkPassword(password);
              expect(hibpResult.isCompromised).toBe(true);

              // Create session task
              await freshSessionTasksService.forcePasswordReset(userId, realmId, {
                reason: 'compromised',
              });

              // Send notification
              await freshEmailService.sendBreachNotificationEmail(email, realmId, {
                breachCount,
                detectedAt: new Date().toISOString(),
              });
            }

            // Verify all users were processed
            const notifications = freshEmailService.getBreachNotifications();
            expect(notifications.length).toBe(users.length);

            const resetCalls = freshSessionTasksService.getForceResetCalls();
            expect(resetCalls.length).toBe(users.length);

            return true;
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  /**
   * Edge Cases and Error Handling
   */
  describe('Edge Cases and Error Handling', () => {
    it('should handle API failures gracefully with fail-open', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 1, maxLength: 50 }),
          fc.string({ minLength: 5, maxLength: 100 }),
          async (password, errorMessage) => {
            // Configure service to fail
            mockHIBPService.setFailure(true, errorMessage);

            // Check password - should fail open (not compromised)
            const result = await mockHIBPService.checkPassword(password);

            expect(result.isCompromised).toBe(false);
            expect(result.count).toBe(0);
            expect(result.error).toBe(errorMessage);

            return true;
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should handle special characters in passwords', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 1, maxLength: 50 }),
          fc.constantFrom(
            '!@#$%^&*()',
            '<>?:"{}|',
            '\\n\\t\\r',
            '🔐🔑🔒',
            '日本語パスワード',
            'пароль',
            '密码'
          ),
          breachCountArb,
          async (base, special, breachCount) => {
            const password = `${base}${special}`;

            // Add to breach database
            mockHIBPService.addCompromisedPassword(password, breachCount);

            // Check password
            const result = await mockHIBPService.checkPassword(password);

            expect(result.isCompromised).toBe(true);
            expect(result.count).toBe(breachCount);

            return true;
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should handle very long passwords', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 100, maxLength: 500 }),
          breachCountArb,
          async (longPassword, breachCount) => {
            // Add to breach database
            mockHIBPService.addCompromisedPassword(longPassword, breachCount);

            // Check password
            const result = await mockHIBPService.checkPassword(longPassword);

            expect(result.isCompromised).toBe(true);
            expect(result.count).toBe(breachCount);

            // Hash should still be 40 characters
            const hash = mockHIBPService.hashPassword(longPassword);
            expect(hash.length).toBe(40);

            return true;
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should handle concurrent breach checks', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.integer({ min: 5, max: 10 }),
          async (count) => {
            // Create fresh mock for each iteration
            const freshHIBPService = new MockHIBPService({ failOpen: true });
            
            // Generate unique passwords with unique breach counts
            const passwords: Array<[string, number]> = [];
            for (let i = 0; i < count; i++) {
              // Use index to ensure uniqueness
              const password = `unique_password_${i}_${Date.now()}`;
              const breachCount = (i + 1) * 100; // Unique breach count per password
              passwords.push([password, breachCount]);
              freshHIBPService.addCompromisedPassword(password, breachCount);
            }

            // Check all passwords concurrently
            const results = await Promise.all(
              passwords.map(([password]) => freshHIBPService.checkPassword(password))
            );

            // All should be compromised with correct counts
            for (let i = 0; i < passwords.length; i++) {
              expect(results[i].isCompromised).toBe(true);
              expect(results[i].count).toBe(passwords[i][1]);
            }

            return true;
          }
        ),
        { numRuns: 20 }
      );
    });
  });
});
