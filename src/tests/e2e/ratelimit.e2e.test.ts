/**
 * Rate Limiting E2E Tests
 * Task 6.1: Rate Limiting Service
 * 
 * Tests:
 * - Sliding window algorithm enforcement
 * - Endpoint-specific limits (Login, Register, Password Reset, MFA, API)
 * - 429 response with Retry-After header
 * - DynamoDB TTL cleanup
 * - Realm isolation
 * - Block duration enforcement
 */

import {
  RateLimitEndpoint,
  RATE_LIMIT_CONFIGS,
  checkRateLimit,
  checkEndpointRateLimit,
  resetRateLimit,
  getRateLimitStatus,
  createRateLimitHeaders,
  isWhitelistedIP,
  batchCheckRateLimits
} from '../../services/ratelimit.service';

// Mock DynamoDB for E2E tests
const mockStore = new Map<string, any>();

jest.mock('../../services/dynamodb.service', () => ({
  dynamoDb: {
    send: jest.fn().mockImplementation((command: any) => {
      const commandName = command.constructor.name;
      
      if (commandName === 'GetCommand') {
        const key = `${command.input.Key.pk}#${command.input.Key.sk}`;
        return Promise.resolve({ Item: mockStore.get(key) });
      }
      
      if (commandName === 'PutCommand') {
        const key = `${command.input.Item.pk}#${command.input.Item.sk}`;
        mockStore.set(key, command.input.Item);
        return Promise.resolve({});
      }
      
      if (commandName === 'UpdateCommand') {
        const key = `${command.input.Key.pk}#${command.input.Key.sk}`;
        const existing = mockStore.get(key) || {};
        
        // Parse update expression and apply changes
        const updateExpr = command.input.UpdateExpression;
        const attrValues = command.input.ExpressionAttributeValues || {};
        
        if (updateExpr.includes('requests = :requests')) {
          existing.requests = attrValues[':requests'];
        }
        if (updateExpr.includes('#count = :count')) {
          existing.count = attrValues[':count'];
        }
        if (updateExpr.includes('blocked_until = :blocked')) {
          existing.blocked_until = attrValues[':blocked'];
        }
        if (updateExpr.includes('#ttl = :ttl')) {
          existing.ttl = attrValues[':ttl'];
        }
        if (updateExpr.includes('requests = :empty')) {
          existing.requests = [];
        }
        if (updateExpr.includes('#count = :zero')) {
          existing.count = 0;
        }
        if (updateExpr.includes('blocked_until = :null')) {
          existing.blocked_until = null;
        }
        
        mockStore.set(key, existing);
        return Promise.resolve({ Attributes: existing });
      }
      
      return Promise.resolve({});
    })
  },
  TableNames: {
    SESSIONS: 'test-sessions'
  }
}));

describe('Rate Limiting E2E Tests', () => {
  beforeEach(() => {
    mockStore.clear();
    jest.clearAllMocks();
  });

  describe('Sliding Window Algorithm', () => {
    it('should allow requests within the limit', async () => {
      const realmId = 'test-realm';
      const ip = '192.168.1.1';
      
      // Make 4 requests (limit is 5 for login)
      for (let i = 0; i < 4; i++) {
        const result = await checkEndpointRateLimit(realmId, RateLimitEndpoint.LOGIN, ip);
        expect(result.allowed).toBe(true);
        expect(result.remaining).toBe(4 - i);
      }
    });

    it('should block requests after limit exceeded', async () => {
      const realmId = 'test-realm';
      const ip = '192.168.1.2';
      
      // Make 5 requests (at the limit)
      for (let i = 0; i < 5; i++) {
        const result = await checkEndpointRateLimit(realmId, RateLimitEndpoint.LOGIN, ip);
        expect(result.allowed).toBe(true);
      }
      
      // 6th request should be blocked
      const blockedResult = await checkEndpointRateLimit(realmId, RateLimitEndpoint.LOGIN, ip);
      expect(blockedResult.allowed).toBe(false);
      expect(blockedResult.remaining).toBe(0);
      expect(blockedResult.blocked).toBe(true);
      expect(blockedResult.retryAfter).toBeGreaterThan(0);
    });

    it('should track requests in sliding window', async () => {
      const realmId = 'test-realm';
      const ip = '192.168.1.3';
      
      // Make 3 requests
      for (let i = 0; i < 3; i++) {
        await checkEndpointRateLimit(realmId, RateLimitEndpoint.LOGIN, ip);
      }
      
      // Check status without incrementing
      const status = await getRateLimitStatus(realmId, RateLimitEndpoint.LOGIN, ip);
      expect(status.remaining).toBe(2); // 5 - 3
    });
  });

  describe('Endpoint-Specific Limits', () => {
    it('should enforce login rate limit (5/15min)', async () => {
      const config = RATE_LIMIT_CONFIGS[RateLimitEndpoint.LOGIN];
      expect(config.maxRequests).toBe(5);
      expect(config.windowSeconds).toBe(900);
      
      const realmId = 'test-realm';
      const ip = '192.168.1.10';
      
      // Make 5 requests
      for (let i = 0; i < 5; i++) {
        const result = await checkEndpointRateLimit(realmId, RateLimitEndpoint.LOGIN, ip);
        expect(result.allowed).toBe(true);
      }
      
      // 6th should be blocked
      const blocked = await checkEndpointRateLimit(realmId, RateLimitEndpoint.LOGIN, ip);
      expect(blocked.allowed).toBe(false);
    });

    it('should enforce register rate limit (3/hour)', async () => {
      const config = RATE_LIMIT_CONFIGS[RateLimitEndpoint.REGISTER];
      expect(config.maxRequests).toBe(3);
      expect(config.windowSeconds).toBe(3600);
      
      const realmId = 'test-realm';
      const ip = '192.168.1.11';
      
      // Make 3 requests
      for (let i = 0; i < 3; i++) {
        const result = await checkEndpointRateLimit(realmId, RateLimitEndpoint.REGISTER, ip);
        expect(result.allowed).toBe(true);
      }
      
      // 4th should be blocked
      const blocked = await checkEndpointRateLimit(realmId, RateLimitEndpoint.REGISTER, ip);
      expect(blocked.allowed).toBe(false);
    });

    it('should enforce password reset rate limit (3/hour)', async () => {
      const config = RATE_LIMIT_CONFIGS[RateLimitEndpoint.PASSWORD_RESET];
      expect(config.maxRequests).toBe(3);
      expect(config.windowSeconds).toBe(3600);
      
      const realmId = 'test-realm';
      const email = 'test@example.com';
      
      // Make 3 requests
      for (let i = 0; i < 3; i++) {
        const result = await checkEndpointRateLimit(realmId, RateLimitEndpoint.PASSWORD_RESET, email);
        expect(result.allowed).toBe(true);
      }
      
      // 4th should be blocked
      const blocked = await checkEndpointRateLimit(realmId, RateLimitEndpoint.PASSWORD_RESET, email);
      expect(blocked.allowed).toBe(false);
    });

    it('should enforce MFA verify rate limit (5/min)', async () => {
      const config = RATE_LIMIT_CONFIGS[RateLimitEndpoint.MFA_VERIFY];
      expect(config.maxRequests).toBe(5);
      expect(config.windowSeconds).toBe(60);
      
      const realmId = 'test-realm';
      const userId = 'user-123';
      
      // Make 5 requests
      for (let i = 0; i < 5; i++) {
        const result = await checkEndpointRateLimit(realmId, RateLimitEndpoint.MFA_VERIFY, userId);
        expect(result.allowed).toBe(true);
      }
      
      // 6th should be blocked
      const blocked = await checkEndpointRateLimit(realmId, RateLimitEndpoint.MFA_VERIFY, userId);
      expect(blocked.allowed).toBe(false);
    });

    it('should enforce API general rate limit (100/min)', async () => {
      const config = RATE_LIMIT_CONFIGS[RateLimitEndpoint.API_GENERAL];
      expect(config.maxRequests).toBe(100);
      expect(config.windowSeconds).toBe(60);
    });
  });

  describe('429 Response with Retry-After', () => {
    it('should return retryAfter when rate limited', async () => {
      const realmId = 'test-realm';
      const ip = '192.168.1.20';
      
      // Exhaust the limit
      for (let i = 0; i < 5; i++) {
        await checkEndpointRateLimit(realmId, RateLimitEndpoint.LOGIN, ip);
      }
      
      // Get blocked result
      const blocked = await checkEndpointRateLimit(realmId, RateLimitEndpoint.LOGIN, ip);
      
      expect(blocked.allowed).toBe(false);
      expect(blocked.retryAfter).toBeDefined();
      expect(blocked.retryAfter).toBeGreaterThan(0);
    });

    it('should create proper rate limit headers', () => {
      const result = {
        allowed: false,
        remaining: 0,
        resetAt: Math.floor(Date.now() / 1000) + 900,
        retryAfter: 900,
        blocked: true
      };
      
      const headers = createRateLimitHeaders(result);
      
      expect(headers['X-RateLimit-Remaining']).toBe('0');
      expect(headers['X-RateLimit-Reset']).toBeDefined();
      expect(headers['Retry-After']).toBe('900');
      expect(headers['X-RateLimit-Blocked']).toBe('true');
    });

    it('should include remaining count in headers for allowed requests', async () => {
      const realmId = 'test-realm';
      const ip = '192.168.1.21';
      
      const result = await checkEndpointRateLimit(realmId, RateLimitEndpoint.LOGIN, ip);
      const headers = createRateLimitHeaders(result);
      
      expect(headers['X-RateLimit-Remaining']).toBe('4');
      expect(headers['Retry-After']).toBeUndefined();
    });
  });

  describe('Block Duration Enforcement', () => {
    it('should apply block duration after limit exceeded', async () => {
      const realmId = 'test-realm';
      const ip = '192.168.1.30';
      
      // Exhaust the limit
      for (let i = 0; i < 5; i++) {
        await checkEndpointRateLimit(realmId, RateLimitEndpoint.LOGIN, ip);
      }
      
      // Get blocked result
      const blocked = await checkEndpointRateLimit(realmId, RateLimitEndpoint.LOGIN, ip);
      
      expect(blocked.blocked).toBe(true);
      expect(blocked.blockExpiresAt).toBeDefined();
      expect(blocked.blockExpiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
    });

    it('should return blocked status on subsequent requests', async () => {
      const realmId = 'test-realm';
      const ip = '192.168.1.31';
      
      // Exhaust the limit and get blocked
      for (let i = 0; i < 6; i++) {
        await checkEndpointRateLimit(realmId, RateLimitEndpoint.LOGIN, ip);
      }
      
      // Subsequent request should still be blocked
      const stillBlocked = await checkEndpointRateLimit(realmId, RateLimitEndpoint.LOGIN, ip);
      expect(stillBlocked.allowed).toBe(false);
      expect(stillBlocked.blocked).toBe(true);
    });
  });

  describe('Realm Isolation', () => {
    it('should isolate rate limits between realms', async () => {
      const realm1 = 'realm-1';
      const realm2 = 'realm-2';
      const ip = '192.168.1.40';
      
      // Exhaust limit in realm1
      for (let i = 0; i < 5; i++) {
        await checkEndpointRateLimit(realm1, RateLimitEndpoint.LOGIN, ip);
      }
      
      // Should be blocked in realm1
      const blockedRealm1 = await checkEndpointRateLimit(realm1, RateLimitEndpoint.LOGIN, ip);
      expect(blockedRealm1.allowed).toBe(false);
      
      // Should still be allowed in realm2
      const allowedRealm2 = await checkEndpointRateLimit(realm2, RateLimitEndpoint.LOGIN, ip);
      expect(allowedRealm2.allowed).toBe(true);
    });

    it('should isolate rate limits between IPs in same realm', async () => {
      const realmId = 'test-realm';
      const ip1 = '192.168.1.41';
      const ip2 = '192.168.1.42';
      
      // Exhaust limit for ip1
      for (let i = 0; i < 5; i++) {
        await checkEndpointRateLimit(realmId, RateLimitEndpoint.LOGIN, ip1);
      }
      
      // ip1 should be blocked
      const blockedIp1 = await checkEndpointRateLimit(realmId, RateLimitEndpoint.LOGIN, ip1);
      expect(blockedIp1.allowed).toBe(false);
      
      // ip2 should still be allowed
      const allowedIp2 = await checkEndpointRateLimit(realmId, RateLimitEndpoint.LOGIN, ip2);
      expect(allowedIp2.allowed).toBe(true);
    });
  });

  describe('Reset Rate Limit', () => {
    it('should reset rate limit for identifier', async () => {
      const realmId = 'test-realm';
      const ip = '192.168.1.50';
      
      // Make some requests
      for (let i = 0; i < 3; i++) {
        await checkEndpointRateLimit(realmId, RateLimitEndpoint.LOGIN, ip);
      }
      
      // Verify count
      let status = await getRateLimitStatus(realmId, RateLimitEndpoint.LOGIN, ip);
      expect(status.remaining).toBe(2);
      
      // Reset
      await resetRateLimit(realmId, RateLimitEndpoint.LOGIN, ip);
      
      // Verify reset
      status = await getRateLimitStatus(realmId, RateLimitEndpoint.LOGIN, ip);
      expect(status.remaining).toBe(5);
    });

    it('should clear block status on reset', async () => {
      const realmId = 'test-realm';
      const ip = '192.168.1.51';
      
      // Exhaust limit and get blocked
      for (let i = 0; i < 6; i++) {
        await checkEndpointRateLimit(realmId, RateLimitEndpoint.LOGIN, ip);
      }
      
      // Verify blocked
      let status = await getRateLimitStatus(realmId, RateLimitEndpoint.LOGIN, ip);
      expect(status.blocked).toBe(true);
      
      // Reset
      await resetRateLimit(realmId, RateLimitEndpoint.LOGIN, ip);
      
      // Should be allowed again
      const result = await checkEndpointRateLimit(realmId, RateLimitEndpoint.LOGIN, ip);
      expect(result.allowed).toBe(true);
    });
  });

  describe('IP Whitelist', () => {
    it('should allow exact IP match', () => {
      const whitelist = ['192.168.1.1', '10.0.0.1'];
      expect(isWhitelistedIP('192.168.1.1', whitelist)).toBe(true);
      expect(isWhitelistedIP('192.168.1.2', whitelist)).toBe(false);
    });

    it('should support wildcard patterns', () => {
      const whitelist = ['192.168.1.*', '10.0.*'];
      expect(isWhitelistedIP('192.168.1.100', whitelist)).toBe(true);
      expect(isWhitelistedIP('192.168.1.255', whitelist)).toBe(true);
      expect(isWhitelistedIP('192.168.2.1', whitelist)).toBe(false);
      expect(isWhitelistedIP('10.0.5.1', whitelist)).toBe(true);
    });

    it('should return false for empty whitelist', () => {
      expect(isWhitelistedIP('192.168.1.1', [])).toBe(false);
    });
  });

  describe('Batch Rate Limit Check', () => {
    it('should check multiple identifiers', async () => {
      const realmId = 'test-realm';
      const identifiers = ['192.168.1.60', '192.168.1.61', '192.168.1.62'];
      
      const results = await batchCheckRateLimits(realmId, RateLimitEndpoint.LOGIN, identifiers);
      
      expect(results.size).toBe(3);
      identifiers.forEach(id => {
        expect(results.has(id)).toBe(true);
        expect(results.get(id)?.allowed).toBe(true);
      });
    });

    it('should handle mixed allowed/blocked results', async () => {
      const realmId = 'test-realm';
      const blockedIp = '192.168.1.70';
      const allowedIp = '192.168.1.71';
      
      // Block one IP
      for (let i = 0; i < 6; i++) {
        await checkEndpointRateLimit(realmId, RateLimitEndpoint.LOGIN, blockedIp);
      }
      
      const results = await batchCheckRateLimits(
        realmId,
        RateLimitEndpoint.LOGIN,
        [blockedIp, allowedIp]
      );
      
      expect(results.get(blockedIp)?.allowed).toBe(false);
      expect(results.get(allowedIp)?.allowed).toBe(true);
    });
  });

  describe('Legacy checkRateLimit compatibility', () => {
    it('should parse endpoint from identifier string', async () => {
      const realmId = 'test-realm';
      
      // Using legacy format: "endpoint:identifier"
      const result = await checkRateLimit(realmId, 'login:192.168.1.80');
      
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(4); // Login limit is 5
    });

    it('should default to API_GENERAL for unknown endpoint', async () => {
      const realmId = 'test-realm';
      
      // Using identifier without endpoint prefix
      const result = await checkRateLimit(realmId, '192.168.1.81');
      
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(99); // API_GENERAL limit is 100
    });
  });

  describe('DynamoDB TTL', () => {
    it('should set TTL on rate limit records', async () => {
      const realmId = 'test-realm';
      const ip = '192.168.1.90';
      
      await checkEndpointRateLimit(realmId, RateLimitEndpoint.LOGIN, ip);
      
      // Check that TTL was set in the mock store
      const key = `RATELIMIT#${realmId}#login#${ip}`;
      const record = mockStore.get(key);
      
      expect(record).toBeDefined();
      expect(record.ttl).toBeDefined();
      expect(record.ttl).toBeGreaterThan(Math.floor(Date.now() / 1000));
    });
  });

  describe('Security Scenarios', () => {
    it('should protect against brute force login attacks', async () => {
      const realmId = 'clinisyn-psychologists';
      const attackerIp = '203.0.113.1';
      
      // Simulate brute force attack
      const results = [];
      for (let i = 0; i < 10; i++) {
        const result = await checkEndpointRateLimit(realmId, RateLimitEndpoint.LOGIN, attackerIp);
        results.push(result);
      }
      
      // First 5 should be allowed
      expect(results.slice(0, 5).every(r => r.allowed)).toBe(true);
      
      // Rest should be blocked
      expect(results.slice(5).every(r => !r.allowed)).toBe(true);
    });

    it('should protect against registration spam', async () => {
      const realmId = 'clinisyn-students';
      const spammerIp = '203.0.113.2';
      
      // Simulate registration spam
      const results = [];
      for (let i = 0; i < 5; i++) {
        const result = await checkEndpointRateLimit(realmId, RateLimitEndpoint.REGISTER, spammerIp);
        results.push(result);
      }
      
      // First 3 should be allowed
      expect(results.slice(0, 3).every(r => r.allowed)).toBe(true);
      
      // Rest should be blocked
      expect(results.slice(3).every(r => !r.allowed)).toBe(true);
    });

    it('should protect against password reset abuse', async () => {
      const realmId = 'test-realm';
      const targetEmail = 'victim@example.com';
      
      // Simulate password reset abuse
      const results = [];
      for (let i = 0; i < 5; i++) {
        const result = await checkEndpointRateLimit(realmId, RateLimitEndpoint.PASSWORD_RESET, targetEmail);
        results.push(result);
      }
      
      // First 3 should be allowed
      expect(results.slice(0, 3).every(r => r.allowed)).toBe(true);
      
      // Rest should be blocked
      expect(results.slice(3).every(r => !r.allowed)).toBe(true);
    });

    it('should protect against MFA brute force', async () => {
      const realmId = 'test-realm';
      const userId = 'user-under-attack';
      
      // Simulate MFA brute force
      const results = [];
      for (let i = 0; i < 8; i++) {
        const result = await checkEndpointRateLimit(realmId, RateLimitEndpoint.MFA_VERIFY, userId);
        results.push(result);
      }
      
      // First 5 should be allowed
      expect(results.slice(0, 5).every(r => r.allowed)).toBe(true);
      
      // Rest should be blocked
      expect(results.slice(5).every(r => !r.allowed)).toBe(true);
    });
  });
});
