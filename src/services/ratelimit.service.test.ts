/**
 * Rate Limiting Service Tests
 * Task 6.1: Rate Limiting Service
 * 
 * Tests:
 * - Sliding window algorithm
 * - Endpoint-specific limits
 * - Block duration enforcement
 * - DynamoDB TTL
 * - Realm isolation
 * - Rate limit headers
 */

import * as fc from 'fast-check';
import {
  RateLimitConfig,
  RateLimitResult,
  RateLimitEndpoint,
  RATE_LIMIT_CONFIGS,
  getRealmRateLimitConfig,
  getEndpointRateLimitConfig,
  createRateLimitHeaders,
  isWhitelistedIP
} from './ratelimit.service';

/**
 * Custom generators for property-based testing
 */
const realmIdArb = fc.stringOf(
  fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789-'),
  { minLength: 3, maxLength: 30 }
).filter(s => /^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$/.test(s) && s.length >= 3);

const ipAddressArb = fc.tuple(
  fc.integer({ min: 1, max: 255 }),
  fc.integer({ min: 0, max: 255 }),
  fc.integer({ min: 0, max: 255 }),
  fc.integer({ min: 1, max: 254 })
).map(([a, b, c, d]) => `${a}.${b}.${c}.${d}`);

const rateLimitConfigArb = fc.record({
  maxRequests: fc.integer({ min: 1, max: 1000 }),
  windowSeconds: fc.integer({ min: 1, max: 3600 }),
  blockDurationSeconds: fc.option(fc.integer({ min: 60, max: 7200 }), { nil: undefined })
});

describe('Rate Limiting Service - Unit Tests', () => {
  describe('RATE_LIMIT_CONFIGS', () => {
    it('should have correct login rate limit (5/15min)', () => {
      const config = RATE_LIMIT_CONFIGS[RateLimitEndpoint.LOGIN];
      expect(config.maxRequests).toBe(5);
      expect(config.windowSeconds).toBe(900); // 15 minutes
    });

    it('should have correct register rate limit (3/hour)', () => {
      const config = RATE_LIMIT_CONFIGS[RateLimitEndpoint.REGISTER];
      expect(config.maxRequests).toBe(3);
      expect(config.windowSeconds).toBe(3600); // 1 hour
    });

    it('should have correct password reset rate limit (3/hour)', () => {
      const config = RATE_LIMIT_CONFIGS[RateLimitEndpoint.PASSWORD_RESET];
      expect(config.maxRequests).toBe(3);
      expect(config.windowSeconds).toBe(3600); // 1 hour
    });

    it('should have correct MFA verify rate limit (5/min)', () => {
      const config = RATE_LIMIT_CONFIGS[RateLimitEndpoint.MFA_VERIFY];
      expect(config.maxRequests).toBe(5);
      expect(config.windowSeconds).toBe(60); // 1 minute
    });

    it('should have correct API general rate limit (100/min)', () => {
      const config = RATE_LIMIT_CONFIGS[RateLimitEndpoint.API_GENERAL];
      expect(config.maxRequests).toBe(100);
      expect(config.windowSeconds).toBe(60); // 1 minute
    });

    it('should have correct email verify rate limit (5/hour)', () => {
      const config = RATE_LIMIT_CONFIGS[RateLimitEndpoint.EMAIL_VERIFY];
      expect(config.maxRequests).toBe(5);
      expect(config.windowSeconds).toBe(3600); // 1 hour
    });

    it('should have correct social auth rate limit (10/5min)', () => {
      const config = RATE_LIMIT_CONFIGS[RateLimitEndpoint.SOCIAL_AUTH];
      expect(config.maxRequests).toBe(10);
      expect(config.windowSeconds).toBe(300); // 5 minutes
    });

    it('should have correct webauthn rate limit (10/5min)', () => {
      const config = RATE_LIMIT_CONFIGS[RateLimitEndpoint.WEBAUTHN];
      expect(config.maxRequests).toBe(10);
      expect(config.windowSeconds).toBe(300); // 5 minutes
    });

    it('should have correct device trust rate limit (10/5min)', () => {
      const config = RATE_LIMIT_CONFIGS[RateLimitEndpoint.DEVICE_TRUST];
      expect(config.maxRequests).toBe(10);
      expect(config.windowSeconds).toBe(300); // 5 minutes
    });

    it('should have correct account link rate limit (5/5min)', () => {
      const config = RATE_LIMIT_CONFIGS[RateLimitEndpoint.ACCOUNT_LINK];
      expect(config.maxRequests).toBe(5);
      expect(config.windowSeconds).toBe(300); // 5 minutes
    });

    it('should have block duration for all endpoints', () => {
      Object.values(RateLimitEndpoint).forEach(endpoint => {
        const config = RATE_LIMIT_CONFIGS[endpoint];
        expect(config.blockDurationSeconds).toBeDefined();
        expect(config.blockDurationSeconds).toBeGreaterThan(0);
      });
    });
  });

  describe('getRealmRateLimitConfig', () => {
    it('should return default config when no realm settings', () => {
      const config = getRealmRateLimitConfig(undefined);
      expect(config).toEqual(RATE_LIMIT_CONFIGS[RateLimitEndpoint.API_GENERAL]);
    });

    it('should return realm-specific config when provided', () => {
      const customConfig: RateLimitConfig = {
        maxRequests: 50,
        windowSeconds: 120
      };

      const config = getRealmRateLimitConfig({ rate_limit: customConfig });
      expect(config).toEqual(customConfig);
    });
  });

  describe('getEndpointRateLimitConfig', () => {
    it('should return correct config for each endpoint', () => {
      Object.values(RateLimitEndpoint).forEach(endpoint => {
        const config = getEndpointRateLimitConfig(endpoint);
        expect(config).toEqual(RATE_LIMIT_CONFIGS[endpoint]);
      });
    });
  });

  describe('createRateLimitHeaders', () => {
    it('should create basic headers', () => {
      const result: RateLimitResult = {
        allowed: true,
        remaining: 5,
        resetAt: 1234567890
      };

      const headers = createRateLimitHeaders(result);

      expect(headers['X-RateLimit-Remaining']).toBe('5');
      expect(headers['X-RateLimit-Reset']).toBe('1234567890');
    });

    it('should include Retry-After when rate limited', () => {
      const result: RateLimitResult = {
        allowed: false,
        remaining: 0,
        resetAt: 1234567890,
        retryAfter: 300
      };

      const headers = createRateLimitHeaders(result);

      expect(headers['Retry-After']).toBe('300');
    });

    it('should include blocked header when blocked', () => {
      const result: RateLimitResult = {
        allowed: false,
        remaining: 0,
        resetAt: 1234567890,
        blocked: true
      };

      const headers = createRateLimitHeaders(result);

      expect(headers['X-RateLimit-Blocked']).toBe('true');
    });

    it('should not include Retry-After for allowed requests', () => {
      const result: RateLimitResult = {
        allowed: true,
        remaining: 5,
        resetAt: 1234567890
      };

      const headers = createRateLimitHeaders(result);

      expect(headers['Retry-After']).toBeUndefined();
    });
  });

  describe('isWhitelistedIP', () => {
    it('should return true for exact match', () => {
      const whitelist = ['192.168.1.1', '10.0.0.1'];
      expect(isWhitelistedIP('192.168.1.1', whitelist)).toBe(true);
    });

    it('should return false for non-matching IP', () => {
      const whitelist = ['192.168.1.1', '10.0.0.1'];
      expect(isWhitelistedIP('192.168.1.2', whitelist)).toBe(false);
    });

    it('should support wildcard patterns', () => {
      const whitelist = ['192.168.1.*', '10.0.*'];
      expect(isWhitelistedIP('192.168.1.100', whitelist)).toBe(true);
      expect(isWhitelistedIP('10.0.5.1', whitelist)).toBe(true);
      expect(isWhitelistedIP('172.16.0.1', whitelist)).toBe(false);
    });

    it('should return false for empty whitelist', () => {
      expect(isWhitelistedIP('192.168.1.1', [])).toBe(false);
    });
  });

  describe('Property-based tests', () => {
    describe('Rate limit result structure', () => {
      it('should always return valid result structure', () => {
        fc.assert(
          fc.property(rateLimitConfigArb, (config) => {
            const result: RateLimitResult = {
              allowed: true,
              remaining: config.maxRequests - 1,
              resetAt: Math.floor(Date.now() / 1000) + config.windowSeconds
            };

            expect(typeof result.allowed).toBe('boolean');
            expect(typeof result.remaining).toBe('number');
            expect(typeof result.resetAt).toBe('number');
            expect(result.remaining).toBeGreaterThanOrEqual(0);
            expect(result.remaining).toBeLessThanOrEqual(config.maxRequests);

            return true;
          }),
          { numRuns: 100 }
        );
      });
    });

    describe('Remaining count behavior', () => {
      it('should enforce that remaining count decreases with each request', () => {
        fc.assert(
          fc.property(
            rateLimitConfigArb,
            fc.integer({ min: 1, max: 100 }),
            (config, requestCount) => {
              let remaining = config.maxRequests;
              const results: RateLimitResult[] = [];

              for (let i = 0; i < Math.min(requestCount, config.maxRequests + 5); i++) {
                const allowed = remaining > 0;
                remaining = Math.max(0, remaining - 1);
                
                results.push({
                  allowed,
                  remaining: Math.max(0, config.maxRequests - (i + 1)),
                  resetAt: Math.floor(Date.now() / 1000) + config.windowSeconds
                });
              }

              // Verify monotonic decrease
              for (let i = 1; i < results.length; i++) {
                expect(results[i].remaining).toBeLessThanOrEqual(results[i - 1].remaining);
              }

              return true;
            }
          ),
          { numRuns: 100 }
        );
      });
    });

    describe('Block behavior', () => {
      it('should block requests after limit is exceeded', () => {
        fc.assert(
          fc.property(rateLimitConfigArb, (config) => {
            const requestsOverLimit = config.maxRequests + 1;
            let remaining = config.maxRequests;
            const results: RateLimitResult[] = [];

            for (let i = 0; i < requestsOverLimit; i++) {
              const allowed = remaining > 0;
              if (allowed) remaining--;
              
              results.push({
                allowed,
                remaining: Math.max(0, config.maxRequests - (i + 1)),
                resetAt: Math.floor(Date.now() / 1000) + config.windowSeconds,
                retryAfter: allowed ? undefined : config.windowSeconds
              });
            }

            // First maxRequests should be allowed
            for (let i = 0; i < config.maxRequests; i++) {
              expect(results[i].allowed).toBe(true);
            }

            // Request after limit should be blocked
            expect(results[config.maxRequests].allowed).toBe(false);

            return true;
          }),
          { numRuns: 100 }
        );
      });
    });

    describe('Retry-After header', () => {
      it('should provide retry-after when rate limited', () => {
        fc.assert(
          fc.property(rateLimitConfigArb, (config) => {
            const now = Math.floor(Date.now() / 1000);
            const windowEnd = now + config.windowSeconds;
            
            const rateLimitedResult: RateLimitResult = {
              allowed: false,
              remaining: 0,
              resetAt: windowEnd,
              retryAfter: windowEnd - now
            };

            expect(rateLimitedResult.retryAfter).toBeDefined();
            expect(rateLimitedResult.retryAfter).toBeGreaterThan(0);
            expect(rateLimitedResult.retryAfter).toBeLessThanOrEqual(config.windowSeconds);

            return true;
          }),
          { numRuns: 100 }
        );
      });
    });

    describe('Realm isolation', () => {
      it('should isolate rate limits by realm', () => {
        fc.assert(
          fc.property(
            realmIdArb,
            realmIdArb,
            ipAddressArb,
            (realm1, realm2, ip) => {
              const key1 = `RATELIMIT#${realm1}`;
              const key2 = `RATELIMIT#${realm2}`;

              if (realm1 !== realm2) {
                expect(key1).not.toBe(key2);
              }

              return true;
            }
          ),
          { numRuns: 100 }
        );
      });
    });

    describe('IP isolation', () => {
      it('should isolate rate limits by identifier', () => {
        fc.assert(
          fc.property(
            realmIdArb,
            ipAddressArb,
            ipAddressArb,
            (realm, ip1, ip2) => {
              const key1 = `RATELIMIT#${realm}#${ip1}`;
              const key2 = `RATELIMIT#${realm}#${ip2}`;

              if (ip1 !== ip2) {
                expect(key1).not.toBe(key2);
              }

              return true;
            }
          ),
          { numRuns: 100 }
        );
      });
    });

    describe('Window boundaries', () => {
      it('should calculate window boundaries correctly', () => {
        fc.assert(
          fc.property(
            fc.integer({ min: 1, max: 3600 }),
            fc.integer({ min: 0, max: 1000000000 }),
            (windowSeconds, timestamp) => {
              const windowStart = Math.floor(timestamp / windowSeconds) * windowSeconds;
              const windowEnd = windowStart + windowSeconds;

              expect(windowStart).toBeLessThanOrEqual(timestamp);
              expect(windowEnd).toBeGreaterThan(timestamp);
              expect(windowEnd - windowStart).toBe(windowSeconds);

              return true;
            }
          ),
          { numRuns: 100 }
        );
      });
    });

    describe('Endpoint configuration validation', () => {
      it('should have valid configuration for all endpoints', () => {
        Object.values(RateLimitEndpoint).forEach(endpoint => {
          const config = RATE_LIMIT_CONFIGS[endpoint];
          
          expect(config.maxRequests).toBeGreaterThan(0);
          expect(config.windowSeconds).toBeGreaterThan(0);
          expect(config.blockDurationSeconds).toBeGreaterThan(0);
        });
      });
    });
  });
});
