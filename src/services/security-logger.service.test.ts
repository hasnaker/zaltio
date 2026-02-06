/**
 * Property-based tests for Security Event Logging
 * Feature: zalt-platform, Property 16: Security Event Logging Completeness
 * Validates: Requirements 9.4
 */

import * as fc from 'fast-check';
import { APIGatewayProxyEvent } from 'aws-lambda';
import {
  SecurityEventTypes,
  SecurityEventSeverity,
  SecurityEvent,
  SecurityEventType,
  SecuritySeverity,
  logSecurityEvent,
  logAuthAttempt,
  logRegistrationAttempt,
  logTokenRefresh,
  logLogout,
  logRateLimitExceeded,
  logAdminAction,
  logUnauthorizedAccess
} from './security-logger.service';

/**
 * Custom generators for security logging tests
 */
const securityEventTypeArb = fc.constantFrom(...Object.values(SecurityEventTypes)) as fc.Arbitrary<SecurityEventType>;

const securitySeverityArb = fc.constantFrom(...Object.values(SecurityEventSeverity)) as fc.Arbitrary<SecuritySeverity>;

const validRealmIdArb = fc.stringMatching(/^[a-zA-Z0-9][a-zA-Z0-9-]{1,28}[a-zA-Z0-9]$/);

const validUserIdArb = fc.uuid();

const validEmailArb = fc.tuple(
  fc.stringMatching(/^[a-z0-9]{3,20}$/),
  fc.constantFrom('gmail.com', 'example.com', 'hsdcore.com')
).map(([local, domain]) => `${local}@${domain}`);

const ipAddressArb = fc.tuple(
  fc.integer({ min: 1, max: 255 }),
  fc.integer({ min: 0, max: 255 }),
  fc.integer({ min: 0, max: 255 }),
  fc.integer({ min: 0, max: 255 })
).map(([a, b, c, d]) => `${a}.${b}.${c}.${d}`);

const userAgentArb = fc.constantFrom(
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
  'PostmanRuntime/7.32.3',
  'curl/7.88.1'
);

const actionArb = fc.constantFrom(
  'User authentication',
  'User registration',
  'Token refresh',
  'Logout',
  'Realm creation',
  'Realm deletion',
  'Password change'
);

const outcomeArb = fc.constantFrom('SUCCESS', 'FAILURE') as fc.Arbitrary<'SUCCESS' | 'FAILURE'>;

/**
 * Create a mock API Gateway event for testing
 */
function createMockEvent(
  sourceIp: string,
  userAgent: string,
  requestId?: string
): APIGatewayProxyEvent {
  return {
    body: null,
    headers: {
      'User-Agent': userAgent
    },
    multiValueHeaders: {},
    httpMethod: 'POST',
    isBase64Encoded: false,
    path: '/auth/login',
    pathParameters: null,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: {
      accountId: '123456789012',
      apiId: 'test-api',
      authorizer: null,
      protocol: 'HTTP/1.1',
      httpMethod: 'POST',
      identity: {
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
        sourceIp,
        user: null,
        userAgent,
        userArn: null
      },
      path: '/auth/login',
      stage: 'prod',
      requestId: requestId || 'test-request-id',
      requestTimeEpoch: Date.now(),
      resourceId: 'test-resource',
      resourcePath: '/auth/login'
    },
    resource: '/auth/login'
  };
}

describe('Security Event Logging - Property Tests', () => {
  /**
   * Property 16: Security Event Logging Completeness
   * For any authentication attempt, administrative action, or security-relevant event,
   * a complete audit log entry should be created with timestamp, user identity,
   * action details, and outcome.
   * Validates: Requirements 9.4
   */
  describe('Property 16: Security Event Logging Completeness', () => {
    // Capture console output for verification
    let consoleSpy: jest.SpyInstance;
    
    beforeEach(() => {
      consoleSpy = jest.spyOn(console, 'info').mockImplementation();
      jest.spyOn(console, 'warn').mockImplementation();
      jest.spyOn(console, 'error').mockImplementation();
    });
    
    afterEach(() => {
      jest.restoreAllMocks();
    });

    it('should create complete security event with all required fields', () => {
      fc.assert(
        fc.property(
          securityEventTypeArb,
          actionArb,
          outcomeArb,
          ipAddressArb,
          userAgentArb,
          validRealmIdArb,
          validUserIdArb,
          validEmailArb,
          (eventType, action, outcome, sourceIp, userAgent, realmId, userId, email) => {
            const event = createMockEvent(sourceIp, userAgent);
            
            const securityEvent = logSecurityEvent(
              event,
              eventType,
              action,
              outcome,
              { realmId, userId, email }
            );
            
            // Verify all required fields are present
            expect(securityEvent.event_type).toBe(eventType);
            expect(securityEvent.action).toBe(action);
            expect(securityEvent.outcome).toBe(outcome);
            expect(securityEvent.source_ip).toBe(sourceIp);
            expect(securityEvent.user_agent).toBe(userAgent);
            expect(securityEvent.realm_id).toBe(realmId);
            expect(securityEvent.user_id).toBe(userId);
            expect(securityEvent.email).toBe(email);
            
            // Verify timestamp is valid ISO format
            expect(securityEvent.timestamp).toBeDefined();
            expect(new Date(securityEvent.timestamp).toISOString()).toBe(securityEvent.timestamp);
            
            // Verify severity is set
            expect(Object.values(SecurityEventSeverity)).toContain(securityEvent.severity);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should include request ID when available', () => {
      fc.assert(
        fc.property(
          securityEventTypeArb,
          actionArb,
          outcomeArb,
          ipAddressArb,
          userAgentArb,
          fc.uuid(),
          (eventType, action, outcome, sourceIp, userAgent, requestId) => {
            const event = createMockEvent(sourceIp, userAgent, requestId);
            
            const securityEvent = logSecurityEvent(event, eventType, action, outcome);
            
            // Request ID should be captured
            expect(securityEvent.request_id).toBe(requestId);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should log authentication attempts with complete information', () => {
      fc.assert(
        fc.property(
          validRealmIdArb,
          validEmailArb,
          fc.boolean(),
          ipAddressArb,
          userAgentArb,
          (realmId, email, success, sourceIp, userAgent) => {
            const event = createMockEvent(sourceIp, userAgent);
            
            const securityEvent = logAuthAttempt(event, realmId, email, success);
            
            // Verify authentication-specific fields
            expect(securityEvent.realm_id).toBe(realmId);
            expect(securityEvent.email).toBe(email);
            expect(securityEvent.outcome).toBe(success ? 'SUCCESS' : 'FAILURE');
            expect(securityEvent.event_type).toBe(
              success ? SecurityEventTypes.LOGIN_SUCCESS : SecurityEventTypes.LOGIN_FAILURE
            );
            expect(securityEvent.action).toBe('User authentication');
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should log registration attempts with complete information', () => {
      fc.assert(
        fc.property(
          validRealmIdArb,
          validEmailArb,
          fc.boolean(),
          ipAddressArb,
          userAgentArb,
          (realmId, email, success, sourceIp, userAgent) => {
            const event = createMockEvent(sourceIp, userAgent);
            
            const securityEvent = logRegistrationAttempt(event, realmId, email, success);
            
            // Verify registration-specific fields
            expect(securityEvent.realm_id).toBe(realmId);
            expect(securityEvent.email).toBe(email);
            expect(securityEvent.outcome).toBe(success ? 'SUCCESS' : 'FAILURE');
            expect(securityEvent.event_type).toBe(
              success ? SecurityEventTypes.REGISTRATION_SUCCESS : SecurityEventTypes.REGISTRATION_FAILURE
            );
            expect(securityEvent.action).toBe('User registration');
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should log token refresh attempts with complete information', () => {
      fc.assert(
        fc.property(
          validRealmIdArb,
          validUserIdArb,
          fc.boolean(),
          ipAddressArb,
          userAgentArb,
          (realmId, userId, success, sourceIp, userAgent) => {
            const event = createMockEvent(sourceIp, userAgent);
            
            const securityEvent = logTokenRefresh(event, realmId, userId, success);
            
            // Verify token refresh-specific fields
            expect(securityEvent.realm_id).toBe(realmId);
            expect(securityEvent.user_id).toBe(userId);
            expect(securityEvent.outcome).toBe(success ? 'SUCCESS' : 'FAILURE');
            expect(securityEvent.event_type).toBe(
              success ? SecurityEventTypes.TOKEN_REFRESH : SecurityEventTypes.TOKEN_REFRESH_FAILURE
            );
            expect(securityEvent.action).toBe('Token refresh');
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should log logout events with complete information', () => {
      fc.assert(
        fc.property(
          validRealmIdArb,
          validUserIdArb,
          fc.boolean(),
          ipAddressArb,
          userAgentArb,
          (realmId, userId, logoutAll, sourceIp, userAgent) => {
            const event = createMockEvent(sourceIp, userAgent);
            
            const securityEvent = logLogout(event, realmId, userId, logoutAll);
            
            // Verify logout-specific fields
            expect(securityEvent.realm_id).toBe(realmId);
            expect(securityEvent.user_id).toBe(userId);
            expect(securityEvent.outcome).toBe('SUCCESS');
            expect(securityEvent.event_type).toBe(
              logoutAll ? SecurityEventTypes.LOGOUT_ALL : SecurityEventTypes.LOGOUT
            );
            expect(securityEvent.action).toBe(
              logoutAll ? 'Logout all sessions' : 'Logout single session'
            );
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should log rate limit exceeded events with retry information', () => {
      fc.assert(
        fc.property(
          validRealmIdArb,
          fc.integer({ min: 1, max: 3600 }),
          ipAddressArb,
          userAgentArb,
          (realmId, retryAfter, sourceIp, userAgent) => {
            const event = createMockEvent(sourceIp, userAgent);
            
            const securityEvent = logRateLimitExceeded(event, realmId, retryAfter);
            
            // Verify rate limit-specific fields
            expect(securityEvent.realm_id).toBe(realmId);
            expect(securityEvent.outcome).toBe('FAILURE');
            expect(securityEvent.event_type).toBe(SecurityEventTypes.RATE_LIMIT_EXCEEDED);
            expect(securityEvent.action).toBe('Rate limit exceeded');
            expect(securityEvent.details?.retry_after).toBe(retryAfter);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should log administrative actions with complete information', () => {
      const adminEventTypes = [
        SecurityEventTypes.REALM_CREATED,
        SecurityEventTypes.REALM_UPDATED,
        SecurityEventTypes.REALM_DELETED
      ] as const;

      fc.assert(
        fc.property(
          fc.constantFrom(...adminEventTypes),
          actionArb,
          validRealmIdArb,
          fc.boolean(),
          ipAddressArb,
          userAgentArb,
          (eventType, action, realmId, success, sourceIp, userAgent) => {
            const event = createMockEvent(sourceIp, userAgent);
            
            const securityEvent = logAdminAction(
              event,
              eventType,
              action,
              realmId,
              success
            );
            
            // Verify admin action-specific fields
            expect(securityEvent.realm_id).toBe(realmId);
            expect(securityEvent.outcome).toBe(success ? 'SUCCESS' : 'FAILURE');
            expect(securityEvent.event_type).toBe(eventType);
            expect(securityEvent.action).toBe(action);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should log unauthorized access attempts', () => {
      fc.assert(
        fc.property(
          actionArb,
          fc.string({ minLength: 1, maxLength: 50 }),
          fc.string({ minLength: 1, maxLength: 100 }),
          ipAddressArb,
          userAgentArb,
          (action, errorCode, errorMessage, sourceIp, userAgent) => {
            const event = createMockEvent(sourceIp, userAgent);
            
            const securityEvent = logUnauthorizedAccess(
              event,
              action,
              errorCode,
              errorMessage
            );
            
            // Verify unauthorized access-specific fields
            expect(securityEvent.outcome).toBe('FAILURE');
            expect(securityEvent.event_type).toBe(SecurityEventTypes.UNAUTHORIZED_ACCESS);
            expect(securityEvent.action).toBe(action);
            expect(securityEvent.error_code).toBe(errorCode);
            expect(securityEvent.error_message).toBe(errorMessage);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should assign appropriate severity levels to event types', () => {
      const severityMappings: Array<{ eventType: SecurityEventType; expectedSeverities: SecuritySeverity[] }> = [
        { eventType: SecurityEventTypes.LOGIN_SUCCESS, expectedSeverities: [SecurityEventSeverity.INFO] },
        { eventType: SecurityEventTypes.LOGIN_FAILURE, expectedSeverities: [SecurityEventSeverity.WARNING] },
        { eventType: SecurityEventTypes.RATE_LIMIT_EXCEEDED, expectedSeverities: [SecurityEventSeverity.ERROR] },
        { eventType: SecurityEventTypes.SUSPICIOUS_ACTIVITY, expectedSeverities: [SecurityEventSeverity.CRITICAL] }
      ];

      fc.assert(
        fc.property(
          fc.constantFrom(...severityMappings),
          ipAddressArb,
          userAgentArb,
          ({ eventType, expectedSeverities }, sourceIp, userAgent) => {
            const event = createMockEvent(sourceIp, userAgent);
            
            const securityEvent = logSecurityEvent(event, eventType, 'Test action', 'SUCCESS');
            
            // Verify severity is appropriate for event type
            expect(expectedSeverities).toContain(securityEvent.severity);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should handle missing source IP gracefully', () => {
      fc.assert(
        fc.property(
          securityEventTypeArb,
          actionArb,
          outcomeArb,
          userAgentArb,
          (eventType, action, outcome, userAgent) => {
            const event = createMockEvent('', userAgent);
            // Simulate missing source IP
            event.requestContext.identity.sourceIp = '';
            
            const securityEvent = logSecurityEvent(event, eventType, action, outcome);
            
            // Should handle gracefully (empty string or 'unknown')
            expect(typeof securityEvent.source_ip).toBe('string');
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should handle missing user agent gracefully', () => {
      fc.assert(
        fc.property(
          securityEventTypeArb,
          actionArb,
          outcomeArb,
          ipAddressArb,
          (eventType, action, outcome, sourceIp) => {
            const event = createMockEvent(sourceIp, '');
            // Remove user agent header
            delete event.headers['User-Agent'];
            
            const securityEvent = logSecurityEvent(event, eventType, action, outcome);
            
            // Should handle gracefully (empty string or 'unknown')
            expect(typeof securityEvent.user_agent).toBe('string');
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should include error details when provided', () => {
      fc.assert(
        fc.property(
          securityEventTypeArb,
          actionArb,
          fc.string({ minLength: 1, maxLength: 50 }),
          fc.string({ minLength: 1, maxLength: 100 }),
          ipAddressArb,
          userAgentArb,
          (eventType, action, errorCode, errorMessage, sourceIp, userAgent) => {
            const event = createMockEvent(sourceIp, userAgent);
            
            const securityEvent = logSecurityEvent(
              event,
              eventType,
              action,
              'FAILURE',
              { errorCode, errorMessage }
            );
            
            // Error details should be included
            expect(securityEvent.error_code).toBe(errorCode);
            expect(securityEvent.error_message).toBe(errorMessage);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });
  });
});
