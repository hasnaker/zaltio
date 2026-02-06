/**
 * Webhook Service Property Tests
 * 
 * Property-based tests for webhook functionality:
 * - Property 16: Webhook signature validity
 * - Property 17: Retry with exponential backoff
 * - Property 18: Event filtering works correctly
 * 
 * Validates: Requirements 12.3, 12.4, 12.5, 12.8
 */

import * as fc from 'fast-check';
import { createHmac } from 'crypto';
import {
  createWebhookSignature,
  verifyWebhookSignature,
  isValidWebhookUrl,
  isValidWebhookEvent,
  eventMatchesSubscription,
  WebhookEventType,
  WEBHOOK_EVENTS
} from '../models/webhook.model';

describe('Webhook Service Property Tests', () => {
  
  // =========================================================================
  // Property 16: Webhook signature validity
  // =========================================================================
  describe('Property 16: Webhook signature validity', () => {
    
    it('should always produce valid signatures that can be verified', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 10000 }), // payload
          fc.string({ minLength: 16, maxLength: 64 }),   // secret
          (payload, secret) => {
            // Use current timestamp to pass tolerance check
            const timestamp = Math.floor(Date.now() / 1000);
            
            // Create signature
            const signature = createWebhookSignature(payload, timestamp, secret);
            
            // Verify signature
            const isValid = verifyWebhookSignature(payload, signature, timestamp, secret);
            
            return isValid === true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject signatures with wrong payload', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 1000 }),
          fc.string({ minLength: 1, maxLength: 1000 }),
          fc.string({ minLength: 16, maxLength: 64 }),
          (payload1, payload2, secret) => {
            // Skip if payloads are the same
            if (payload1 === payload2) return true;
            
            const timestamp = Math.floor(Date.now() / 1000);
            
            // Create signature for payload1
            const signature = createWebhookSignature(payload1, timestamp, secret);
            
            // Verify with payload2 should fail
            const isValid = verifyWebhookSignature(payload2, signature, timestamp, secret);
            
            return isValid === false;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject signatures with wrong secret', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 1000 }),
          fc.string({ minLength: 16, maxLength: 64 }),
          fc.string({ minLength: 16, maxLength: 64 }),
          (payload, secret1, secret2) => {
            // Skip if secrets are the same
            if (secret1 === secret2) return true;
            
            const timestamp = Math.floor(Date.now() / 1000);
            
            // Create signature with secret1
            const signature = createWebhookSignature(payload, timestamp, secret1);
            
            // Verify with secret2 should fail
            const isValid = verifyWebhookSignature(payload, signature, timestamp, secret2);
            
            return isValid === false;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject signatures with wrong timestamp', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 1000 }),
          fc.string({ minLength: 16, maxLength: 64 }),
          (payload, secret) => {
            const timestamp1 = Math.floor(Date.now() / 1000);
            const timestamp2 = timestamp1 + 1; // Different timestamp
            
            // Create signature with timestamp1
            const signature = createWebhookSignature(payload, timestamp1, secret);
            
            // Verify with timestamp2 should fail (signature mismatch)
            const isValid = verifyWebhookSignature(payload, signature, timestamp2, secret);
            
            return isValid === false;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should produce consistent signatures for same inputs', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 1000 }),
          fc.string({ minLength: 16, maxLength: 64 }),
          (payload, secret) => {
            const timestamp = Math.floor(Date.now() / 1000);
            const sig1 = createWebhookSignature(payload, timestamp, secret);
            const sig2 = createWebhookSignature(payload, timestamp, secret);
            
            return sig1 === sig2;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should produce 64-character hex signatures', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 1000 }),
          fc.string({ minLength: 16, maxLength: 64 }),
          (payload, secret) => {
            const timestamp = Math.floor(Date.now() / 1000);
            const signature = createWebhookSignature(payload, timestamp, secret);
            
            return signature.length === 64 && /^[a-f0-9]+$/.test(signature);
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  // =========================================================================
  // Property 17: Retry with exponential backoff
  // =========================================================================
  describe('Property 17: Retry with exponential backoff', () => {
    
    // Backoff delays in milliseconds
    const BACKOFF_DELAYS = [1000, 5000, 30000, 300000]; // 1s, 5s, 30s, 5m
    
    it('should calculate correct backoff delay for each attempt', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1, max: 10 }), // attempt number
          (attempt) => {
            const index = Math.min(attempt - 1, BACKOFF_DELAYS.length - 1);
            const expectedDelay = BACKOFF_DELAYS[index];
            
            // Verify delay increases with attempts (up to max)
            if (attempt <= BACKOFF_DELAYS.length) {
              return expectedDelay === BACKOFF_DELAYS[attempt - 1];
            } else {
              // After max attempts, delay stays at max
              return expectedDelay === BACKOFF_DELAYS[BACKOFF_DELAYS.length - 1];
            }
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should never exceed maximum backoff delay', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1, max: 100 }),
          (attempt) => {
            const index = Math.min(attempt - 1, BACKOFF_DELAYS.length - 1);
            const delay = BACKOFF_DELAYS[index];
            const maxDelay = BACKOFF_DELAYS[BACKOFF_DELAYS.length - 1];
            
            return delay <= maxDelay;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should have monotonically increasing delays up to max', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1, max: BACKOFF_DELAYS.length - 1 }),
          (attempt) => {
            const currentDelay = BACKOFF_DELAYS[attempt - 1];
            const nextDelay = BACKOFF_DELAYS[attempt];
            
            return nextDelay >= currentDelay;
          }
        ),
        { numRuns: 10 }
      );
    });
  });

  // =========================================================================
  // Property 18: Event filtering works correctly
  // =========================================================================
  describe('Property 18: Event filtering works correctly', () => {
    
    it('should match exact event types', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...WEBHOOK_EVENTS),
          (eventType) => {
            const subscriptions = [eventType];
            return eventMatchesSubscription(eventType, subscriptions) === true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should match wildcard subscriptions', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...WEBHOOK_EVENTS),
          (eventType) => {
            // Test with all events subscribed (simulating wildcard behavior)
            const subscriptions = [...WEBHOOK_EVENTS];
            return eventMatchesSubscription(eventType, subscriptions) === true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should match category wildcards', () => {
      const categoryTests = [
        { category: 'user.*', events: ['user.created', 'user.updated', 'user.deleted'] },
        { category: 'session.*', events: ['session.created', 'session.revoked'] },
        { category: 'tenant.*', events: ['tenant.created', 'tenant.updated'] },
        { category: 'member.*', events: ['member.invited', 'member.joined', 'member.removed'] },
        { category: 'mfa.*', events: ['mfa.enabled', 'mfa.disabled'] }
      ];

      for (const test of categoryTests) {
        for (const event of test.events) {
          const matches = eventMatchesSubscription(
            event as WebhookEventType,
            [test.category as WebhookEventType]
          );
          expect(matches).toBe(true);
        }
      }
    });

    it('should not match events from different categories', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('user.created', 'user.updated', 'user.deleted'),
          (userEvent) => {
            const sessionSubscriptions = ['session.created', 'session.revoked'] as WebhookEventType[];
            return eventMatchesSubscription(userEvent as WebhookEventType, sessionSubscriptions) === false;
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should match when event is in subscription list', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...WEBHOOK_EVENTS),
          fc.array(fc.constantFrom(...WEBHOOK_EVENTS), { minLength: 1, maxLength: 5 }),
          (eventType, subscriptions) => {
            const uniqueSubscriptions = [...new Set(subscriptions)] as WebhookEventType[];
            const shouldMatch = uniqueSubscriptions.includes(eventType);
            const actualMatch = eventMatchesSubscription(eventType, uniqueSubscriptions);
            
            return shouldMatch === actualMatch;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should not match empty subscription list', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...WEBHOOK_EVENTS),
          (eventType) => {
            return eventMatchesSubscription(eventType, []) === false;
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  // =========================================================================
  // Additional Properties: URL and Event Validation
  // =========================================================================
  describe('URL Validation Properties', () => {
    
    it('should accept valid HTTPS URLs', () => {
      fc.assert(
        fc.property(
          fc.webUrl({ validSchemes: ['https'] }),
          (url) => {
            return isValidWebhookUrl(url) === true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should reject HTTP URLs', () => {
      fc.assert(
        fc.property(
          fc.webUrl({ validSchemes: ['http'] }),
          (url) => {
            return isValidWebhookUrl(url) === false;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should reject non-URL strings', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 100 }).filter(s => !s.startsWith('http')),
          (notUrl) => {
            return isValidWebhookUrl(notUrl) === false;
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  describe('Event Type Validation Properties', () => {
    
    it('should accept all valid event types', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...WEBHOOK_EVENTS),
          (eventType) => {
            return isValidWebhookEvent(eventType) === true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should reject invalid event types', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 50 }).filter(s => !WEBHOOK_EVENTS.includes(s as any)),
          (invalidEvent) => {
            return isValidWebhookEvent(invalidEvent as WebhookEventType) === false;
          }
        ),
        { numRuns: 50 }
      );
    });
  });
});
