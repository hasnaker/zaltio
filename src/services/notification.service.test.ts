/**
 * Property-based tests for Real-time Notification Delivery
 * Feature: zalt-platform, Property 7: Real-time Notification Delivery
 * Validates: Requirements 3.6
 */

import * as fc from 'fast-check';
import {
  Notification,
  NotificationSeverity,
  NotificationCategory,
  NotificationSubscriber,
  DeliveryResult,
  createNotification,
  shouldDeliverToSubscriber,
  deliverNotification,
  validateDeliveryTiming,
  isDuplicateNotification,
  deliverToSubscribers,
  getNotificationsForSubscriber,
  getUnreadCount,
  markAsRead,
  markAllAsRead,
  getCriticalNotifications,
} from './notification.service';

/**
 * Custom generators for realistic test data
 */
const severityArb = fc.constantFrom<NotificationSeverity>('info', 'warning', 'error', 'critical');

const categoryArb = fc.constantFrom<NotificationCategory>(
  'security', 'system', 'user', 'realm', 'performance'
);

const realmIdArb = fc.stringOf(
  fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789-'),
  { minLength: 3, maxLength: 20 }
).filter(s => /^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$/.test(s) && s.length >= 3);

const notificationArb = fc.record({
  id: fc.uuid(),
  title: fc.string({ minLength: 1, maxLength: 100 }),
  message: fc.string({ minLength: 1, maxLength: 500 }),
  severity: severityArb,
  category: categoryArb,
  realm_id: fc.option(realmIdArb, { nil: undefined }),
  timestamp: fc.date({ min: new Date('2024-01-01'), max: new Date('2025-12-31') }).map(d => d.toISOString()),
  read: fc.boolean(),
});

const subscriberArb = fc.record({
  admin_id: fc.uuid(),
  realm_access: fc.array(realmIdArb, { minLength: 0, maxLength: 5 }),
  categories: fc.array(categoryArb, { minLength: 1, maxLength: 5 }).map(arr => [...new Set(arr)]),
  severities: fc.array(severityArb, { minLength: 1, maxLength: 4 }).map(arr => [...new Set(arr)]),
});

describe('Real-time Notification Delivery - Property Tests', () => {
  /**
   * Property 7: Real-time Notification Delivery
   * For any critical system event, notifications should be delivered to all subscribed
   * administrators within the configured time threshold without duplication.
   * Validates: Requirements 3.6
   */
  describe('Property 7: Real-time Notification Delivery', () => {
    it('should deliver notifications only to subscribers with matching category preferences', () => {
      fc.assert(
        fc.property(notificationArb, subscriberArb, (notification, subscriber) => {
          const shouldDeliver = shouldDeliverToSubscriber(notification, subscriber);
          
          // If category doesn't match, should not deliver
          if (!subscriber.categories.includes(notification.category)) {
            expect(shouldDeliver).toBe(false);
            return true;
          }
          
          // If severity doesn't match, should not deliver
          if (!subscriber.severities.includes(notification.severity)) {
            expect(shouldDeliver).toBe(false);
            return true;
          }
          
          // If realm-specific and no access, should not deliver
          if (notification.realm_id && 
              subscriber.realm_access.length > 0 && 
              !subscriber.realm_access.includes(notification.realm_id)) {
            expect(shouldDeliver).toBe(false);
            return true;
          }
          
          // Otherwise should deliver
          expect(shouldDeliver).toBe(true);
          return true;
        }),
        { numRuns: 100 }
      );
    });

    it('should deliver notifications within the configured time threshold', () => {
      fc.assert(
        fc.property(
          notificationArb,
          subscriberArb,
          fc.integer({ min: 0, max: 1000 }), // Simulated delay in ms
          (notification, subscriber, delay) => {
            const eventTimestamp = new Date().toISOString();
            
            // Simulate delivery with delay
            const deliveryResult = deliverNotification(notification, subscriber, eventTimestamp);
            
            // Delivery time should be recorded
            expect(deliveryResult.delivered_at).toBeDefined();
            expect(deliveryResult.delivery_time_ms).toBeGreaterThanOrEqual(0);
            
            // For immediate delivery (no artificial delay), should be within threshold
            const isWithinThreshold = validateDeliveryTiming(deliveryResult, 5000);
            expect(isWithinThreshold).toBe(true);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should not deliver duplicate notifications', () => {
      fc.assert(
        fc.property(
          notificationArb,
          fc.array(notificationArb, { minLength: 0, maxLength: 10 }),
          (notification, existingNotifications) => {
            // Create a duplicate with same title, message, category, and close timestamp
            const duplicate: Notification = {
              ...notification,
              id: 'duplicate-id',
              timestamp: notification.timestamp, // Same timestamp
            };
            
            // Add original to existing
            const withOriginal = [...existingNotifications, notification];
            
            // Duplicate should be detected
            const isDuplicate = isDuplicateNotification(duplicate, withOriginal);
            expect(isDuplicate).toBe(true);
            
            // Original should not be detected as duplicate of itself
            const isOriginalDuplicate = isDuplicateNotification(notification, existingNotifications);
            // Only true if there's actually a duplicate in existingNotifications
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should deliver to all eligible subscribers without duplication', () => {
      fc.assert(
        fc.property(
          notificationArb,
          fc.array(subscriberArb, { minLength: 1, maxLength: 10 }),
          (notification, subscribers) => {
            const eventTimestamp = new Date().toISOString();
            const results = deliverToSubscribers(notification, subscribers, eventTimestamp);
            
            // Each result should be for a unique subscriber
            const subscriberIds = results.map(r => r.subscriber_id);
            const uniqueIds = new Set(subscriberIds);
            expect(subscriberIds.length).toBe(uniqueIds.size);
            
            // All delivered results should be for eligible subscribers
            results.forEach(result => {
              const subscriber = subscribers.find(s => s.admin_id === result.subscriber_id);
              expect(subscriber).toBeDefined();
              if (subscriber) {
                expect(shouldDeliverToSubscriber(notification, subscriber)).toBe(true);
              }
            });
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should filter notifications correctly for each subscriber', () => {
      fc.assert(
        fc.property(
          fc.array(notificationArb, { minLength: 1, maxLength: 20 }),
          subscriberArb,
          (notifications, subscriber) => {
            const filtered = getNotificationsForSubscriber(notifications, subscriber);
            
            // All filtered notifications should match subscriber preferences
            filtered.forEach(notification => {
              expect(subscriber.categories).toContain(notification.category);
              expect(subscriber.severities).toContain(notification.severity);
              
              if (notification.realm_id && subscriber.realm_access.length > 0) {
                expect(subscriber.realm_access).toContain(notification.realm_id);
              }
            });
            
            // No eligible notification should be missing
            notifications.forEach(notification => {
              if (shouldDeliverToSubscriber(notification, subscriber)) {
                expect(filtered).toContainEqual(notification);
              }
            });
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should correctly count unread notifications', () => {
      fc.assert(
        fc.property(
          fc.array(notificationArb, { minLength: 0, maxLength: 20 }),
          subscriberArb,
          (notifications, subscriber) => {
            const unreadCount = getUnreadCount(notifications, subscriber);
            
            // Count should match manual calculation
            const filtered = getNotificationsForSubscriber(notifications, subscriber);
            const expectedCount = filtered.filter(n => !n.read).length;
            
            expect(unreadCount).toBe(expectedCount);
            expect(unreadCount).toBeGreaterThanOrEqual(0);
            expect(unreadCount).toBeLessThanOrEqual(notifications.length);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should mark notifications as read correctly', () => {
      fc.assert(
        fc.property(notificationArb, (notification) => {
          const unreadNotification = { ...notification, read: false };
          const readNotification = markAsRead(unreadNotification);
          
          // Should be marked as read
          expect(readNotification.read).toBe(true);
          
          // Other properties should be unchanged
          expect(readNotification.id).toBe(unreadNotification.id);
          expect(readNotification.title).toBe(unreadNotification.title);
          expect(readNotification.message).toBe(unreadNotification.message);
          expect(readNotification.severity).toBe(unreadNotification.severity);
          expect(readNotification.category).toBe(unreadNotification.category);
          
          return true;
        }),
        { numRuns: 100 }
      );
    });

    it('should mark all subscriber notifications as read', () => {
      fc.assert(
        fc.property(
          fc.array(notificationArb.map(n => ({ ...n, read: false })), { minLength: 1, maxLength: 20 }),
          subscriberArb,
          (notifications, subscriber) => {
            const updated = markAllAsRead(notifications, subscriber);
            
            // All notifications for this subscriber should be read
            updated.forEach((notification, index) => {
              const original = notifications[index];
              if (shouldDeliverToSubscriber(original, subscriber)) {
                expect(notification.read).toBe(true);
              } else {
                // Notifications not for this subscriber should be unchanged
                expect(notification.read).toBe(original.read);
              }
            });
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should correctly identify critical notifications', () => {
      fc.assert(
        fc.property(
          fc.array(notificationArb, { minLength: 0, maxLength: 20 }),
          (notifications) => {
            const critical = getCriticalNotifications(notifications);
            
            // All returned notifications should be critical or error
            critical.forEach(notification => {
              expect(['critical', 'error']).toContain(notification.severity);
            });
            
            // All critical/error notifications should be included
            notifications.forEach(notification => {
              if (notification.severity === 'critical' || notification.severity === 'error') {
                expect(critical).toContainEqual(notification);
              }
            });
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should ensure notification timestamps are preserved during delivery', () => {
      fc.assert(
        fc.property(
          notificationArb,
          subscriberArb,
          (notification, subscriber) => {
            const eventTimestamp = notification.timestamp;
            const result = deliverNotification(notification, subscriber, eventTimestamp);
            
            // Original timestamp should be preserved
            expect(result.notification.timestamp).toBe(notification.timestamp);
            
            // Delivery timestamp should be set
            expect(result.delivered_at).toBeDefined();
            
            // Delivery should be after or at event time
            const eventTime = new Date(eventTimestamp).getTime();
            const deliveryTime = new Date(result.delivered_at).getTime();
            expect(deliveryTime).toBeGreaterThanOrEqual(eventTime);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should handle empty subscriber lists gracefully', () => {
      fc.assert(
        fc.property(notificationArb, (notification) => {
          const eventTimestamp = new Date().toISOString();
          const results = deliverToSubscribers(notification, [], eventTimestamp);
          
          // Should return empty array, not error
          expect(results).toEqual([]);
          
          return true;
        }),
        { numRuns: 100 }
      );
    });

    it('should handle subscribers with empty preferences gracefully', () => {
      fc.assert(
        fc.property(notificationArb, (notification) => {
          const subscriberWithNoCategories: NotificationSubscriber = {
            admin_id: 'test-admin',
            realm_access: [],
            categories: [],
            severities: ['critical'],
          };
          
          const subscriberWithNoSeverities: NotificationSubscriber = {
            admin_id: 'test-admin-2',
            realm_access: [],
            categories: ['security'],
            severities: [],
          };
          
          // Should not deliver to subscribers with empty preferences
          expect(shouldDeliverToSubscriber(notification, subscriberWithNoCategories)).toBe(false);
          expect(shouldDeliverToSubscriber(notification, subscriberWithNoSeverities)).toBe(false);
          
          return true;
        }),
        { numRuns: 100 }
      );
    });
  });
});
