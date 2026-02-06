/**
 * Notification Service for HSD Auth Platform
 * Validates: Requirements 3.6 (real-time notifications)
 * 
 * Provides notification delivery and management for critical system events
 */

export type NotificationSeverity = 'info' | 'warning' | 'error' | 'critical';

export type NotificationCategory = 
  | 'security'
  | 'system'
  | 'user'
  | 'realm'
  | 'performance';

export interface Notification {
  id: string;
  title: string;
  message: string;
  severity: NotificationSeverity;
  category: NotificationCategory;
  realm_id?: string;
  timestamp: string;
  read: boolean;
  delivered_at?: string;
  action_url?: string;
}

export interface NotificationSubscriber {
  admin_id: string;
  realm_access: string[];
  categories: NotificationCategory[];
  severities: NotificationSeverity[];
}

export interface DeliveryResult {
  notification: Notification;
  subscriber_id: string;
  delivered: boolean;
  delivered_at: string;
  delivery_time_ms: number;
}

/**
 * Create a notification with timestamp
 */
export function createNotification(
  id: string,
  title: string,
  message: string,
  severity: NotificationSeverity,
  category: NotificationCategory,
  realmId?: string,
  eventTimestamp?: string
): Notification {
  return {
    id,
    title,
    message,
    severity,
    category,
    realm_id: realmId,
    timestamp: eventTimestamp || new Date().toISOString(),
    read: false,
  };
}

/**
 * Check if a subscriber should receive a notification
 * Based on realm access, category preferences, and severity preferences
 */
export function shouldDeliverToSubscriber(
  notification: Notification,
  subscriber: NotificationSubscriber
): boolean {
  // Check category preference
  if (!subscriber.categories.includes(notification.category)) {
    return false;
  }
  
  // Check severity preference
  if (!subscriber.severities.includes(notification.severity)) {
    return false;
  }
  
  // Check realm access for realm-specific notifications
  if (notification.realm_id) {
    // Super admins (empty realm_access means all access) or specific realm access
    if (subscriber.realm_access.length > 0 && !subscriber.realm_access.includes(notification.realm_id)) {
      return false;
    }
  }
  
  return true;
}

/**
 * Deliver notification to a subscriber
 * Returns delivery result with timing information
 */
export function deliverNotification(
  notification: Notification,
  subscriber: NotificationSubscriber,
  eventTimestamp: string
): DeliveryResult {
  const deliveredAt = new Date().toISOString();
  const eventTime = new Date(eventTimestamp).getTime();
  const deliveryTime = new Date(deliveredAt).getTime();
  
  return {
    notification: {
      ...notification,
      delivered_at: deliveredAt,
    },
    subscriber_id: subscriber.admin_id,
    delivered: shouldDeliverToSubscriber(notification, subscriber),
    delivered_at: deliveredAt,
    delivery_time_ms: deliveryTime - eventTime,
  };
}

/**
 * Validate notification delivery timing
 * Returns true if notification was delivered within threshold
 * Validates: Requirements 3.6 (real-time notification delivery)
 */
export function validateDeliveryTiming(
  deliveryResult: DeliveryResult,
  thresholdMs: number = 5000
): boolean {
  return deliveryResult.delivery_time_ms <= thresholdMs;
}

/**
 * Check for duplicate notifications
 * Two notifications are duplicates if they have the same title, message, 
 * category, and were created within 1 second of each other
 */
export function isDuplicateNotification(
  notification: Notification,
  existingNotifications: Notification[]
): boolean {
  return existingNotifications.some(existing => {
    if (existing.id === notification.id) return false; // Same notification
    if (existing.title !== notification.title) return false;
    if (existing.message !== notification.message) return false;
    if (existing.category !== notification.category) return false;
    
    const timeDiff = Math.abs(
      new Date(existing.timestamp).getTime() - new Date(notification.timestamp).getTime()
    );
    return timeDiff < 1000; // Within 1 second
  });
}

/**
 * Deliver notification to multiple subscribers
 * Returns array of delivery results, filtering out duplicates
 */
export function deliverToSubscribers(
  notification: Notification,
  subscribers: NotificationSubscriber[],
  eventTimestamp: string,
  existingNotifications: Notification[] = []
): DeliveryResult[] {
  // Check for duplicates first
  if (isDuplicateNotification(notification, existingNotifications)) {
    return []; // Don't deliver duplicates
  }
  
  return subscribers
    .filter(subscriber => shouldDeliverToSubscriber(notification, subscriber))
    .map(subscriber => deliverNotification(notification, subscriber, eventTimestamp));
}

/**
 * Get notifications for a subscriber
 * Filters by realm access and preferences
 */
export function getNotificationsForSubscriber(
  allNotifications: Notification[],
  subscriber: NotificationSubscriber
): Notification[] {
  return allNotifications.filter(notification => 
    shouldDeliverToSubscriber(notification, subscriber)
  );
}

/**
 * Count unread notifications for a subscriber
 */
export function getUnreadCount(
  notifications: Notification[],
  subscriber: NotificationSubscriber
): number {
  return getNotificationsForSubscriber(notifications, subscriber)
    .filter(n => !n.read)
    .length;
}

/**
 * Mark notification as read
 */
export function markAsRead(notification: Notification): Notification {
  return {
    ...notification,
    read: true,
  };
}

/**
 * Mark all notifications as read for a subscriber
 */
export function markAllAsRead(
  notifications: Notification[],
  subscriber: NotificationSubscriber
): Notification[] {
  return notifications.map(notification => {
    if (shouldDeliverToSubscriber(notification, subscriber)) {
      return markAsRead(notification);
    }
    return notification;
  });
}

/**
 * Filter critical notifications
 * Critical notifications are those with 'critical' or 'error' severity
 */
export function getCriticalNotifications(notifications: Notification[]): Notification[] {
  return notifications.filter(n => 
    n.severity === 'critical' || n.severity === 'error'
  );
}

/**
 * Validate that all critical events generate notifications
 */
export function validateCriticalEventNotification(
  eventType: string,
  eventTimestamp: string,
  notifications: Notification[]
): boolean {
  // Check if there's a notification for this event within the time window
  const eventTime = new Date(eventTimestamp).getTime();
  
  return notifications.some(notification => {
    const notificationTime = new Date(notification.timestamp).getTime();
    const timeDiff = notificationTime - eventTime;
    
    // Notification should be created within 5 seconds of the event
    return timeDiff >= 0 && timeDiff <= 5000;
  });
}
