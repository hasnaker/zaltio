/**
 * Notification Service for HSD Auth Dashboard
 * Validates: Requirements 3.6 (real-time notifications)
 */

import { Notification, NotificationSeverity, NotificationCategory } from '@/types/notifications';

export type NotificationHandler = (notification: Notification) => void;

/**
 * Notification Service class for managing real-time notifications
 */
export class NotificationService {
  private handlers: Set<NotificationHandler> = new Set();
  private notifications: Notification[] = [];
  private pollingInterval: NodeJS.Timeout | null = null;
  private lastFetchTime: string = new Date().toISOString();

  /**
   * Subscribe to notifications
   */
  subscribe(handler: NotificationHandler): () => void {
    this.handlers.add(handler);
    
    // Start polling if this is the first subscriber
    if (this.handlers.size === 1) {
      this.startPolling();
    }
    
    // Return unsubscribe function
    return () => {
      this.handlers.delete(handler);
      
      // Stop polling if no more subscribers
      if (this.handlers.size === 0) {
        this.stopPolling();
      }
    };
  }

  /**
   * Start polling for new notifications
   */
  private startPolling(): void {
    // Poll every 10 seconds
    this.pollingInterval = setInterval(() => {
      this.fetchNotifications();
    }, 10000);
    
    // Fetch immediately
    this.fetchNotifications();
  }

  /**
   * Stop polling for notifications
   */
  private stopPolling(): void {
    if (this.pollingInterval) {
      clearInterval(this.pollingInterval);
      this.pollingInterval = null;
    }
  }

  /**
   * Fetch new notifications from the server
   */
  private async fetchNotifications(): Promise<void> {
    try {
      const response = await fetch(`/api/notifications?since=${encodeURIComponent(this.lastFetchTime)}`);
      if (!response.ok) return;
      
      const data = await response.json();
      const newNotifications: Notification[] = data.notifications || [];
      
      // Update last fetch time
      this.lastFetchTime = new Date().toISOString();
      
      // Notify handlers of new notifications
      newNotifications.forEach(notification => {
        this.notifications.unshift(notification);
        this.handlers.forEach(handler => handler(notification));
      });
    } catch (error) {
      console.error('Failed to fetch notifications:', error);
    }
  }

  /**
   * Get all notifications
   */
  getNotifications(): Notification[] {
    return [...this.notifications];
  }

  /**
   * Get unread notification count
   */
  getUnreadCount(): number {
    return this.notifications.filter(n => !n.read).length;
  }

  /**
   * Mark notification as read
   */
  async markAsRead(notificationId: string): Promise<void> {
    const notification = this.notifications.find(n => n.id === notificationId);
    if (notification) {
      notification.read = true;
    }
    
    try {
      await fetch(`/api/notifications/${notificationId}/read`, { method: 'POST' });
    } catch (error) {
      console.error('Failed to mark notification as read:', error);
    }
  }

  /**
   * Mark all notifications as read
   */
  async markAllAsRead(): Promise<void> {
    this.notifications.forEach(n => n.read = true);
    
    try {
      await fetch('/api/notifications/read-all', { method: 'POST' });
    } catch (error) {
      console.error('Failed to mark all notifications as read:', error);
    }
  }

  /**
   * Clear all notifications
   */
  clearAll(): void {
    this.notifications = [];
  }
}

// Singleton instance
let notificationService: NotificationService | null = null;

export function getNotificationService(): NotificationService {
  if (!notificationService) {
    notificationService = new NotificationService();
  }
  return notificationService;
}

/**
 * Create a notification (for testing/demo purposes)
 */
export function createNotification(
  title: string,
  message: string,
  severity: NotificationSeverity,
  category: NotificationCategory,
  realmId?: string
): Notification {
  return {
    id: `notif-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    title,
    message,
    severity,
    category,
    realm_id: realmId,
    timestamp: new Date().toISOString(),
    read: false,
  };
}

/**
 * Validate notification delivery timing
 * Returns true if notification was delivered within threshold
 */
export function validateNotificationTiming(
  notification: Notification,
  eventTimestamp: string,
  thresholdMs: number = 5000
): boolean {
  const eventTime = new Date(eventTimestamp).getTime();
  const notificationTime = new Date(notification.timestamp).getTime();
  return (notificationTime - eventTime) <= thresholdMs;
}

/**
 * Check for duplicate notifications
 */
export function isDuplicateNotification(
  notification: Notification,
  existingNotifications: Notification[]
): boolean {
  return existingNotifications.some(
    existing => 
      existing.title === notification.title &&
      existing.message === notification.message &&
      existing.category === notification.category &&
      Math.abs(new Date(existing.timestamp).getTime() - new Date(notification.timestamp).getTime()) < 1000
  );
}
