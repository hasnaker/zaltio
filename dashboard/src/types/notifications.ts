/**
 * Notification types for HSD Auth Dashboard
 * Validates: Requirements 3.6 (real-time notifications)
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
  action_url?: string;
}

export interface NotificationPreferences {
  enabled: boolean;
  categories: NotificationCategory[];
  severities: NotificationSeverity[];
  email_notifications: boolean;
}

export const DEFAULT_NOTIFICATION_PREFERENCES: NotificationPreferences = {
  enabled: true,
  categories: ['security', 'system', 'user', 'realm', 'performance'],
  severities: ['warning', 'error', 'critical'],
  email_notifications: true,
};
