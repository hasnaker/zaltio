/**
 * Notifications API Route for HSD Auth Dashboard
 * Validates: Requirements 3.6 (real-time notifications)
 */

import { NextRequest, NextResponse } from 'next/server';
import { verifyToken, extractAdminUser, hasRealmAccess } from '@/middleware/auth';
import { Notification } from '@/types/notifications';

// Mock notifications for development
const MOCK_NOTIFICATIONS: Notification[] = [
  {
    id: 'notif-1',
    title: 'High Error Rate Detected',
    message: 'Error rate exceeded 5% threshold in HSD Portal realm',
    severity: 'warning',
    category: 'performance',
    realm_id: 'realm-1',
    timestamp: new Date(Date.now() - 300000).toISOString(),
    read: false,
  },
  {
    id: 'notif-2',
    title: 'Suspicious Login Activity',
    message: 'Multiple failed login attempts detected from IP 192.168.1.100',
    severity: 'critical',
    category: 'security',
    realm_id: 'realm-1',
    timestamp: new Date(Date.now() - 600000).toISOString(),
    read: false,
  },
  {
    id: 'notif-3',
    title: 'New User Registration Spike',
    message: '50 new users registered in the last hour',
    severity: 'info',
    category: 'user',
    realm_id: 'realm-2',
    timestamp: new Date(Date.now() - 1800000).toISOString(),
    read: true,
  },
  {
    id: 'notif-4',
    title: 'Realm Configuration Updated',
    message: 'Password policy updated for HSD Chat realm',
    severity: 'info',
    category: 'realm',
    realm_id: 'realm-2',
    timestamp: new Date(Date.now() - 3600000).toISOString(),
    read: true,
  },
  {
    id: 'notif-5',
    title: 'System Maintenance Scheduled',
    message: 'Scheduled maintenance window: Jan 20, 2024 02:00-04:00 UTC',
    severity: 'warning',
    category: 'system',
    timestamp: new Date(Date.now() - 7200000).toISOString(),
    read: false,
  },
];

export async function GET(request: NextRequest) {
  const token = request.cookies.get('auth_token')?.value;
  
  if (!token) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const payload = verifyToken(token);
  if (!payload) {
    return NextResponse.json({ error: 'Invalid token' }, { status: 401 });
  }

  const admin = extractAdminUser(payload);
  const { searchParams } = new URL(request.url);
  const since = searchParams.get('since');

  // Filter notifications based on admin's realm access
  let filteredNotifications = MOCK_NOTIFICATIONS.filter(notification => {
    // System-wide notifications are visible to all
    if (!notification.realm_id) return true;
    // Realm-specific notifications require realm access
    return hasRealmAccess(admin, notification.realm_id);
  });

  // Filter by timestamp if 'since' parameter provided
  if (since) {
    const sinceTime = new Date(since).getTime();
    filteredNotifications = filteredNotifications.filter(
      n => new Date(n.timestamp).getTime() > sinceTime
    );
  }

  return NextResponse.json({ notifications: filteredNotifications });
}
