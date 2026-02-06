/**
 * Notification Settings API Route
 * Validates: Requirements 3.6 (real-time notifications)
 */

import { NextRequest, NextResponse } from 'next/server';
import { verifyToken, extractAdminUser, hasPermission } from '@/middleware/auth';
import { NotificationPreferences, DEFAULT_NOTIFICATION_PREFERENCES } from '@/types/notifications';

// Mock storage for development
const userPreferences: Map<string, NotificationPreferences> = new Map();

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
  
  if (!hasPermission(admin, 'settings:read')) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
  }

  const preferences = userPreferences.get(admin.id) || DEFAULT_NOTIFICATION_PREFERENCES;

  return NextResponse.json({ preferences });
}

export async function PUT(request: NextRequest) {
  const token = request.cookies.get('auth_token')?.value;
  
  if (!token) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const payload = verifyToken(token);
  if (!payload) {
    return NextResponse.json({ error: 'Invalid token' }, { status: 401 });
  }

  const admin = extractAdminUser(payload);
  
  if (!hasPermission(admin, 'settings:write')) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
  }

  try {
    const { preferences } = await request.json();
    
    // In production, save to DynamoDB
    userPreferences.set(admin.id, preferences);

    return NextResponse.json({ success: true, preferences });
  } catch (error) {
    return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
  }
}
