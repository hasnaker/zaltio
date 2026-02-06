/**
 * Mark All Notifications as Read API Route
 * Validates: Requirements 3.6 (real-time notifications)
 */

import { NextRequest, NextResponse } from 'next/server';
import { verifyToken } from '@/middleware/auth';

export async function POST(request: NextRequest) {
  const token = request.cookies.get('auth_token')?.value;
  
  if (!token) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const payload = verifyToken(token);
  if (!payload) {
    return NextResponse.json({ error: 'Invalid token' }, { status: 401 });
  }

  // In production, update all notification statuses in DynamoDB
  return NextResponse.json({ success: true });
}
