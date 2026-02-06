/**
 * Sessions API Route for Zalt.io Dashboard
 * Connects to real Zalt API for session management
 */

import { NextRequest, NextResponse } from 'next/server';
import { listSessions, revokeSession } from '@/lib/zalt-api';

export async function GET(request: NextRequest) {
  const accessToken = request.cookies.get('zalt_access_token')?.value;
  
  if (!accessToken) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { searchParams } = new URL(request.url);
  const realmId = searchParams.get('realmId') || request.cookies.get('zalt_realm')?.value || 'clinisyn';
  const userId = searchParams.get('userId') || undefined;

  const result = await listSessions(realmId, userId, accessToken);

  if (result.error) {
    return NextResponse.json({ error: result.error }, { status: result.status });
  }

  return NextResponse.json({ sessions: result.data?.sessions || [] });
}

export async function DELETE(request: NextRequest) {
  const accessToken = request.cookies.get('zalt_access_token')?.value;
  
  if (!accessToken) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { searchParams } = new URL(request.url);
  const sessionId = searchParams.get('sessionId');

  if (!sessionId) {
    return NextResponse.json({ error: 'Session ID required' }, { status: 400 });
  }

  const result = await revokeSession(sessionId, accessToken);

  if (result.error) {
    return NextResponse.json({ error: result.error }, { status: result.status });
  }

  return NextResponse.json({ success: true });
}
