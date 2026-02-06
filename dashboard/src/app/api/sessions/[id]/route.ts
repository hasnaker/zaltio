/**
 * Single Session API Route for Zalt.io Dashboard
 * Connects to real Zalt API for session management
 */

import { NextRequest, NextResponse } from 'next/server';
import { revokeSession } from '@/lib/zalt-api';

export async function DELETE(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  const accessToken = request.cookies.get('zalt_access_token')?.value;
  
  if (!accessToken) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const sessionId = params.id;
  const result = await revokeSession(sessionId, accessToken);

  if (result.error) {
    return NextResponse.json({ error: result.error }, { status: result.status });
  }

  return NextResponse.json({ success: true });
}
