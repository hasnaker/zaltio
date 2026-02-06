/**
 * Activate User API Route for Zalt.io Dashboard
 * Connects to real Zalt API for user activation
 */

import { NextRequest, NextResponse } from 'next/server';
import { activateUser } from '@/lib/zalt-api';

export async function POST(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  const accessToken = request.cookies.get('zalt_access_token')?.value;
  
  if (!accessToken) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const userId = params.id;
  const realmId = request.cookies.get('zalt_realm')?.value || 'clinisyn';

  const result = await activateUser(realmId, userId, accessToken);

  if (result.error) {
    return NextResponse.json({ error: result.error }, { status: result.status });
  }

  return NextResponse.json({ success: true, status: 'active' });
}
