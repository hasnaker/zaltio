/**
 * Single User API Route for Zalt.io Dashboard
 * Connects to real Zalt API for user management
 */

import { NextRequest, NextResponse } from 'next/server';
import { getUser, suspendUser, activateUser, zaltApiRequest } from '@/lib/zalt-api';

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  const accessToken = request.cookies.get('zalt_access_token')?.value;
  
  if (!accessToken) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const userId = params.id;
  const realmId = request.cookies.get('zalt_realm')?.value || 'clinisyn';
  
  const result = await getUser(realmId, userId, accessToken);

  if (result.error) {
    return NextResponse.json({ error: result.error }, { status: result.status });
  }

  return NextResponse.json({ user: result.data?.user });
}

export async function PATCH(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  const accessToken = request.cookies.get('zalt_access_token')?.value;
  
  if (!accessToken) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const userId = params.id;
  const realmId = request.cookies.get('zalt_realm')?.value || 'clinisyn';

  try {
    const body = await request.json();
    
    // Handle status changes
    if (body.status === 'suspended') {
      const result = await suspendUser(realmId, userId, accessToken);
      if (result.error) {
        return NextResponse.json({ error: result.error }, { status: result.status });
      }
      return NextResponse.json({ success: true });
    }
    
    if (body.status === 'active') {
      const result = await activateUser(realmId, userId, accessToken);
      if (result.error) {
        return NextResponse.json({ error: result.error }, { status: result.status });
      }
      return NextResponse.json({ success: true });
    }

    // General user update
    const result = await zaltApiRequest(`/v1/admin/users/${userId}`, {
      method: 'PATCH',
      body: { ...body, realm_id: realmId },
      accessToken,
    });

    if (result.error) {
      return NextResponse.json({ error: result.error }, { status: result.status });
    }

    return NextResponse.json({ user: result.data });
  } catch {
    return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
  }
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  const accessToken = request.cookies.get('zalt_access_token')?.value;
  
  if (!accessToken) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const userId = params.id;
  const realmId = request.cookies.get('zalt_realm')?.value || 'clinisyn';

  const result = await zaltApiRequest(`/v1/admin/users/${userId}`, {
    method: 'DELETE',
    body: { realm_id: realmId },
    accessToken,
  });

  if (result.error) {
    return NextResponse.json({ error: result.error }, { status: result.status });
  }

  return NextResponse.json({ success: true });
}
