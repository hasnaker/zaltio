/**
 * Single Realm API Route for Zalt.io Dashboard
 * Connects to real Zalt API for realm management
 */

import { NextRequest, NextResponse } from 'next/server';
import { getRealm, updateRealm, zaltApiRequest } from '@/lib/zalt-api';

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  const accessToken = request.cookies.get('zalt_access_token')?.value;
  
  if (!accessToken) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const realmId = params.id;
  const result = await getRealm(realmId, accessToken);

  if (result.error) {
    return NextResponse.json({ error: result.error }, { status: result.status });
  }

  return NextResponse.json({ realm: result.data?.realm });
}

export async function PUT(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  const accessToken = request.cookies.get('zalt_access_token')?.value;
  
  if (!accessToken) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const realmId = params.id;

  try {
    const body = await request.json();
    const result = await updateRealm(realmId, body, accessToken);

    if (result.error) {
      return NextResponse.json({ error: result.error }, { status: result.status });
    }

    return NextResponse.json({ realm: result.data?.realm });
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

  const realmId = params.id;
  const result = await zaltApiRequest(`/v1/admin/realms/${realmId}`, {
    method: 'DELETE',
    accessToken,
  });

  if (result.error) {
    return NextResponse.json({ error: result.error }, { status: result.status });
  }

  return NextResponse.json({ success: true });
}
