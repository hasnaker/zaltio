/**
 * Admin by ID API Route for Zalt.io Dashboard
 * Connects to real Zalt API for admin management
 */

import { NextRequest, NextResponse } from 'next/server';
import { zaltApiRequest } from '@/lib/zalt-api';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const accessToken = request.cookies.get('zalt_access_token')?.value;
  
  if (!accessToken) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { id } = await params;
  
  const result = await zaltApiRequest<{ admin: unknown }>(`/v1/admin/admins/${id}`, {
    accessToken,
  });

  if (result.error) {
    return NextResponse.json({ error: result.error }, { status: result.status });
  }

  return NextResponse.json({ admin: result.data?.admin });
}

export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const accessToken = request.cookies.get('zalt_access_token')?.value;
  
  if (!accessToken) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { id } = await params;

  try {
    const body = await request.json();
    
    const result = await zaltApiRequest<{ admin: unknown }>(`/v1/admin/admins/${id}`, {
      method: 'PUT',
      body,
      accessToken,
    });

    if (result.error) {
      return NextResponse.json({ error: result.error }, { status: result.status });
    }

    return NextResponse.json({ admin: result.data?.admin });
  } catch {
    return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
  }
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const accessToken = request.cookies.get('zalt_access_token')?.value;
  
  if (!accessToken) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { id } = await params;

  const result = await zaltApiRequest(`/v1/admin/admins/${id}`, {
    method: 'DELETE',
    accessToken,
  });

  if (result.error) {
    return NextResponse.json({ error: result.error }, { status: result.status });
  }

  return NextResponse.json({ success: true, deleted: id });
}
