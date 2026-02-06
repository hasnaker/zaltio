/**
 * Admins API Route for Zalt.io Dashboard
 * Connects to real Zalt API for admin management
 */

import { NextRequest, NextResponse } from 'next/server';
import { zaltApiRequest } from '@/lib/zalt-api';

export async function GET(request: NextRequest) {
  const accessToken = request.cookies.get('zalt_access_token')?.value;
  
  if (!accessToken) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const result = await zaltApiRequest<{ admins: unknown[] }>('/v1/admin/admins', { accessToken });

  if (result.error) {
    return NextResponse.json({ error: result.error }, { status: result.status });
  }

  return NextResponse.json({ admins: result.data?.admins || [] });
}

export async function POST(request: NextRequest) {
  const accessToken = request.cookies.get('zalt_access_token')?.value;
  
  if (!accessToken) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  try {
    const body = await request.json();
    
    const result = await zaltApiRequest<{ admin: unknown }>('/v1/admin/admins', {
      method: 'POST',
      body,
      accessToken,
    });

    if (result.error) {
      return NextResponse.json({ error: result.error }, { status: result.status });
    }

    return NextResponse.json({ admin: result.data?.admin }, { status: 201 });
  } catch {
    return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
  }
}
