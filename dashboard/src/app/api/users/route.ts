/**
 * Users API Route for Zalt.io Dashboard
 * Connects to real Zalt API backend
 */

import { NextRequest, NextResponse } from 'next/server';
import { listUsers, ZALT_API_URL } from '@/lib/zalt-api';

export async function GET(request: NextRequest) {
  const accessToken = request.cookies.get('zalt_access_token')?.value;
  
  if (!accessToken) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { searchParams } = new URL(request.url);
  const realmId = searchParams.get('realmId') || searchParams.get('realm_id');
  const limit = searchParams.get('limit');
  const cursor = searchParams.get('cursor');

  if (!realmId) {
    return NextResponse.json({ error: 'realm_id is required' }, { status: 400 });
  }

  try {
    const response = await listUsers(
      realmId,
      { 
        limit: limit ? parseInt(limit) : 50,
        cursor: cursor || undefined 
      },
      accessToken
    );

    if (response.error) {
      console.error('Failed to fetch users from Zalt API:', response.error);
      return NextResponse.json({ 
        users: [],
        error: response.error,
        apiUrl: ZALT_API_URL 
      });
    }

    // Transform API response to dashboard format
    const users = (response.data?.users || []).map(user => ({
      id: user.id,
      realm_id: realmId,
      email: user.email,
      email_verified: user.email_verified,
      status: user.status,
      mfa_enabled: user.mfa_enabled,
      profile: user.profile,
      created_at: user.created_at,
      last_login: user.last_login_at,
    }));

    return NextResponse.json({ 
      users,
      nextCursor: response.data?.nextCursor 
    });
  } catch (error) {
    console.error('Users API error:', error);
    return NextResponse.json({ 
      users: [],
      error: 'Failed to connect to Zalt API' 
    });
  }
}
