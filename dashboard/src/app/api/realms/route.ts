/**
 * Realms API Route for Zalt.io Dashboard
 * Uses Platform API for customer realm management
 */

import { NextRequest, NextResponse } from 'next/server';
import { listPlatformRealms, createPlatformRealm, ZALT_API_URL } from '@/lib/zalt-api';

export async function GET(request: NextRequest) {
  const accessToken = request.cookies.get('zalt_access_token')?.value;
  
  if (!accessToken) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  try {
    const response = await listPlatformRealms(accessToken);
    
    if (response.error) {
      console.error('Failed to fetch realms from Platform API:', response.error);
      return NextResponse.json({ 
        realms: [],
        error: response.error,
        apiUrl: ZALT_API_URL 
      });
    }

    // Transform API response to dashboard format
    const realms = (response.data?.realms || []).map(realm => ({
      id: realm.realmId || realm.id,
      name: realm.name,
      slug: realm.realmId || realm.id,
      domain: realm.domain,
      userCount: 0, // Will be fetched separately
      sessionCount: 0,
      mfaPolicy: realm.settings?.mfa_required ? 'required' : 'optional',
      status: realm.status || 'active',
      createdAt: realm.createdAt ? new Date(realm.createdAt).toLocaleDateString() : 'Unknown',
      settings: realm.settings,
    }));

    return NextResponse.json({ realms });
  } catch (error) {
    console.error('Realms API error:', error);
    return NextResponse.json({ 
      realms: [],
      error: 'Failed to connect to Platform API' 
    });
  }
}

export async function POST(request: NextRequest) {
  const accessToken = request.cookies.get('zalt_access_token')?.value;
  
  if (!accessToken) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  try {
    const body = await request.json();
    
    if (!body.name) {
      return NextResponse.json({ error: 'Realm name is required' }, { status: 400 });
    }

    const response = await createPlatformRealm({
      name: body.name,
      domain: body.domain,
      settings: body.settings,
    }, accessToken);

    if (response.error) {
      return NextResponse.json({ error: response.error }, { status: response.status });
    }

    return NextResponse.json({ realm: response.data?.realm }, { status: 201 });
  } catch (error) {
    console.error('Create realm error:', error);
    return NextResponse.json({ error: 'Failed to create realm' }, { status: 500 });
  }
}
