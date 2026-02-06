/**
 * API Keys Route for Zalt.io Dashboard
 * Uses Platform API for customer API key management
 */

import { NextRequest, NextResponse } from 'next/server';
import { 
  listPlatformApiKeys, 
  createPlatformApiKey, 
  revokePlatformApiKey 
} from '@/lib/zalt-api';

// GET /api/settings/api-keys - List customer's API keys
export async function GET(request: NextRequest) {
  const accessToken = request.cookies.get('zalt_access_token')?.value;

  if (!accessToken) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const result = await listPlatformApiKeys(accessToken);

  if (result.error) {
    // If endpoint doesn't exist yet, return empty array
    if (result.status === 404) {
      return NextResponse.json({ keys: [] });
    }
    return NextResponse.json({ error: result.error }, { status: result.status });
  }

  // Transform to dashboard format
  const keys = (result.data?.api_keys || []).map(key => ({
    id: key.id,
    name: key.name || `${key.type} key`,
    key: key.key_hint, // Only show hint, not full key
    type: key.environment,
    keyType: key.type,
    createdAt: key.created_at,
    lastUsed: key.last_used_at || null,
    usageCount: key.usage_count,
    status: key.status,
  }));

  return NextResponse.json({ keys });
}

// POST /api/settings/api-keys - Create new API key
export async function POST(request: NextRequest) {
  const accessToken = request.cookies.get('zalt_access_token')?.value;

  if (!accessToken) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  try {
    const body = await request.json();
    const { name, type, keyType } = body as { 
      name?: string; 
      type: 'live' | 'test';
      keyType?: 'publishable' | 'secret';
    };

    if (!type || !['live', 'test'].includes(type)) {
      return NextResponse.json({ error: 'Invalid key type' }, { status: 400 });
    }

    const result = await createPlatformApiKey({
      type: keyType || 'publishable',
      environment: type,
      name,
    }, accessToken);

    if (result.error) {
      return NextResponse.json({ error: result.error }, { status: result.status });
    }

    return NextResponse.json({
      key: {
        id: result.data?.api_key.id,
        name: result.data?.api_key.name,
        fullKey: result.data?.full_key, // Only returned on creation
        type: result.data?.api_key.environment,
        keyType: result.data?.api_key.type,
        createdAt: result.data?.api_key.created_at,
      },
      message: 'API key created. Copy it now - you won\'t see it again!',
    });
  } catch {
    return NextResponse.json({ error: 'Failed to create API key' }, { status: 500 });
  }
}

// DELETE /api/settings/api-keys - Revoke an API key
export async function DELETE(request: NextRequest) {
  const accessToken = request.cookies.get('zalt_access_token')?.value;

  if (!accessToken) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { searchParams } = new URL(request.url);
  const keyId = searchParams.get('keyId');

  if (!keyId) {
    return NextResponse.json({ error: 'Key ID required' }, { status: 400 });
  }

  const result = await revokePlatformApiKey(keyId, accessToken);

  if (result.error) {
    return NextResponse.json({ error: result.error }, { status: result.status });
  }

  return NextResponse.json({ success: true });
}
