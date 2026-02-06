import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import crypto from 'crypto';

// Mock data - in production this would come from DynamoDB
const mockKeys = [
  {
    id: 'key_1',
    name: 'Production Backend',
    key: 'zalt_sk_live_' + crypto.randomBytes(24).toString('hex'),
    prefix: 'zalt_sk_live_',
    type: 'secret' as const,
    createdAt: '2026-01-15T10:00:00Z',
    lastUsed: '2026-02-03T09:30:00Z',
    expiresAt: null,
    scopes: ['read:users', 'write:users', 'read:sessions'],
  },
  {
    id: 'key_2',
    name: 'Frontend Client',
    key: 'zalt_pk_live_' + crypto.randomBytes(24).toString('hex'),
    prefix: 'zalt_pk_live_',
    type: 'publishable' as const,
    createdAt: '2026-01-15T10:00:00Z',
    lastUsed: '2026-02-03T13:00:00Z',
    expiresAt: null,
    scopes: ['read:users'],
  },
];

export async function GET(request: NextRequest) {
  try {
    // In production, verify auth token and fetch from DynamoDB
    return NextResponse.json({ keys: mockKeys });
  } catch (error) {
    return NextResponse.json({ error: 'Failed to fetch API keys' }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { name, type, scopes } = body;

    if (!name) {
      return NextResponse.json({ error: 'Name is required' }, { status: 400 });
    }

    // Generate new API key
    const prefix = type === 'secret' ? 'zalt_sk_live_' : 'zalt_pk_live_';
    const key = prefix + crypto.randomBytes(24).toString('hex');

    const newKey = {
      id: 'key_' + crypto.randomBytes(8).toString('hex'),
      name,
      key,
      prefix,
      type: type || 'publishable',
      createdAt: new Date().toISOString(),
      lastUsed: null,
      expiresAt: null,
      scopes: scopes || [],
    };

    // In production, save to DynamoDB
    // Return the full key only once
    return NextResponse.json({ 
      key: newKey.key,
      keyData: { ...newKey, key: prefix + '••••••••' }
    });
  } catch (error) {
    return NextResponse.json({ error: 'Failed to create API key' }, { status: 500 });
  }
}
