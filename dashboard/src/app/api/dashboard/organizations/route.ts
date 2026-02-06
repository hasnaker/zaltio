import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';

// Mock data - in production this would come from DynamoDB
const mockOrganizations = [
  {
    id: 'org_clinisyn',
    name: 'Clinisyn',
    slug: 'clinisyn',
    memberCount: 4200,
    plan: 'enterprise' as const,
    role: 'owner' as const,
    createdAt: '2025-12-01T10:00:00Z',
  },
  {
    id: 'org_demo',
    name: 'Demo Organization',
    slug: 'demo-org',
    memberCount: 5,
    plan: 'pro' as const,
    role: 'admin' as const,
    createdAt: '2026-01-20T10:00:00Z',
  },
];

export async function GET(request: NextRequest) {
  try {
    return NextResponse.json({ organizations: mockOrganizations });
  } catch (error) {
    return NextResponse.json({ error: 'Failed to fetch organizations' }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { name } = body;

    if (!name) {
      return NextResponse.json({ error: 'Name is required' }, { status: 400 });
    }

    // Generate slug from name
    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');

    const newOrg = {
      id: 'org_' + crypto.randomBytes(8).toString('hex'),
      name,
      slug,
      memberCount: 1,
      plan: 'free' as const,
      role: 'owner' as const,
      createdAt: new Date().toISOString(),
    };

    // In production, save to DynamoDB
    return NextResponse.json({ organization: newOrg });
  } catch (error) {
    return NextResponse.json({ error: 'Failed to create organization' }, { status: 500 });
  }
}
