import { NextRequest, NextResponse } from 'next/server';

// Mock members data
const mockMembers: Record<string, any[]> = {
  'org_clinisyn': [
    { id: 'user_1', email: 'hasan@clinisyn.com', name: 'Hasan Aker', role: 'owner', joinedAt: '2025-12-01T10:00:00Z', lastActive: '2026-02-03T13:00:00Z' },
    { id: 'user_2', email: 'admin@clinisyn.com', name: 'Admin User', role: 'admin', joinedAt: '2025-12-15T10:00:00Z', lastActive: '2026-02-03T12:00:00Z' },
    { id: 'user_3', email: 'dr.ayse@clinisyn.com', name: 'Dr. Ayşe Yılmaz', role: 'member', joinedAt: '2026-01-05T10:00:00Z', lastActive: '2026-02-03T11:00:00Z' },
    { id: 'user_4', email: 'dr.mehmet@clinisyn.com', name: 'Dr. Mehmet Kaya', role: 'member', joinedAt: '2026-01-10T10:00:00Z', lastActive: '2026-02-02T15:00:00Z' },
  ],
  'org_demo': [
    { id: 'user_5', email: 'demo@zalt.io', name: 'Demo User', role: 'owner', joinedAt: '2026-01-20T10:00:00Z', lastActive: '2026-02-03T10:00:00Z' },
  ],
};

export async function GET(
  request: NextRequest,
  { params }: { params: { orgId: string } }
) {
  try {
    const members = mockMembers[params.orgId] || [];
    return NextResponse.json({ members });
  } catch (error) {
    return NextResponse.json({ error: 'Failed to fetch members' }, { status: 500 });
  }
}
