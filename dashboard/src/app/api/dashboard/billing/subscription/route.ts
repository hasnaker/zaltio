import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
  try {
    // Mock subscription data - in production this would come from Stripe
    const subscription = {
      id: 'sub_clinisyn',
      planId: 'enterprise',
      status: 'active' as const,
      currentPeriodEnd: '2026-03-01T00:00:00Z',
      cancelAtPeriodEnd: false,
    };

    return NextResponse.json({ subscription });
  } catch (error) {
    return NextResponse.json({ error: 'Failed to fetch subscription' }, { status: 500 });
  }
}
