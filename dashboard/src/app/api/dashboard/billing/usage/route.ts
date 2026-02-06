import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
  try {
    // Mock usage data - in production this would come from analytics
    const usage = {
      mau: 4247,
      mauLimit: -1, // unlimited for enterprise
      apiCalls: 1250000,
      apiCallsLimit: -1,
      storage: 2500,
      storageLimit: 10000,
    };

    return NextResponse.json({ usage });
  } catch (error) {
    return NextResponse.json({ error: 'Failed to fetch usage' }, { status: 500 });
  }
}
