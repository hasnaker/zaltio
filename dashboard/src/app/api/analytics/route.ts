/**
 * Analytics API Route for Zalt.io Dashboard
 * Proxies requests to Platform Analytics API
 * 
 * Validates: Requirements 9.1, 9.2, 9.3
 */

import { NextRequest, NextResponse } from 'next/server';

const ZALT_API_URL = process.env.NEXT_PUBLIC_ZALT_API_URL || 'https://api.zalt.io';

export async function GET(request: NextRequest) {
  const accessToken = request.cookies.get('zalt_access_token')?.value;

  if (!accessToken) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { searchParams } = new URL(request.url);
  const chartType = searchParams.get('type') || 'summary';
  const startDate = searchParams.get('start_date');
  const endDate = searchParams.get('end_date');
  const realmId = searchParams.get('realm_id');

  // Build query string
  const params = new URLSearchParams();
  if (startDate) params.set('start_date', startDate);
  if (endDate) params.set('end_date', endDate);
  if (realmId) params.set('realm_id', realmId);

  // Determine endpoint based on chart type
  let endpoint = '/platform/analytics';
  if (chartType === 'dau') {
    endpoint = '/platform/analytics/dau';
  } else if (chartType === 'logins') {
    endpoint = '/platform/analytics/logins';
  } else if (chartType === 'mfa') {
    endpoint = '/platform/analytics/mfa';
  }

  try {
    const response = await fetch(
      `${ZALT_API_URL}${endpoint}?${params.toString()}`,
      {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
      }
    );

    const data = await response.json();

    if (!response.ok) {
      return NextResponse.json(
        { error: data.error?.message || 'Failed to fetch analytics' },
        { status: response.status }
      );
    }

    return NextResponse.json(data);
  } catch (error) {
    console.error('Analytics API error:', error);
    return NextResponse.json(
      { error: 'Failed to connect to analytics API' },
      { status: 500 }
    );
  }
}
