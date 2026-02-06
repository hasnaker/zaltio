/**
 * Dashboard Stats API Route
 * Connects to real Zalt API backend
 */

import { NextRequest, NextResponse } from 'next/server';
import { getDashboardStats, ZALT_API_URL } from '@/lib/zalt-api';

export async function GET(request: NextRequest) {
  const accessToken = request.cookies.get('zalt_access_token')?.value;
  const realmId = request.cookies.get('zalt_realm')?.value;

  try {
    // Try to fetch from real Zalt API
    const response = await getDashboardStats(realmId, accessToken);

    if (response.error || !response.data) {
      // Return zeros if API fails (not mock data)
      console.error('Failed to fetch stats from Zalt API:', response.error);
      return NextResponse.json({
        totalRealms: 0,
        totalUsers: 0,
        activeSessions: 0,
        loginsTodayCount: 0,
        mfaEnabledUsers: 0,
        recentSignups: 0,
        error: response.error,
        apiUrl: ZALT_API_URL,
      });
    }

    return NextResponse.json(response.data);
  } catch (error) {
    console.error('Stats API error:', error);
    return NextResponse.json({
      totalRealms: 0,
      totalUsers: 0,
      activeSessions: 0,
      loginsTodayCount: 0,
      error: 'Failed to connect to Zalt API',
    });
  }
}
