/**
 * Logout API Route for Zalt.io Dashboard
 * Invalidates customer session via Platform API
 */

import { NextRequest, NextResponse } from 'next/server';

const ZALT_API_URL = process.env.NEXT_PUBLIC_ZALT_API_URL || 'https://api.zalt.io';

export async function POST(request: NextRequest) {
  const accessToken = request.cookies.get('zalt_access_token')?.value;
  const refreshToken = request.cookies.get('zalt_refresh_token')?.value;

  // Call Platform API to invalidate session (best effort)
  if (accessToken) {
    try {
      await fetch(`${ZALT_API_URL}/platform/logout`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`,
        },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });
    } catch (error) {
      // Log but don't fail - we'll clear cookies anyway
      console.warn('Logout API call failed:', error);
    }
  }

  const response = NextResponse.json({ success: true });
  
  // Clear all auth cookies
  response.cookies.delete('zalt_access_token');
  response.cookies.delete('zalt_refresh_token');
  response.cookies.delete('zalt_customer_id');
  
  // Clear legacy cookies for migration
  response.cookies.delete('zalt_user_role');
  response.cookies.delete('zalt_realm');
  response.cookies.delete('auth_token');
  
  return response;
}
