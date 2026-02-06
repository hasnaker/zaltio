/**
 * Current Customer API Route for Zalt.io Dashboard
 * Returns authenticated customer's profile via Platform API
 * 
 * Flow:
 * 1. Get access token from cookie
 * 2. Call GET /platform/me with token
 * 3. Return customer info
 * 4. Handle token refresh if needed
 */

import { NextRequest, NextResponse } from 'next/server';

const ZALT_API_URL = process.env.NEXT_PUBLIC_ZALT_API_URL || 'https://api.zalt.io';

export async function GET(request: NextRequest) {
  const accessToken = request.cookies.get('zalt_access_token')?.value;
  const refreshToken = request.cookies.get('zalt_refresh_token')?.value;

  if (!accessToken) {
    // Try to refresh if we have refresh token
    if (refreshToken) {
      return tryRefreshToken(refreshToken);
    }
    return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
  }

  try {
    // Call Platform Me API
    const meResponse = await fetch(`${ZALT_API_URL}/platform/me`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
    });

    // Handle token expiration
    if (meResponse.status === 401) {
      if (refreshToken) {
        return tryRefreshToken(refreshToken);
      }
      const response = NextResponse.json({ error: 'Session expired' }, { status: 401 });
      clearAuthCookies(response);
      return response;
    }

    if (!meResponse.ok) {
      const errorData = await meResponse.json();
      return NextResponse.json(
        { error: errorData.error?.message || 'Failed to get profile' },
        { status: meResponse.status }
      );
    }

    const meData = await meResponse.json();

    return NextResponse.json({
      customer: meData.customer,
      api_keys: meData.api_keys,
      realms: meData.realms,
    });

  } catch (error) {
    console.error('Me endpoint error:', error);
    return NextResponse.json(
      { error: 'An error occurred. Please try again.' },
      { status: 500 }
    );
  }
}

/**
 * Try to refresh the access token using Platform API
 */
async function tryRefreshToken(refreshToken: string) {
  try {
    // Call Platform Refresh API
    const refreshResponse = await fetch(`${ZALT_API_URL}/platform/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    if (!refreshResponse.ok) {
      const response = NextResponse.json({ error: 'Session expired' }, { status: 401 });
      clearAuthCookies(response);
      return response;
    }

    const refreshData = await refreshResponse.json();
    const newAccessToken = refreshData.tokens?.access_token;
    const newRefreshToken = refreshData.tokens?.refresh_token;

    if (!newAccessToken) {
      const response = NextResponse.json({ error: 'Refresh failed' }, { status: 401 });
      clearAuthCookies(response);
      return response;
    }

    // Now call /platform/me with new token
    const meResponse = await fetch(`${ZALT_API_URL}/platform/me`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${newAccessToken}`,
        'Content-Type': 'application/json',
      },
    });

    if (!meResponse.ok) {
      const response = NextResponse.json({ error: 'Failed to get profile' }, { status: 401 });
      clearAuthCookies(response);
      return response;
    }

    const meData = await meResponse.json();

    const response = NextResponse.json({
      customer: meData.customer,
      api_keys: meData.api_keys,
      realms: meData.realms,
    });

    // Set new access token cookie
    response.cookies.set('zalt_access_token', newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: refreshData.tokens?.expires_in || 900,
      path: '/',
    });

    // Set new refresh token cookie if provided
    if (newRefreshToken) {
      response.cookies.set('zalt_refresh_token', newRefreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60,
        path: '/',
      });
    }

    return response;

  } catch (error) {
    console.error('Refresh token error:', error);
    const response = NextResponse.json({ error: 'Session expired' }, { status: 401 });
    clearAuthCookies(response);
    return response;
  }
}

/**
 * Clear all auth cookies
 */
function clearAuthCookies(response: NextResponse) {
  response.cookies.delete('zalt_access_token');
  response.cookies.delete('zalt_refresh_token');
  response.cookies.delete('zalt_customer_id');
}
