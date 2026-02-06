/**
 * Login API Route for Zalt.io Dashboard
 * Authenticates customer accounts via Platform API
 * 
 * Flow:
 * 1. Validate input
 * 2. Call POST /platform/login
 * 3. Receive customer info and tokens
 * 4. Set session cookies
 */

import { NextRequest, NextResponse } from 'next/server';

const ZALT_API_URL = process.env.NEXT_PUBLIC_ZALT_API_URL || 'https://api.zalt.io';

// Rate limiting - simple in-memory store (use Redis in production)
const loginAttempts = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const attempt = loginAttempts.get(ip);
  
  if (!attempt || now > attempt.resetAt) {
    loginAttempts.set(ip, { count: 1, resetAt: now + 900000 }); // 15 minutes
    return true;
  }
  
  if (attempt.count >= 5) {
    return false;
  }
  
  attempt.count++;
  return true;
}

function validateEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

export async function POST(request: NextRequest) {
  try {
    // Get client IP for rate limiting
    const ip = request.headers.get('x-forwarded-for')?.split(',')[0] || 
               request.headers.get('x-real-ip') || 
               'unknown';
    
    // Check rate limit
    if (!checkRateLimit(ip)) {
      return NextResponse.json(
        { error: 'Too many login attempts. Please try again later.' },
        { status: 429 }
      );
    }

    const body = await request.json();
    const { email, password } = body;

    // Validate required fields
    if (!email || !password) {
      return NextResponse.json(
        { error: 'Email and password are required' },
        { status: 400 }
      );
    }

    // Validate email format
    if (!validateEmail(email)) {
      return NextResponse.json(
        { error: 'Invalid email format' },
        { status: 400 }
      );
    }

    // Call Platform Login API
    const loginResponse = await fetch(`${ZALT_API_URL}/platform/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email,
        password,
      }),
    });

    const loginData = await loginResponse.json();

    if (!loginResponse.ok) {
      // Handle specific error codes
      if (loginResponse.status === 429) {
        return NextResponse.json(
          { error: 'Too many login attempts. Please try again later.' },
          { status: 429 }
        );
      }
      if (loginResponse.status === 401) {
        return NextResponse.json(
          { error: 'Invalid email or password' },
          { status: 401 }
        );
      }
      if (loginResponse.status === 423) {
        return NextResponse.json(
          { error: loginData.error?.message || 'Account is temporarily locked' },
          { status: 423 }
        );
      }
      if (loginResponse.status === 403) {
        return NextResponse.json(
          { error: loginData.error?.message || 'Account is suspended' },
          { status: 403 }
        );
      }
      return NextResponse.json(
        { error: loginData.error?.message || 'Login failed' },
        { status: loginResponse.status }
      );
    }

    // Success - set cookies and return customer info
    const response = NextResponse.json({
      success: true,
      customer: loginData.customer,
    });

    // Set access token cookie
    if (loginData.tokens?.access_token) {
      response.cookies.set('zalt_access_token', loginData.tokens.access_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: loginData.tokens.expires_in || 900,
        path: '/',
      });
    }

    // Set refresh token cookie
    if (loginData.tokens?.refresh_token) {
      response.cookies.set('zalt_refresh_token', loginData.tokens.refresh_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60,
        path: '/',
      });
    }

    // Set customer ID cookie
    if (loginData.customer?.id) {
      response.cookies.set('zalt_customer_id', loginData.customer.id, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60,
        path: '/',
      });
    }

    return response;

  } catch (error) {
    console.error('Login error:', error);
    return NextResponse.json(
      { error: 'An error occurred during login. Please try again.' },
      { status: 500 }
    );
  }
}
