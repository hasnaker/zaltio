/**
 * Signup API Route for Zalt.io Dashboard
 * Creates new customer accounts via Platform API
 * 
 * Flow:
 * 1. Validate input
 * 2. Call POST /platform/register
 * 3. Receive customer, realm, and API keys
 * 4. Set session cookies
 */

import { NextRequest, NextResponse } from 'next/server';

const ZALT_API_URL = process.env.NEXT_PUBLIC_ZALT_API_URL || 'https://api.zalt.io';

// Rate limiting - simple in-memory store (use Redis in production)
const signupAttempts = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const attempt = signupAttempts.get(ip);
  
  if (!attempt || now > attempt.resetAt) {
    signupAttempts.set(ip, { count: 1, resetAt: now + 3600000 }); // 1 hour
    return true;
  }
  
  if (attempt.count >= 3) {
    return false;
  }
  
  attempt.count++;
  return true;
}

function validateEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

function validatePassword(password: string): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  if (password.length < 8) {
    errors.push('Password must be at least 8 characters');
  }
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  if (!/[0-9]/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  
  return { valid: errors.length === 0, errors };
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
        { error: 'Too many signup attempts. Please try again later.' },
        { status: 429 }
      );
    }

    const body = await request.json();
    const { email, password, name, company, plan } = body;

    // Validate required fields
    if (!email || !password || !company) {
      return NextResponse.json(
        { error: 'Email, password, and company name are required' },
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

    // Validate password strength
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
      return NextResponse.json(
        { error: 'Password does not meet requirements', details: passwordValidation.errors },
        { status: 400 }
      );
    }

    // Call Platform Register API
    const registerResponse = await fetch(`${ZALT_API_URL}/platform/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email,
        password,
        company_name: company,
        plan: plan || 'free',
      }),
    });

    const registerData = await registerResponse.json();

    if (!registerResponse.ok) {
      // Handle specific error codes
      if (registerResponse.status === 409) {
        return NextResponse.json(
          { error: 'An account with this email already exists' },
          { status: 409 }
        );
      }
      if (registerResponse.status === 429) {
        return NextResponse.json(
          { error: 'Too many signup attempts. Please try again later.' },
          { status: 429 }
        );
      }
      return NextResponse.json(
        { error: registerData.error?.message || 'Registration failed' },
        { status: registerResponse.status }
      );
    }

    // Success - set cookies and return customer info
    const response = NextResponse.json({
      success: true,
      message: 'Account created successfully!',
      customer: registerData.customer,
      realm: registerData.realm,
      api_keys: {
        publishable_key: registerData.api_keys?.publishable_key,
        // Don't expose secret key in response - shown only once in dashboard
        has_secret_key: !!registerData.api_keys?.secret_key,
      },
      nextSteps: [
        'Check your email to verify your account',
        'Get your API keys from Settings > API Keys',
        'Follow the Quick Start guide to integrate Zalt',
      ],
    }, { status: 201 });

    // Set access token cookie
    if (registerData.tokens?.access_token) {
      response.cookies.set('zalt_access_token', registerData.tokens.access_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: registerData.tokens.expires_in || 900,
        path: '/',
      });
    }

    // Set refresh token cookie
    if (registerData.tokens?.refresh_token) {
      response.cookies.set('zalt_refresh_token', registerData.tokens.refresh_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60,
        path: '/',
      });
    }

    // Set customer ID cookie
    if (registerData.customer?.id) {
      response.cookies.set('zalt_customer_id', registerData.customer.id, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60,
        path: '/',
      });
    }

    return response;

  } catch (error) {
    console.error('Signup error:', error);
    return NextResponse.json(
      { error: 'An error occurred during signup. Please try again.' },
      { status: 500 }
    );
  }
}
