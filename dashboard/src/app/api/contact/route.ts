import { NextRequest, NextResponse } from 'next/server';

// Simple in-memory rate limiting (in production, use Redis)
const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT = 5; // 5 requests
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute

function getRateLimitKey(request: NextRequest): string {
  const forwarded = request.headers.get('x-forwarded-for');
  const ip = forwarded ? forwarded.split(',')[0] : 'unknown';
  return `contact:${ip}`;
}

function checkRateLimit(key: string): { allowed: boolean; remaining: number } {
  const now = Date.now();
  const record = rateLimitMap.get(key);

  if (!record || now > record.resetTime) {
    rateLimitMap.set(key, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return { allowed: true, remaining: RATE_LIMIT - 1 };
  }

  if (record.count >= RATE_LIMIT) {
    return { allowed: false, remaining: 0 };
  }

  record.count++;
  return { allowed: true, remaining: RATE_LIMIT - record.count };
}

interface ContactFormData {
  name: string;
  email: string;
  company: string;
  message: string;
}

function validateEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

function validateFormData(data: unknown): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  if (!data || typeof data !== 'object') {
    return { valid: false, errors: ['Invalid request body'] };
  }

  const formData = data as Partial<ContactFormData>;

  if (!formData.name || typeof formData.name !== 'string' || !formData.name.trim()) {
    errors.push('Name is required');
  }

  if (!formData.email || typeof formData.email !== 'string' || !formData.email.trim()) {
    errors.push('Email is required');
  } else if (!validateEmail(formData.email)) {
    errors.push('Invalid email format');
  }

  if (!formData.company || typeof formData.company !== 'string' || !formData.company.trim()) {
    errors.push('Company is required');
  }

  if (!formData.message || typeof formData.message !== 'string' || !formData.message.trim()) {
    errors.push('Message is required');
  } else if (formData.message.trim().length < 10) {
    errors.push('Message must be at least 10 characters');
  }

  return { valid: errors.length === 0, errors };
}

export async function POST(request: NextRequest) {
  // Rate limiting
  const rateLimitKey = getRateLimitKey(request);
  const { allowed, remaining } = checkRateLimit(rateLimitKey);

  if (!allowed) {
    return NextResponse.json(
      { error: 'Too many requests. Please try again later.' },
      { 
        status: 429,
        headers: {
          'X-RateLimit-Limit': RATE_LIMIT.toString(),
          'X-RateLimit-Remaining': '0',
          'Retry-After': '60',
        },
      }
    );
  }

  try {
    const body = await request.json();
    
    // Validate form data
    const validation = validateFormData(body);
    if (!validation.valid) {
      return NextResponse.json(
        { error: 'Validation failed', details: validation.errors },
        { status: 400 }
      );
    }

    const formData = body as ContactFormData;

    // In production, you would:
    // 1. Send email via AWS SES
    // 2. Store in database
    // 3. Send to CRM (HubSpot, Salesforce, etc.)
    // 4. Send Slack notification
    
    // For now, just log (in production, use proper logging)
    console.log('Contact form submission:', {
      name: formData.name,
      email: formData.email,
      company: formData.company,
      messageLength: formData.message.length,
      timestamp: new Date().toISOString(),
    });

    return NextResponse.json(
      { success: true, message: 'Message received' },
      { 
        status: 200,
        headers: {
          'X-RateLimit-Limit': RATE_LIMIT.toString(),
          'X-RateLimit-Remaining': remaining.toString(),
        },
      }
    );
  } catch {
    return NextResponse.json(
      { error: 'Invalid request body' },
      { status: 400 }
    );
  }
}
