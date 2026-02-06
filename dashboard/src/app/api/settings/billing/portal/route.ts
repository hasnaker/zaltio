import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { isStripeConfigured, createPortalSession } from '@/lib/stripe';

// POST /api/settings/billing/portal - Create Stripe customer portal session
export async function POST(request: NextRequest) {
  try {
    const cookieStore = await cookies();
    const sessionToken = cookieStore.get('zalt_session')?.value;

    if (!sessionToken) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Check if Stripe is configured
    if (!isStripeConfigured()) {
      return NextResponse.json({ 
        error: 'Billing system will be available soon',
        message: 'Stripe integration pending activation',
        comingSoon: true,
      }, { status: 503 });
    }

    // TODO: Get user's Stripe customer ID from DB
    const stripeCustomerId = null; // Replace with actual customer ID

    if (!stripeCustomerId) {
      return NextResponse.json({ 
        error: 'No billing account found',
        message: 'Please subscribe to a plan first',
      }, { status: 400 });
    }

    const baseUrl = process.env.NEXT_PUBLIC_APP_URL || 'https://zalt.io';
    const session = await createPortalSession({
      customerId: stripeCustomerId,
      returnUrl: `${baseUrl}/dashboard/settings`,
    });

    if (!session) {
      return NextResponse.json({ error: 'Failed to create portal session' }, { status: 500 });
    }

    return NextResponse.json({ url: session.url });
  } catch (error) {
    console.error('Portal error:', error);
    return NextResponse.json({ error: 'Portal access failed' }, { status: 500 });
  }
}
