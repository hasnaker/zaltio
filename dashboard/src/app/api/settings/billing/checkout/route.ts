import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { 
  stripe, 
  isStripeConfigured, 
  PRICE_IDS, 
  createCheckoutSession,
  getOrCreateCustomer,
  PlanId 
} from '@/lib/stripe';

// POST /api/settings/billing/checkout - Create Stripe checkout session
export async function POST(request: NextRequest) {
  try {
    const cookieStore = await cookies();
    const sessionToken = cookieStore.get('zalt_session')?.value;

    if (!sessionToken) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { planId } = await request.json() as { planId: PlanId };

    if (!planId || !['free', 'pro', 'enterprise'].includes(planId)) {
      return NextResponse.json({ error: 'Invalid plan' }, { status: 400 });
    }

    // Free plan doesn't need checkout
    if (planId === 'free') {
      // TODO: Downgrade user to free plan in DB
      return NextResponse.json({ success: true, message: 'Downgraded to free plan' });
    }

    // Check if Stripe is configured
    if (!isStripeConfigured()) {
      // Stripe not active yet - return placeholder response
      return NextResponse.json({ 
        error: 'Billing system will be available soon',
        message: 'Stripe integration pending activation',
        comingSoon: true,
      }, { status: 503 });
    }

    // TODO: Get user email from session
    const userEmail = 'user@example.com'; // Replace with actual user email
    const userId = 'user_123'; // Replace with actual user ID

    // Get or create Stripe customer
    const customer = await getOrCreateCustomer({
      email: userEmail,
      metadata: { zaltUserId: userId },
    });

    if (!customer) {
      return NextResponse.json({ error: 'Failed to create customer' }, { status: 500 });
    }

    // Get price ID for the plan
    const priceId = PRICE_IDS[planId];
    if (!priceId) {
      return NextResponse.json({ error: 'Price not configured' }, { status: 500 });
    }

    // Create checkout session
    const baseUrl = process.env.NEXT_PUBLIC_APP_URL || 'https://zalt.io';
    const session = await createCheckoutSession({
      customerId: customer.id,
      customerEmail: userEmail,
      priceId,
      successUrl: `${baseUrl}/dashboard/settings?billing=success`,
      cancelUrl: `${baseUrl}/dashboard/settings?billing=canceled`,
      metadata: {
        zaltUserId: userId,
        planId,
      },
    });

    if (!session) {
      return NextResponse.json({ error: 'Failed to create checkout session' }, { status: 500 });
    }

    return NextResponse.json({ url: session.url });
  } catch (error) {
    console.error('Checkout error:', error);
    return NextResponse.json({ error: 'Checkout failed' }, { status: 500 });
  }
}
