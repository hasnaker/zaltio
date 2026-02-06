/**
 * Billing API Route for Zalt.io Dashboard
 * Uses Platform API for customer billing management
 */

import { NextRequest, NextResponse } from 'next/server';
import { 
  getPlatformBilling, 
  getPlatformUsage,
  createPlatformCheckout,
  getPlatformBillingPortal 
} from '@/lib/zalt-api';
import { PLANS, PlanId } from '@/lib/stripe';

// GET /api/settings/billing - Get current subscription and usage
export async function GET(request: NextRequest) {
  const accessToken = request.cookies.get('zalt_access_token')?.value;

  if (!accessToken) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  try {
    // Fetch billing and usage in parallel
    const [billingResult, usageResult] = await Promise.all([
      getPlatformBilling(accessToken),
      getPlatformUsage(accessToken),
    ]);

    // Handle billing errors gracefully
    const plan = (billingResult.data?.plan || 'free') as PlanId;
    const planConfig = PLANS[plan] || PLANS.free;

    const subscription = {
      plan,
      status: billingResult.data?.status || 'active',
      currentPeriodEnd: billingResult.data?.current_period_end,
      stripeCustomerId: billingResult.data?.stripe_customer_id || null,
      usage: {
        mau: usageResult.data?.usage?.mau || 0,
        mauLimit: usageResult.data?.limits?.max_mau || planConfig.mauLimit,
        apiCalls: usageResult.data?.usage?.api_calls || 0,
        apiCallsLimit: usageResult.data?.limits?.max_api_calls || 10000,
        realms: usageResult.data?.usage?.realms || 0,
        realmsLimit: usageResult.data?.limits?.max_realms || planConfig.realmsLimit,
      },
      period: usageResult.data?.period,
    };

    return NextResponse.json({ subscription });
  } catch (error) {
    console.error('Billing fetch error:', error);
    return NextResponse.json({ error: 'Failed to fetch billing' }, { status: 500 });
  }
}

// POST /api/settings/billing - Create checkout session or portal
export async function POST(request: NextRequest) {
  const accessToken = request.cookies.get('zalt_access_token')?.value;

  if (!accessToken) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  try {
    const body = await request.json();
    const { action, plan } = body as { action: 'checkout' | 'portal'; plan?: 'pro' | 'enterprise' };

    const baseUrl = process.env.NEXT_PUBLIC_APP_URL || 'https://dashboard.zalt.io';

    if (action === 'checkout') {
      if (!plan || !['pro', 'enterprise'].includes(plan)) {
        return NextResponse.json({ error: 'Invalid plan' }, { status: 400 });
      }

      const result = await createPlatformCheckout({
        plan,
        success_url: `${baseUrl}/dashboard/settings/billing?success=true`,
        cancel_url: `${baseUrl}/dashboard/settings/billing?canceled=true`,
      }, accessToken);

      if (result.error) {
        return NextResponse.json({ error: result.error }, { status: result.status });
      }

      return NextResponse.json({ checkoutUrl: result.data?.checkout_url });
    }

    if (action === 'portal') {
      const result = await getPlatformBillingPortal({
        return_url: `${baseUrl}/dashboard/settings/billing`,
      }, accessToken);

      if (result.error) {
        return NextResponse.json({ error: result.error }, { status: result.status });
      }

      return NextResponse.json({ portalUrl: result.data?.portal_url });
    }

    return NextResponse.json({ error: 'Invalid action' }, { status: 400 });
  } catch (error) {
    console.error('Billing action error:', error);
    return NextResponse.json({ error: 'Failed to process billing action' }, { status: 500 });
  }
}
