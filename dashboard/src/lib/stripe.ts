import Stripe from 'stripe';

// Stripe will be initialized when STRIPE_SECRET_KEY is available
// For now, create a placeholder that checks for the key
const stripeSecretKey = process.env.STRIPE_SECRET_KEY;

export const stripe = stripeSecretKey 
  ? new Stripe(stripeSecretKey, { apiVersion: '2025-02-24.acacia' })
  : null;

// Price IDs - will be set after Stripe account activation
export const PRICE_IDS = {
  free: null, // Free tier, no Stripe price
  pro: process.env.STRIPE_PRICE_PRO || 'price_pro_placeholder',
  enterprise: process.env.STRIPE_PRICE_ENTERPRISE || 'price_enterprise_placeholder',
} as const;

// Product configuration
export const PLANS = {
  free: {
    name: 'Free',
    price: 0,
    mauLimit: 1000,
    realmsLimit: 1,
    features: ['1,000 MAU', '1 Realm', 'Email Support', 'Basic Analytics'],
  },
  pro: {
    name: 'Pro',
    price: 49,
    mauLimit: 10000,
    realmsLimit: 5,
    features: ['10,000 MAU', '5 Realms', 'Priority Support', 'Advanced Analytics', 'Custom Branding', 'Webhooks'],
  },
  enterprise: {
    name: 'Enterprise',
    price: 299,
    mauLimit: -1, // Unlimited
    realmsLimit: -1, // Unlimited
    features: ['Unlimited MAU', 'Unlimited Realms', 'Dedicated Support', 'SLA 99.99%', 'SSO/SAML', 'Custom Contracts'],
  },
} as const;

export type PlanId = keyof typeof PLANS;

// Helper to check if Stripe is configured
export function isStripeConfigured(): boolean {
  return !!stripe;
}

// Create checkout session
export async function createCheckoutSession(params: {
  customerId?: string;
  customerEmail: string;
  priceId: string;
  successUrl: string;
  cancelUrl: string;
  metadata?: Record<string, string>;
}): Promise<Stripe.Checkout.Session | null> {
  if (!stripe) {
    console.warn('Stripe not configured');
    return null;
  }

  return stripe.checkout.sessions.create({
    mode: 'subscription',
    customer: params.customerId,
    customer_email: params.customerId ? undefined : params.customerEmail,
    line_items: [{ price: params.priceId, quantity: 1 }],
    success_url: params.successUrl,
    cancel_url: params.cancelUrl,
    metadata: params.metadata,
    subscription_data: {
      metadata: params.metadata,
    },
  });
}

// Create customer portal session
export async function createPortalSession(params: {
  customerId: string;
  returnUrl: string;
}): Promise<Stripe.BillingPortal.Session | null> {
  if (!stripe) {
    console.warn('Stripe not configured');
    return null;
  }

  return stripe.billingPortal.sessions.create({
    customer: params.customerId,
    return_url: params.returnUrl,
  });
}

// Get or create Stripe customer
export async function getOrCreateCustomer(params: {
  email: string;
  name?: string;
  metadata?: Record<string, string>;
}): Promise<Stripe.Customer | null> {
  if (!stripe) return null;

  // Search for existing customer
  const existing = await stripe.customers.list({
    email: params.email,
    limit: 1,
  });

  if (existing.data.length > 0) {
    return existing.data[0];
  }

  // Create new customer
  return stripe.customers.create({
    email: params.email,
    name: params.name,
    metadata: params.metadata,
  });
}

// Get subscription details
export async function getSubscription(subscriptionId: string): Promise<Stripe.Subscription | null> {
  if (!stripe) return null;
  
  try {
    return await stripe.subscriptions.retrieve(subscriptionId);
  } catch {
    return null;
  }
}

// Cancel subscription
export async function cancelSubscription(subscriptionId: string): Promise<Stripe.Subscription | null> {
  if (!stripe) return null;

  return stripe.subscriptions.update(subscriptionId, {
    cancel_at_period_end: true,
  });
}
