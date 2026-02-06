/**
 * Stripe Webhook Handler
 * Handles Stripe events for subscription management
 * 
 * Events handled:
 * - checkout.session.completed → Upgrade plan
 * - invoice.paid → Record payment
 * - customer.subscription.updated → Update plan
 * - customer.subscription.deleted → Downgrade to free
 * 
 * Validates: Requirements 8.4, 8.5
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import Stripe from 'stripe';
import { 
  getCustomerById, 
  updateCustomerBilling,
  getCustomerByStripeId 
} from '../../repositories/customer.repository';
import { logSecurityEvent } from '../../services/security-logger.service';

// Initialize Stripe
const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2025-02-24.acacia' as Stripe.LatestApiVersion })
  : null;

const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';

// Plan limits
const PLAN_LIMITS = {
  free: { max_mau: 1000, max_api_calls: 10000, max_realms: 1 },
  pro: { max_mau: 10000, max_api_calls: 100000, max_realms: 5 },
  enterprise: { max_mau: 100000, max_api_calls: 1000000, max_realms: 50 },
};

function createResponse(statusCode: number, body: unknown): APIGatewayProxyResult {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  };
}

/**
 * Handle checkout.session.completed
 * Customer completed checkout - upgrade their plan
 */
async function handleCheckoutCompleted(session: Stripe.Checkout.Session): Promise<void> {
  const customerId = session.metadata?.zalt_customer_id;
  const plan = session.metadata?.plan as 'pro' | 'enterprise';

  if (!customerId || !plan) {
    console.error('Missing metadata in checkout session:', session.id);
    return;
  }

  const customer = await getCustomerById(customerId);
  if (!customer) {
    console.error('Customer not found:', customerId);
    return;
  }

  // Update customer billing
  await updateCustomerBilling(customerId, {
    plan,
    stripe_customer_id: session.customer as string,
    stripe_subscription_id: session.subscription as string,
    plan_started_at: new Date().toISOString(),
  });

  // Update usage limits
  await updateCustomerBilling(customerId, {
    ...PLAN_LIMITS[plan],
  });

  await logSecurityEvent({
    event_type: 'plan_upgraded',
    ip_address: 'webhook',
    user_id: customerId,
    details: { 
      plan, 
      session_id: session.id,
      subscription_id: session.subscription,
    },
  });

  console.log(`Customer ${customerId} upgraded to ${plan}`);
}

/**
 * Handle invoice.paid
 * Record successful payment
 */
async function handleInvoicePaid(invoice: Stripe.Invoice): Promise<void> {
  const stripeCustomerId = invoice.customer as string;
  
  const customer = await getCustomerByStripeId(stripeCustomerId);
  if (!customer) {
    console.error('Customer not found for Stripe ID:', stripeCustomerId);
    return;
  }

  await logSecurityEvent({
    event_type: 'payment_received',
    ip_address: 'webhook',
    user_id: customer.id,
    details: {
      invoice_id: invoice.id,
      amount: invoice.amount_paid,
      currency: invoice.currency,
    },
  });

  console.log(`Payment received for customer ${customer.id}: ${invoice.amount_paid} ${invoice.currency}`);
}

/**
 * Handle customer.subscription.updated
 * Subscription changed (upgrade/downgrade/cancel)
 */
async function handleSubscriptionUpdated(subscription: Stripe.Subscription): Promise<void> {
  const stripeCustomerId = subscription.customer as string;
  const plan = subscription.metadata?.plan as 'pro' | 'enterprise' | undefined;

  const customer = await getCustomerByStripeId(stripeCustomerId);
  if (!customer) {
    console.error('Customer not found for Stripe ID:', stripeCustomerId);
    return;
  }

  // Update subscription status
  await updateCustomerBilling(customer.id, {
    stripe_subscription_id: subscription.id,
    plan_expires_at: subscription.cancel_at
      ? new Date(subscription.cancel_at * 1000).toISOString()
      : undefined,
  });

  // If plan changed, update limits
  if (plan && plan !== customer.billing.plan) {
    await updateCustomerBilling(customer.id, {
      plan,
      ...PLAN_LIMITS[plan],
    });

    await logSecurityEvent({
      event_type: 'plan_changed',
      ip_address: 'webhook',
      user_id: customer.id,
      details: {
        old_plan: customer.billing.plan,
        new_plan: plan,
        subscription_id: subscription.id,
      },
    });
  }

  console.log(`Subscription updated for customer ${customer.id}`);
}

/**
 * Handle customer.subscription.deleted
 * Subscription canceled - downgrade to free
 */
async function handleSubscriptionDeleted(subscription: Stripe.Subscription): Promise<void> {
  const stripeCustomerId = subscription.customer as string;

  const customer = await getCustomerByStripeId(stripeCustomerId);
  if (!customer) {
    console.error('Customer not found for Stripe ID:', stripeCustomerId);
    return;
  }

  // Downgrade to free plan
  await updateCustomerBilling(customer.id, {
    plan: 'free',
    stripe_subscription_id: undefined,
    plan_expires_at: undefined,
    ...PLAN_LIMITS.free,
  });

  await logSecurityEvent({
    event_type: 'plan_downgraded',
    ip_address: 'webhook',
    user_id: customer.id,
    details: {
      old_plan: customer.billing.plan,
      new_plan: 'free',
      reason: 'subscription_deleted',
    },
  });

  console.log(`Customer ${customer.id} downgraded to free plan`);
}

/**
 * Main webhook handler
 */
export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  if (!stripe) {
    return createResponse(503, { error: 'Stripe not configured' });
  }

  if (!WEBHOOK_SECRET) {
    return createResponse(503, { error: 'Webhook secret not configured' });
  }

  // Verify webhook signature
  const signature = event.headers['Stripe-Signature'] || event.headers['stripe-signature'];
  if (!signature) {
    return createResponse(400, { error: 'Missing signature' });
  }

  let stripeEvent: Stripe.Event;
  try {
    stripeEvent = stripe.webhooks.constructEvent(
      event.body || '',
      signature,
      WEBHOOK_SECRET
    );
  } catch (error) {
    console.error('Webhook signature verification failed:', error);
    return createResponse(400, { error: 'Invalid signature' });
  }

  console.log(`Received Stripe event: ${stripeEvent.type}`);

  try {
    switch (stripeEvent.type) {
      case 'checkout.session.completed':
        await handleCheckoutCompleted(stripeEvent.data.object as Stripe.Checkout.Session);
        break;

      case 'invoice.paid':
        await handleInvoicePaid(stripeEvent.data.object as Stripe.Invoice);
        break;

      case 'customer.subscription.updated':
        await handleSubscriptionUpdated(stripeEvent.data.object as Stripe.Subscription);
        break;

      case 'customer.subscription.deleted':
        await handleSubscriptionDeleted(stripeEvent.data.object as Stripe.Subscription);
        break;

      default:
        console.log(`Unhandled event type: ${stripeEvent.type}`);
    }

    return createResponse(200, { received: true });
  } catch (error) {
    console.error('Webhook handler error:', error);
    return createResponse(500, { error: 'Webhook processing failed' });
  }
}
