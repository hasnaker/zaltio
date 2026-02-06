import { NextRequest, NextResponse } from 'next/server';
import { stripe } from '@/lib/stripe';
import Stripe from 'stripe';

// Stripe webhook secret - set in environment
const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

// POST /api/webhooks/stripe - Handle Stripe webhook events
export async function POST(request: NextRequest) {
  if (!stripe || !webhookSecret) {
    console.warn('Stripe webhook not configured');
    return NextResponse.json({ error: 'Webhook not configured' }, { status: 503 });
  }

  const body = await request.text();
  const signature = request.headers.get('stripe-signature');

  if (!signature) {
    return NextResponse.json({ error: 'Missing signature' }, { status: 400 });
  }

  let event: Stripe.Event;

  try {
    event = stripe.webhooks.constructEvent(body, signature, webhookSecret);
  } catch (err) {
    console.error('Webhook signature verification failed:', err);
    return NextResponse.json({ error: 'Invalid signature' }, { status: 400 });
  }

  // Handle the event
  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object as Stripe.Checkout.Session;
        await handleCheckoutCompleted(session);
        break;
      }

      case 'customer.subscription.created':
      case 'customer.subscription.updated': {
        const subscription = event.data.object as Stripe.Subscription;
        await handleSubscriptionUpdated(subscription);
        break;
      }

      case 'customer.subscription.deleted': {
        const subscription = event.data.object as Stripe.Subscription;
        await handleSubscriptionDeleted(subscription);
        break;
      }

      case 'invoice.payment_succeeded': {
        const invoice = event.data.object as Stripe.Invoice;
        await handlePaymentSucceeded(invoice);
        break;
      }

      case 'invoice.payment_failed': {
        const invoice = event.data.object as Stripe.Invoice;
        await handlePaymentFailed(invoice);
        break;
      }

      default:
        console.log(`Unhandled event type: ${event.type}`);
    }

    return NextResponse.json({ received: true });
  } catch (error) {
    console.error('Webhook handler error:', error);
    return NextResponse.json({ error: 'Webhook handler failed' }, { status: 500 });
  }
}

// Handler functions - implement these when DB is ready

async function handleCheckoutCompleted(session: Stripe.Checkout.Session) {
  const userId = session.metadata?.zaltUserId;
  const planId = session.metadata?.planId;
  const customerId = session.customer as string;
  const subscriptionId = session.subscription as string;

  console.log('Checkout completed:', { userId, planId, customerId, subscriptionId });

  // TODO: Update user in DB with:
  // - stripeCustomerId: customerId
  // - stripeSubscriptionId: subscriptionId
  // - plan: planId
  // - subscriptionStatus: 'active'
}

async function handleSubscriptionUpdated(subscription: Stripe.Subscription) {
  const userId = subscription.metadata?.zaltUserId;
  const status = subscription.status;
  const currentPeriodEnd = new Date(subscription.current_period_end * 1000);

  console.log('Subscription updated:', { userId, status, currentPeriodEnd });

  // TODO: Update user subscription status in DB
}

async function handleSubscriptionDeleted(subscription: Stripe.Subscription) {
  const userId = subscription.metadata?.zaltUserId;

  console.log('Subscription deleted:', { userId });

  // TODO: Downgrade user to free plan in DB
}

async function handlePaymentSucceeded(invoice: Stripe.Invoice) {
  const customerId = invoice.customer as string;

  console.log('Payment succeeded:', { customerId, amount: invoice.amount_paid });

  // TODO: Log payment in audit trail
}

async function handlePaymentFailed(invoice: Stripe.Invoice) {
  const customerId = invoice.customer as string;

  console.log('Payment failed:', { customerId });

  // TODO: 
  // - Update subscription status to 'past_due'
  // - Send notification email to user
}
