'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  CreditCard, Check, Zap, Building2, Shield, 
  TrendingUp, Download, Calendar, AlertCircle, ExternalLink
} from 'lucide-react';

interface Plan {
  id: string;
  name: string;
  price: number;
  interval: 'month' | 'year';
  features: string[];
  limits: {
    mau: number;
    organizations: number;
    sso: boolean;
    support: string;
  };
  popular?: boolean;
}

interface Subscription {
  id: string;
  planId: string;
  status: 'active' | 'canceled' | 'past_due';
  currentPeriodEnd: string;
  cancelAtPeriodEnd: boolean;
}

interface Invoice {
  id: string;
  amount: number;
  status: 'paid' | 'pending' | 'failed';
  date: string;
  pdfUrl: string;
}

interface Usage {
  mau: number;
  mauLimit: number;
  apiCalls: number;
  apiCallsLimit: number;
  storage: number;
  storageLimit: number;
}

const plans: Plan[] = [
  {
    id: 'free',
    name: 'Free',
    price: 0,
    interval: 'month',
    features: [
      'Up to 1,000 MAU',
      'Basic authentication',
      'Email/password login',
      'Community support',
    ],
    limits: { mau: 1000, organizations: 1, sso: false, support: 'Community' },
  },
  {
    id: 'pro',
    name: 'Pro',
    price: 25,
    interval: 'month',
    features: [
      'Up to 10,000 MAU',
      'Social login (Google, Apple)',
      'MFA (TOTP, WebAuthn)',
      'Custom branding',
      'Webhooks',
      'Email support',
    ],
    limits: { mau: 10000, organizations: 5, sso: false, support: 'Email' },
    popular: true,
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    price: 99,
    interval: 'month',
    features: [
      'Unlimited MAU',
      'SAML/OIDC SSO',
      'SCIM provisioning',
      'Custom domains',
      'Audit logs',
      'Data residency',
      'SLA guarantee',
      'Dedicated support',
    ],
    limits: { mau: -1, organizations: -1, sso: true, support: 'Dedicated' },
  },
];

export default function BillingPage() {
  const [subscription, setSubscription] = useState<Subscription | null>(null);
  const [invoices, setInvoices] = useState<Invoice[]>([]);
  const [usage, setUsage] = useState<Usage | null>(null);
  const [loading, setLoading] = useState(true);
  const [billingInterval, setBillingInterval] = useState<'month' | 'year'>('month');

  useEffect(() => {
    fetchBillingData();
  }, []);

  const fetchBillingData = async () => {
    try {
      const [subRes, invRes, usageRes] = await Promise.all([
        fetch('/api/dashboard/billing/subscription'),
        fetch('/api/dashboard/billing/invoices'),
        fetch('/api/dashboard/billing/usage'),
      ]);
      
      if (subRes.ok) {
        const data = await subRes.json();
        setSubscription(data.subscription);
      }
      if (invRes.ok) {
        const data = await invRes.json();
        setInvoices(data.invoices || []);
      }
      if (usageRes.ok) {
        const data = await usageRes.json();
        setUsage(data.usage);
      }
    } catch (error) {
      console.error('Failed to fetch billing data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleUpgrade = async (planId: string) => {
    try {
      const res = await fetch('/api/dashboard/billing/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ planId, interval: billingInterval }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.checkoutUrl) {
          window.location.href = data.checkoutUrl;
        }
      }
    } catch (error) {
      console.error('Failed to create checkout session:', error);
    }
  };

  const handleManageBilling = async () => {
    try {
      const res = await fetch('/api/dashboard/billing/portal', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        if (data.portalUrl) {
          window.location.href = data.portalUrl;
        }
      }
    } catch (error) {
      console.error('Failed to open billing portal:', error);
    }
  };

  const currentPlan = plans.find(p => p.id === subscription?.planId) || plans[0];

  const UsageBar = ({ used, limit, label }: { used: number; limit: number; label: string }) => {
    const percentage = limit === -1 ? 0 : Math.min((used / limit) * 100, 100);
    const isNearLimit = percentage > 80;
    
    return (
      <div>
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm text-neutral-400">{label}</span>
          <span className="text-sm text-white">
            {used.toLocaleString()} / {limit === -1 ? '∞' : limit.toLocaleString()}
          </span>
        </div>
        <div className="h-2 bg-neutral-800 rounded-full overflow-hidden">
          <div 
            className={`h-full rounded-full transition-all ${
              isNearLimit ? 'bg-amber-500' : 'bg-emerald-500'
            }`}
            style={{ width: `${percentage}%` }}
          />
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Billing & Plans</h1>
        <p className="text-neutral-400 mt-1">Manage your subscription and billing information</p>
      </div>

      {/* Current Plan & Usage */}
      <div className="grid lg:grid-cols-2 gap-6">
        {/* Current Plan */}
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
          <div className="flex items-start justify-between mb-6">
            <div>
              <h2 className="text-lg font-semibold text-white">Current Plan</h2>
              <p className="text-neutral-400 text-sm">Your active subscription</p>
            </div>
            {subscription && (
              <span className={`px-3 py-1 rounded-full text-xs font-medium ${
                subscription.status === 'active' ? 'bg-emerald-500/20 text-emerald-400' :
                subscription.status === 'past_due' ? 'bg-amber-500/20 text-amber-400' :
                'bg-red-500/20 text-red-400'
              }`}>
                {subscription.status.replace('_', ' ')}
              </span>
            )}
          </div>
          
          <div className="flex items-center gap-4 mb-6">
            <div className={`w-14 h-14 rounded-xl flex items-center justify-center ${
              currentPlan.id === 'enterprise' ? 'bg-purple-500/20' :
              currentPlan.id === 'pro' ? 'bg-emerald-500/20' : 'bg-neutral-700'
            }`}>
              {currentPlan.id === 'enterprise' ? <Building2 size={24} className="text-purple-400" /> :
               currentPlan.id === 'pro' ? <Zap size={24} className="text-emerald-400" /> :
               <Shield size={24} className="text-neutral-400" />}
            </div>
            <div>
              <h3 className="text-xl font-bold text-white">{currentPlan.name}</h3>
              <p className="text-neutral-400">
                ${currentPlan.price}/{currentPlan.interval}
              </p>
            </div>
          </div>

          {subscription && (
            <div className="space-y-3 mb-6 p-4 bg-neutral-800/50 rounded-lg">
              <div className="flex items-center justify-between text-sm">
                <span className="text-neutral-400">Billing period ends</span>
                <span className="text-white">
                  {new Date(subscription.currentPeriodEnd).toLocaleDateString()}
                </span>
              </div>
              {subscription.cancelAtPeriodEnd && (
                <div className="flex items-center gap-2 text-amber-400 text-sm">
                  <AlertCircle size={14} />
                  <span>Cancels at end of period</span>
                </div>
              )}
            </div>
          )}

          <button
            onClick={handleManageBilling}
            className="w-full flex items-center justify-center gap-2 px-4 py-2 border border-neutral-700 text-neutral-300 rounded-lg hover:bg-neutral-800 transition-colors"
          >
            <CreditCard size={18} />
            Manage Billing
            <ExternalLink size={14} />
          </button>
        </div>

        {/* Usage */}
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-lg font-semibold text-white">Usage</h2>
              <p className="text-neutral-400 text-sm">Current billing period</p>
            </div>
            <TrendingUp size={20} className="text-emerald-500" />
          </div>

          {usage ? (
            <div className="space-y-6">
              <UsageBar 
                used={usage.mau} 
                limit={usage.mauLimit} 
                label="Monthly Active Users" 
              />
              <UsageBar 
                used={usage.apiCalls} 
                limit={usage.apiCallsLimit} 
                label="API Calls" 
              />
              <UsageBar 
                used={usage.storage} 
                limit={usage.storageLimit} 
                label="Storage (MB)" 
              />
            </div>
          ) : (
            <div className="text-center py-8 text-neutral-500">
              Loading usage data...
            </div>
          )}
        </div>
      </div>

      {/* Plans */}
      <div>
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-lg font-semibold text-white">Available Plans</h2>
          <div className="flex items-center gap-2 p-1 bg-neutral-800 rounded-lg">
            <button
              onClick={() => setBillingInterval('month')}
              className={`px-4 py-1.5 rounded text-sm transition-colors ${
                billingInterval === 'month' 
                  ? 'bg-emerald-500 text-neutral-950' 
                  : 'text-neutral-400 hover:text-white'
              }`}
            >
              Monthly
            </button>
            <button
              onClick={() => setBillingInterval('year')}
              className={`px-4 py-1.5 rounded text-sm transition-colors ${
                billingInterval === 'year' 
                  ? 'bg-emerald-500 text-neutral-950' 
                  : 'text-neutral-400 hover:text-white'
              }`}
            >
              Yearly
              <span className="ml-1 text-xs opacity-70">-20%</span>
            </button>
          </div>
        </div>

        <div className="grid md:grid-cols-3 gap-6">
          {plans.map((plan) => {
            const isCurrentPlan = plan.id === currentPlan.id;
            const price = billingInterval === 'year' ? Math.floor(plan.price * 0.8 * 12) : plan.price;
            
            return (
              <motion.div
                key={plan.id}
                whileHover={{ y: -4 }}
                className={`relative bg-neutral-900 border rounded-xl p-6 ${
                  plan.popular 
                    ? 'border-emerald-500/50' 
                    : 'border-emerald-500/10'
                }`}
              >
                {plan.popular && (
                  <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-1 bg-emerald-500 text-neutral-950 text-xs font-medium rounded-full">
                    Most Popular
                  </div>
                )}

                <div className="mb-6">
                  <h3 className="text-xl font-bold text-white">{plan.name}</h3>
                  <div className="mt-2">
                    <span className="text-3xl font-bold text-white">${price}</span>
                    <span className="text-neutral-400">/{billingInterval === 'year' ? 'year' : 'month'}</span>
                  </div>
                </div>

                <ul className="space-y-3 mb-6">
                  {plan.features.map((feature, i) => (
                    <li key={i} className="flex items-start gap-2 text-sm">
                      <Check size={16} className="text-emerald-500 mt-0.5 flex-shrink-0" />
                      <span className="text-neutral-300">{feature}</span>
                    </li>
                  ))}
                </ul>

                <button
                  onClick={() => !isCurrentPlan && handleUpgrade(plan.id)}
                  disabled={isCurrentPlan}
                  className={`w-full py-2.5 rounded-lg font-medium transition-colors ${
                    isCurrentPlan
                      ? 'bg-neutral-800 text-neutral-500 cursor-not-allowed'
                      : plan.popular
                        ? 'bg-emerald-500 text-neutral-950 hover:bg-emerald-400'
                        : 'border border-neutral-700 text-white hover:bg-neutral-800'
                  }`}
                >
                  {isCurrentPlan ? 'Current Plan' : 'Upgrade'}
                </button>
              </motion.div>
            );
          })}
        </div>
      </div>

      {/* Invoices */}
      <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg">
        <div className="p-4 border-b border-emerald-500/10">
          <h2 className="text-lg font-semibold text-white">Invoice History</h2>
        </div>
        {invoices.length === 0 ? (
          <div className="p-8 text-center text-neutral-500">
            No invoices yet
          </div>
        ) : (
          <div className="divide-y divide-emerald-500/10">
            {invoices.map((invoice) => (
              <div key={invoice.id} className="p-4 flex items-center justify-between hover:bg-neutral-800/50">
                <div className="flex items-center gap-4">
                  <div className="w-10 h-10 rounded-lg bg-neutral-800 flex items-center justify-center">
                    <Calendar size={18} className="text-neutral-400" />
                  </div>
                  <div>
                    <p className="text-white font-medium">
                      ${(invoice.amount / 100).toFixed(2)}
                    </p>
                    <p className="text-sm text-neutral-500">
                      {new Date(invoice.date).toLocaleDateString()}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <span className={`px-2 py-1 rounded text-xs ${
                    invoice.status === 'paid' ? 'bg-emerald-500/20 text-emerald-400' :
                    invoice.status === 'pending' ? 'bg-amber-500/20 text-amber-400' :
                    'bg-red-500/20 text-red-400'
                  }`}>
                    {invoice.status}
                  </span>
                  <a
                    href={invoice.pdfUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-2 text-neutral-400 hover:text-white hover:bg-neutral-800 rounded-lg"
                  >
                    <Download size={18} />
                  </a>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
