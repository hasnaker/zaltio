'use client';

import React, { useState, useRef } from 'react';
import Link from 'next/link';
import { motion, useInView } from 'framer-motion';
import { Check, Sparkles, Zap, Building2, ArrowRight, Calculator, Table } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { GradientText } from '@/components/ui/GradientText';
import { cn } from '@/lib/utils';
import { staggerVariants, staggerItemVariants } from '@/lib/motion';
import { PricingCalculator } from './PricingCalculator';
import { FeatureComparisonTable } from './FeatureComparisonTable';

export interface PricingPlan {
  name: string;
  description: string;
  price: {
    monthly: number | 'Custom';
    annual: number | 'Custom';
  };
  features: string[];
  highlighted?: boolean;
  badge?: string;
  cta: string;
  ctaHref: string;
}

export const pricingPlans: PricingPlan[] = [
  {
    name: 'Free',
    description: 'Perfect for side projects and experiments',
    price: { monthly: 0, annual: 0 },
    features: [
      'Up to 5,000 monthly active users',
      'Email/password authentication',
      'Social logins (Google, GitHub)',
      'Basic MFA (TOTP)',
      'Community support',
      'Standard rate limits',
    ],
    cta: 'Start Free',
    ctaHref: '/signup',
  },
  {
    name: 'Pro',
    description: 'For growing teams and production apps',
    price: { monthly: 25, annual: 20 },
    features: [
      'Up to 50,000 monthly active users',
      'Everything in Free, plus:',
      'WebAuthn / Passkeys',
      'Custom branding',
      'Webhooks',
      'Priority email support',
      'Advanced analytics',
      'Custom domains',
    ],
    highlighted: true,
    badge: 'Most Popular',
    cta: 'Start Pro Trial',
    ctaHref: '/signup?plan=pro',
  },
  {
    name: 'Enterprise',
    description: 'For organizations with advanced needs',
    price: { monthly: 'Custom', annual: 'Custom' },
    features: [
      'Unlimited monthly active users',
      'Everything in Pro, plus:',
      'SAML SSO',
      'SCIM provisioning',
      'Dedicated support',
      'SLA guarantee (99.99%)',
      'Custom integrations',
      'Security audit logs',
      'Data residency options',
    ],
    cta: 'Contact Sales',
    ctaHref: '/contact',
  },
];

// Pricing toggle component
function PricingToggle({ 
  isAnnual, 
  onToggle 
}: { 
  isAnnual: boolean; 
  onToggle: () => void;
}) {
  return (
    <div className="flex items-center justify-center gap-4 mb-12">
      <span className={cn(
        'text-sm font-medium transition-colors',
        !isAnnual ? 'text-neutral-900' : 'text-neutral-400'
      )}>
        Monthly
      </span>
      
      <button
        onClick={onToggle}
        className={cn(
          'relative w-14 h-7 rounded-full transition-colors',
          isAnnual ? 'bg-primary' : 'bg-neutral-200'
        )}
      >
        <motion.div
          className="absolute top-1 w-5 h-5 bg-white rounded-full shadow-sm"
          animate={{ left: isAnnual ? '32px' : '4px' }}
          transition={{ type: 'spring', stiffness: 500, damping: 30 }}
        />
      </button>
      
      <span className={cn(
        'text-sm font-medium transition-colors',
        isAnnual ? 'text-neutral-900' : 'text-neutral-400'
      )}>
        Annual
      </span>
      
      <Badge variant="success" size="sm">
        Save 20%
      </Badge>
    </div>
  );
}

// Pricing card component
function PricingCard({ 
  plan, 
  isAnnual,
}: { 
  plan: PricingPlan; 
  isAnnual: boolean;
}) {
  const price = isAnnual ? plan.price.annual : plan.price.monthly;
  const isCustom = price === 'Custom';

  return (
    <motion.div
      variants={staggerItemVariants}
      whileHover={{ y: -8 }}
      transition={{ duration: 0.3 }}
      className={cn(
        'relative rounded-2xl p-8 h-full flex flex-col',
        plan.highlighted 
          ? 'bg-gradient-to-b from-primary/5 to-accent/5 border-2 border-primary/20 shadow-xl shadow-primary/10' 
          : 'bg-white border border-neutral-200'
      )}
    >
      {/* Highlighted badge */}
      {plan.badge && (
        <div className="absolute -top-3 left-1/2 -translate-x-1/2">
          <Badge variant="primary" className="shadow-lg">
            <Sparkles size={12} className="mr-1" />
            {plan.badge}
          </Badge>
        </div>
      )}

      {/* Plan header */}
      <div className="mb-6">
        <h3 className="text-xl font-bold text-neutral-900 mb-2">
          {plan.name}
        </h3>
        <p className="text-sm text-neutral-500">
          {plan.description}
        </p>
      </div>

      {/* Price */}
      <div className="mb-6">
        {isCustom ? (
          <div className="flex items-baseline gap-1">
            <span className="text-4xl font-bold text-neutral-900">Custom</span>
          </div>
        ) : (
          <div className="flex items-baseline gap-1">
            <span className="text-4xl font-bold text-neutral-900">
              ${price}
            </span>
            <span className="text-neutral-500">/month</span>
          </div>
        )}
        {!isCustom && isAnnual && (
          <p className="text-sm text-success mt-1">
            Billed annually (${(price as number) * 12}/year)
          </p>
        )}
      </div>

      {/* CTA Button */}
      <Link href={plan.ctaHref} className="mb-8">
        <Button
          variant={plan.highlighted ? 'gradient' : 'secondary'}
          fullWidth
          size="lg"
          rightIcon={<ArrowRight size={16} />}
        >
          {plan.cta}
        </Button>
      </Link>

      {/* Features */}
      <div className="flex-1">
        <p className="text-sm font-semibold text-neutral-900 mb-4">
          What's included:
        </p>
        <ul className="space-y-3">
          {plan.features.map((feature, i) => (
            <li key={i} className="flex items-start gap-3">
              <Check 
                size={18} 
                className={cn(
                  'flex-shrink-0 mt-0.5',
                  plan.highlighted ? 'text-primary' : 'text-success'
                )} 
              />
              <span className="text-sm text-neutral-600">{feature}</span>
            </li>
          ))}
        </ul>
      </div>
    </motion.div>
  );
}

export function PricingSection() {
  const [isAnnual, setIsAnnual] = useState(true);
  const [showCalculator, setShowCalculator] = useState(false);
  const [showComparison, setShowComparison] = useState(false);
  const ref = useRef<HTMLElement>(null);
  const isInView = useInView(ref, { once: true, margin: '-100px' });

  return (
    <section 
      id="pricing" 
      ref={ref}
      className="py-24 md:py-32 px-6 bg-white relative overflow-hidden"
      data-testid="pricing-section"
    >
      {/* Background decoration */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_50%_at_50%_100%,rgba(108,71,255,0.05),transparent)]" />

      <div className="max-w-7xl mx-auto relative">
        {/* Section header */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={isInView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.6 }}
          className="text-center mb-12"
        >
          <motion.div 
            className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/5 border border-primary/10 mb-6"
            initial={{ opacity: 0, scale: 0.9 }}
            animate={isInView ? { opacity: 1, scale: 1 } : {}}
            transition={{ delay: 0.2 }}
          >
            <Zap size={16} className="text-primary" />
            <span className="text-sm font-medium text-primary">
              Simple, transparent pricing
            </span>
          </motion.div>

          <h2 className="text-4xl md:text-5xl font-bold text-neutral-900 mb-4">
            Start free,{' '}
            <GradientText gradient="primary">
              scale as you grow
            </GradientText>
          </h2>

          <p className="text-lg text-neutral-500 max-w-2xl mx-auto">
            No hidden fees. No credit card required. 
            Upgrade or downgrade anytime.
          </p>
        </motion.div>

        {/* Pricing toggle */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={isInView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.3 }}
        >
          <PricingToggle 
            isAnnual={isAnnual} 
            onToggle={() => setIsAnnual(!isAnnual)} 
          />
        </motion.div>

        {/* Pricing cards - exactly 3 tiers */}
        <motion.div
          initial="hidden"
          animate={isInView ? "visible" : "hidden"}
          variants={staggerVariants}
          className="grid md:grid-cols-3 gap-8"
          data-testid="pricing-tiers"
        >
          {pricingPlans.map((plan) => (
            <PricingCard 
              key={plan.name} 
              plan={plan} 
              isAnnual={isAnnual}
            />
          ))}
        </motion.div>

        {/* Calculator and Comparison Toggle Buttons */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={isInView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.6 }}
          className="mt-12 flex flex-wrap justify-center gap-4"
        >
          <Button
            variant={showCalculator ? 'primary' : 'outline'}
            onClick={() => {
              setShowCalculator(!showCalculator);
              if (!showCalculator) setShowComparison(false);
            }}
            leftIcon={<Calculator size={16} />}
            data-testid="toggle-calculator"
          >
            {showCalculator ? 'Hide Calculator' : 'Estimate Your Cost'}
          </Button>
          <Button
            variant={showComparison ? 'primary' : 'outline'}
            onClick={() => {
              setShowComparison(!showComparison);
              if (!showComparison) setShowCalculator(false);
            }}
            leftIcon={<Table size={16} />}
            data-testid="toggle-comparison"
          >
            {showComparison ? 'Hide Comparison' : 'Compare Features'}
          </Button>
        </motion.div>

        {/* Pricing Calculator */}
        {showCalculator && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.3 }}
            className="mt-8 max-w-xl mx-auto"
          >
            <PricingCalculator 
              billingPeriod={isAnnual ? 'annual' : 'monthly'}
              data-testid="pricing-calculator"
            />
          </motion.div>
        )}

        {/* Feature Comparison Table */}
        {showComparison && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.3 }}
            className="mt-8"
          >
            <FeatureComparisonTable data-testid="feature-comparison" />
          </motion.div>
        )}

        {/* Enterprise CTA */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={isInView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.8 }}
          className="mt-16 text-center"
        >
          <div className="inline-flex items-center gap-4 px-6 py-4 rounded-2xl bg-neutral-50 border border-neutral-100">
            <Building2 size={24} className="text-primary" />
            <div className="text-left">
              <p className="font-semibold text-neutral-900">
                Need a custom solution?
              </p>
              <p className="text-sm text-neutral-500">
                We offer custom plans for large organizations
              </p>
            </div>
            <Link href="/contact">
              <Button variant="outline" size="sm" data-testid="contact-sales-cta">
                Talk to Sales
              </Button>
            </Link>
          </div>
        </motion.div>
      </div>
    </section>
  );
}

export default PricingSection;
