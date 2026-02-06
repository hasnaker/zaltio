'use client';

import React, { useState, useMemo } from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import { cn } from '@/lib/utils';
import { Calculator, TrendingUp, Check } from 'lucide-react';

export interface PricingCalculatorProps {
  /** Initial MAU value */
  initialMAU?: number;
  /** Billing period */
  billingPeriod?: 'monthly' | 'annual';
  /** Callback when MAU changes */
  onMAUChange?: (mau: number) => void;
  /** Additional CSS classes */
  className?: string;
  /** Test ID for testing */
  'data-testid'?: string;
}

// Pricing tiers configuration
const pricingTiers = {
  free: {
    name: 'Free',
    maxMAU: 1000,
    monthlyPrice: 0,
    pricePerMAU: 0,
  },
  pro: {
    name: 'Pro',
    maxMAU: 50000,
    monthlyPrice: 25,
    pricePerMAU: 0.02, // $0.02 per MAU after base
    baseMAU: 5000,
  },
  enterprise: {
    name: 'Enterprise',
    maxMAU: Infinity,
    monthlyPrice: 'Custom',
    pricePerMAU: 0.015, // Volume discount
    baseMAU: 50000,
  },
};

/**
 * Calculate monthly cost based on MAU
 */
export function calculateMonthlyCost(mau: number): { tier: string; cost: number | 'Custom'; breakdown: string } {
  if (mau <= pricingTiers.free.maxMAU) {
    return {
      tier: 'Free',
      cost: 0,
      breakdown: `${mau.toLocaleString()} MAU included free`,
    };
  }
  
  if (mau <= pricingTiers.pro.maxMAU) {
    const basePrice = pricingTiers.pro.monthlyPrice;
    const extraMAU = Math.max(0, mau - pricingTiers.pro.baseMAU);
    const extraCost = extraMAU * pricingTiers.pro.pricePerMAU;
    const totalCost = basePrice + extraCost;
    
    return {
      tier: 'Pro',
      cost: Math.round(totalCost * 100) / 100,
      breakdown: `$${basePrice} base + ${extraMAU.toLocaleString()} extra MAU × $${pricingTiers.pro.pricePerMAU}`,
    };
  }
  
  return {
    tier: 'Enterprise',
    cost: 'Custom',
    breakdown: 'Contact sales for volume pricing',
  };
}

/**
 * Calculate annual cost with 20% discount
 */
export function calculateAnnualCost(monthlyCost: number | 'Custom'): number | 'Custom' {
  if (monthlyCost === 'Custom') return 'Custom';
  return Math.round(monthlyCost * 12 * 0.8 * 100) / 100; // 20% discount
}

/**
 * Pricing Calculator Component
 * Interactive calculator for estimating monthly/annual costs based on MAU
 */
export function PricingCalculator({
  initialMAU = 5000,
  billingPeriod = 'monthly',
  onMAUChange,
  className,
  'data-testid': testId = 'pricing-calculator',
}: PricingCalculatorProps) {
  const [mau, setMAU] = useState(initialMAU);
  const [period, setPeriod] = useState<'monthly' | 'annual'>(billingPeriod);
  const shouldReduceMotion = useReducedMotion();
  const reducedMotion = shouldReduceMotion ?? false;

  // Calculate pricing
  const pricing = useMemo(() => calculateMonthlyCost(mau), [mau]);
  const annualCost = useMemo(() => calculateAnnualCost(pricing.cost), [pricing.cost]);

  const handleMAUChange = (value: number) => {
    setMAU(value);
    onMAUChange?.(value);
  };

  // Slider marks
  const sliderMarks = [1000, 5000, 10000, 25000, 50000, 100000];

  return (
    <div
      className={cn(
        'p-6 rounded-2xl bg-white dark:bg-neutral-800 border border-neutral-200 dark:border-neutral-700 shadow-sm',
        className
      )}
      data-testid={testId}
    >
      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 rounded-xl bg-primary/10 flex items-center justify-center">
          <Calculator className="w-5 h-5 text-primary" />
        </div>
        <div>
          <h3 className="font-semibold text-neutral-900 dark:text-white">
            Pricing Calculator
          </h3>
          <p className="text-sm text-neutral-500">
            Estimate your monthly costs
          </p>
        </div>
      </div>

      {/* MAU Input */}
      <div className="mb-6">
        <label className="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-2">
          Monthly Active Users (MAU)
        </label>
        <div className="flex items-center gap-4">
          <input
            type="range"
            min={100}
            max={100000}
            step={100}
            value={mau}
            onChange={(e) => handleMAUChange(Number(e.target.value))}
            className="flex-1 h-2 bg-neutral-200 dark:bg-neutral-700 rounded-lg appearance-none cursor-pointer accent-primary"
            aria-label="Monthly Active Users slider"
            data-testid="mau-slider"
          />
          <input
            type="number"
            min={100}
            max={1000000}
            value={mau}
            onChange={(e) => handleMAUChange(Number(e.target.value))}
            className="w-28 px-3 py-2 rounded-lg border border-neutral-300 dark:border-neutral-600 bg-white dark:bg-neutral-700 text-neutral-900 dark:text-white text-right font-mono"
            aria-label="Monthly Active Users input"
            data-testid="mau-input"
          />
        </div>
        
        {/* Slider marks */}
        <div className="flex justify-between mt-2 text-xs text-neutral-400">
          {sliderMarks.map((mark) => (
            <button
              key={mark}
              onClick={() => handleMAUChange(mark)}
              className="hover:text-primary transition-colors"
            >
              {mark >= 1000 ? `${mark / 1000}K` : mark}
            </button>
          ))}
        </div>
      </div>

      {/* Billing Period Toggle */}
      <div className="flex items-center justify-center gap-2 mb-6">
        <button
          onClick={() => setPeriod('monthly')}
          className={cn(
            'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
            period === 'monthly'
              ? 'bg-primary text-white'
              : 'bg-neutral-100 dark:bg-neutral-700 text-neutral-600 dark:text-neutral-400'
          )}
          data-testid="billing-monthly"
        >
          Monthly
        </button>
        <button
          onClick={() => setPeriod('annual')}
          className={cn(
            'px-4 py-2 rounded-lg text-sm font-medium transition-colors relative',
            period === 'annual'
              ? 'bg-primary text-white'
              : 'bg-neutral-100 dark:bg-neutral-700 text-neutral-600 dark:text-neutral-400'
          )}
          data-testid="billing-annual"
        >
          Annual
          <span className="absolute -top-2 -right-2 px-1.5 py-0.5 rounded-full bg-green-500 text-white text-[10px] font-bold">
            -20%
          </span>
        </button>
      </div>

      {/* Pricing Result */}
      <motion.div
        key={`${mau}-${period}`}
        initial={{ opacity: reducedMotion ? 1 : 0.5, scale: reducedMotion ? 1 : 0.98 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: reducedMotion ? 0 : 0.2 }}
        className="p-4 rounded-xl bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-700"
        data-testid="pricing-result"
      >
        {/* Recommended tier */}
        <div className="flex items-center gap-2 mb-3">
          <span className="px-2 py-0.5 rounded-full bg-primary/10 text-primary text-xs font-medium">
            Recommended: {pricing.tier}
          </span>
        </div>

        {/* Price display */}
        <div className="flex items-baseline gap-2 mb-2">
          {pricing.cost === 'Custom' ? (
            <span className="text-3xl font-bold text-neutral-900 dark:text-white">
              Custom
            </span>
          ) : (
            <>
              <span className="text-3xl font-bold text-neutral-900 dark:text-white">
                ${period === 'monthly' ? pricing.cost.toLocaleString() : (annualCost as number).toLocaleString()}
              </span>
              <span className="text-neutral-500">
                /{period === 'monthly' ? 'month' : 'year'}
              </span>
            </>
          )}
        </div>

        {/* Breakdown */}
        <p className="text-sm text-neutral-500 mb-3">
          {pricing.breakdown}
        </p>

        {/* Savings indicator for annual */}
        {period === 'annual' && pricing.cost !== 'Custom' && (
          <div className="flex items-center gap-2 text-green-600 dark:text-green-400 text-sm">
            <TrendingUp className="w-4 h-4" />
            <span>
              Save ${((pricing.cost as number) * 12 * 0.2).toLocaleString()} per year
            </span>
          </div>
        )}
      </motion.div>

      {/* Features included */}
      <div className="mt-6 pt-6 border-t border-neutral-200 dark:border-neutral-700">
        <p className="text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-3">
          Included in {pricing.tier}:
        </p>
        <div className="grid grid-cols-2 gap-2">
          {getIncludedFeatures(pricing.tier).map((feature) => (
            <div key={feature} className="flex items-center gap-2 text-sm text-neutral-600 dark:text-neutral-400">
              <Check className="w-4 h-4 text-green-500" />
              {feature}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// Get features included in each tier
function getIncludedFeatures(tier: string): string[] {
  const features = {
    Free: ['1,000 MAU', 'Email/Password Auth', 'Social Logins', 'Basic Analytics'],
    Pro: ['50,000 MAU', 'MFA/WebAuthn', 'Custom Branding', 'Webhooks', 'Priority Support'],
    Enterprise: ['Unlimited MAU', 'SSO/SAML', 'Custom SLA', 'Dedicated Support', 'On-premise Option'],
  };
  return features[tier as keyof typeof features] || features.Free;
}

export default PricingCalculator;
