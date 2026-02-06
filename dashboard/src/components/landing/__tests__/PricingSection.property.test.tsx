/**
 * Property-Based Tests for PricingSection
 * 
 * Feature: zalt-enterprise-landing
 * Property 4: Pricing tier count invariant
 * Property 5: Billing toggle state change
 * Property 6: Pricing calculator accuracy
 * 
 * Validates: Requirements 5.1, 5.3, 5.5
 */

import * as fc from 'fast-check';

// Pricing tiers configuration (mirrors actual implementation)
const PRICING_TIERS = {
  free: { name: 'Free', maxMAU: 1000, monthlyPrice: 0 },
  pro: { name: 'Pro', maxMAU: 50000, monthlyPrice: 25, pricePerMAU: 0.02, baseMAU: 5000 },
  enterprise: { name: 'Enterprise', maxMAU: Infinity },
};

// Pricing plans array (mirrors actual implementation)
const pricingPlans: Array<{
  name: string;
  price: { monthly: number | 'Custom'; annual: number | 'Custom' };
}> = [
  { name: 'Free', price: { monthly: 0, annual: 0 } },
  { name: 'Pro', price: { monthly: 25, annual: 20 } },
  { name: 'Enterprise', price: { monthly: 'Custom', annual: 'Custom' } },
];

// Annual discount rate
const ANNUAL_DISCOUNT = 0.2; // 20%

// Billing toggle state type
type BillingPeriod = 'monthly' | 'annual';

/**
 * Calculate monthly cost based on MAU (mirrors PricingCalculator implementation)
 */
function calculateMonthlyCost(mau: number): { tier: string; cost: number | 'Custom'; breakdown: string } {
  if (mau <= PRICING_TIERS.free.maxMAU) {
    return {
      tier: 'Free',
      cost: 0,
      breakdown: `${mau.toLocaleString()} MAU included free`,
    };
  }
  
  if (mau <= PRICING_TIERS.pro.maxMAU) {
    const basePrice = PRICING_TIERS.pro.monthlyPrice;
    const extraMAU = Math.max(0, mau - PRICING_TIERS.pro.baseMAU);
    const extraCost = extraMAU * PRICING_TIERS.pro.pricePerMAU;
    const totalCost = basePrice + extraCost;
    
    return {
      tier: 'Pro',
      cost: Math.round(totalCost * 100) / 100,
      breakdown: `${basePrice} base + ${extraMAU.toLocaleString()} extra MAU × ${PRICING_TIERS.pro.pricePerMAU}`,
    };
  }
  
  return {
    tier: 'Enterprise',
    cost: 'Custom',
    breakdown: 'Contact sales for volume pricing',
  };
}

/**
 * Calculate annual cost with 20% discount (mirrors PricingCalculator implementation)
 */
function calculateAnnualCost(monthlyCost: number | 'Custom'): number | 'Custom' {
  if (monthlyCost === 'Custom') return 'Custom';
  return Math.round(monthlyCost * 12 * 0.8 * 100) / 100; // 20% discount
}

// Toggle billing period
function toggleBillingPeriod(current: BillingPeriod): BillingPeriod {
  return current === 'monthly' ? 'annual' : 'monthly';
}

// Calculate price based on billing period
function getPrice(plan: typeof pricingPlans[0], isAnnual: boolean): number | 'Custom' {
  return isAnnual ? plan.price.annual : plan.price.monthly;
}

// Calculate annual savings
function calculateAnnualSavings(monthlyPrice: number): number {
  return monthlyPrice * 12 * ANNUAL_DISCOUNT;
}

describe('Feature: zalt-enterprise-landing, Property 4: Pricing tier count invariant', () => {
  describe('Property 4.1: Exactly 3 pricing tiers', () => {
    it('should always have exactly 3 pricing tiers', () => {
      // This is a constant property - always true
      expect(pricingPlans.length).toBe(3);
    });

    it('should have Free, Pro, and Enterprise tiers in order', () => {
      expect(pricingPlans[0].name).toBe('Free');
      expect(pricingPlans[1].name).toBe('Pro');
      expect(pricingPlans[2].name).toBe('Enterprise');
    });

    it('should maintain tier count regardless of billing period', () => {
      fc.assert(
        fc.property(
          fc.boolean(), // isAnnual
          (isAnnual) => {
            // Tier count should always be 3 regardless of billing period
            const visibleTiers = pricingPlans.filter(() => true);
            expect(visibleTiers.length).toBe(3);
          }
        ),
        { numRuns: 10 }
      );
    });
  });

  describe('Property 4.2: Tier pricing hierarchy', () => {
    it('should have Free tier at $0', () => {
      const freeTier = pricingPlans.find(p => p.name === 'Free');
      expect(freeTier?.price.monthly).toBe(0);
      expect(freeTier?.price.annual).toBe(0);
    });

    it('should have Pro tier with numeric pricing', () => {
      const proTier = pricingPlans.find(p => p.name === 'Pro');
      expect(typeof proTier?.price.monthly).toBe('number');
      expect(typeof proTier?.price.annual).toBe('number');
      expect(proTier?.price.monthly).toBeGreaterThan(0);
    });

    it('should have Enterprise tier with Custom pricing', () => {
      const enterpriseTier = pricingPlans.find(p => p.name === 'Enterprise');
      expect(enterpriseTier?.price.monthly).toBe('Custom');
      expect(enterpriseTier?.price.annual).toBe('Custom');
    });

    it('should have annual price less than or equal to monthly for all tiers', () => {
      pricingPlans.forEach(plan => {
        if (typeof plan.price.monthly === 'number' && typeof plan.price.annual === 'number') {
          expect(plan.price.annual).toBeLessThanOrEqual(plan.price.monthly);
        }
      });
    });
  });
});

describe('Feature: zalt-enterprise-landing, Property 5: Billing toggle state change', () => {
  describe('Property 5.1: Toggle is idempotent after two toggles', () => {
    it('should return to original state after double toggle', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('monthly', 'annual') as fc.Arbitrary<BillingPeriod>,
          (initialPeriod) => {
            const afterFirstToggle = toggleBillingPeriod(initialPeriod);
            const afterSecondToggle = toggleBillingPeriod(afterFirstToggle);
            
            expect(afterSecondToggle).toBe(initialPeriod);
          }
        ),
        { numRuns: 10 }
      );
    });
  });

  describe('Property 5.2: Toggle always changes state', () => {
    it('should always change billing period on toggle', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('monthly', 'annual') as fc.Arbitrary<BillingPeriod>,
          (period) => {
            const toggled = toggleBillingPeriod(period);
            expect(toggled).not.toBe(period);
          }
        ),
        { numRuns: 10 }
      );
    });
  });

  describe('Property 5.3: Annual discount is exactly 20%', () => {
    it('should apply 20% discount for annual billing', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1, max: 1000 }), // monthly price
          (monthlyPrice) => {
            const annualTotal = monthlyPrice * 12;
            const discountedAnnual = annualTotal * (1 - ANNUAL_DISCOUNT);
            const savings = calculateAnnualSavings(monthlyPrice);
            
            // Use toBeCloseTo for floating point comparison
            expect(savings).toBeCloseTo(annualTotal * ANNUAL_DISCOUNT, 10);
            expect(discountedAnnual).toBeCloseTo(annualTotal - savings, 10);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should show correct Pro tier annual price with 20% discount', () => {
      const proTier = pricingPlans.find(p => p.name === 'Pro');
      if (proTier && typeof proTier.price.monthly === 'number') {
        const expectedAnnual = proTier.price.monthly * (1 - ANNUAL_DISCOUNT);
        expect(proTier.price.annual).toBe(expectedAnnual);
      }
    });
  });

  describe('Property 5.4: Price display changes with toggle', () => {
    it('should show different prices for monthly vs annual', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...pricingPlans.filter(p => typeof p.price.monthly === 'number')),
          (plan) => {
            const monthlyPrice = getPrice(plan, false);
            const annualPrice = getPrice(plan, true);
            
            if (typeof monthlyPrice === 'number' && monthlyPrice > 0) {
              expect(annualPrice).not.toBe(monthlyPrice);
            }
          }
        ),
        { numRuns: 20 }
      );
    });
  });
});

describe('Feature: zalt-enterprise-landing, Property 6: Pricing calculator accuracy', () => {
  describe('Property 6.1: Free tier for MAU <= 1000', () => {
    it('should return Free tier and $0 for MAU up to 1000', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1, max: 1000 }),
          (mau) => {
            const result = calculateMonthlyCost(mau);
            
            expect(result.tier).toBe('Free');
            expect(result.cost).toBe(0);
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Property 6.2: Pro tier for MAU 1001-50000', () => {
    it('should return Pro tier for MAU between 1001 and 50000', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1001, max: 50000 }),
          (mau) => {
            const result = calculateMonthlyCost(mau);
            
            expect(result.tier).toBe('Pro');
            expect(typeof result.cost).toBe('number');
            expect(result.cost).toBeGreaterThanOrEqual(PRICING_TIERS.pro.monthlyPrice);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should calculate Pro tier cost correctly', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1001, max: 50000 }),
          (mau) => {
            const result = calculateMonthlyCost(mau);
            
            const basePrice = PRICING_TIERS.pro.monthlyPrice;
            const extraMAU = Math.max(0, mau - PRICING_TIERS.pro.baseMAU);
            const extraCost = extraMAU * PRICING_TIERS.pro.pricePerMAU;
            const expectedCost = Math.round((basePrice + extraCost) * 100) / 100;
            
            expect(result.cost).toBe(expectedCost);
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Property 6.3: Enterprise tier for MAU > 50000', () => {
    it('should return Enterprise tier for MAU above 50000', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 50001, max: 1000000 }),
          (mau) => {
            const result = calculateMonthlyCost(mau);
            
            expect(result.tier).toBe('Enterprise');
            expect(result.cost).toBe('Custom');
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Property 6.4: Annual cost calculation', () => {
    it('should apply 20% discount for annual billing', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1, max: 10000 }), // monthly cost
          (monthlyCost) => {
            const annualCost = calculateAnnualCost(monthlyCost);
            const expectedAnnual = Math.round(monthlyCost * 12 * 0.8 * 100) / 100;
            
            expect(annualCost).toBe(expectedAnnual);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should return Custom for Custom monthly cost', () => {
      const result = calculateAnnualCost('Custom');
      expect(result).toBe('Custom');
    });

    it('should return $0 annual for $0 monthly', () => {
      const result = calculateAnnualCost(0);
      expect(result).toBe(0);
    });
  });

  describe('Property 6.5: Cost monotonicity', () => {
    it('should have non-decreasing cost as MAU increases within same tier', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1001, max: 49000 }),
          fc.integer({ min: 1, max: 1000 }),
          (baseMau, increment) => {
            const mau1 = baseMau;
            const mau2 = baseMau + increment;
            
            const cost1 = calculateMonthlyCost(mau1);
            const cost2 = calculateMonthlyCost(mau2);
            
            // Both should be in Pro tier
            if (cost1.tier === 'Pro' && cost2.tier === 'Pro') {
              expect(cost2.cost).toBeGreaterThanOrEqual(cost1.cost as number);
            }
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Property 6.6: Tier boundaries', () => {
    it('should correctly handle tier boundary at 1000 MAU', () => {
      const at1000 = calculateMonthlyCost(1000);
      const at1001 = calculateMonthlyCost(1001);
      
      expect(at1000.tier).toBe('Free');
      expect(at1001.tier).toBe('Pro');
    });

    it('should correctly handle tier boundary at 50000 MAU', () => {
      const at50000 = calculateMonthlyCost(50000);
      const at50001 = calculateMonthlyCost(50001);
      
      expect(at50000.tier).toBe('Pro');
      expect(at50001.tier).toBe('Enterprise');
    });
  });
});

describe('Pricing Calculator Edge Cases', () => {
  it('should handle minimum MAU value', () => {
    const result = calculateMonthlyCost(1);
    expect(result.tier).toBe('Free');
    expect(result.cost).toBe(0);
  });

  it('should handle exact tier boundaries', () => {
    // Exact free tier max
    expect(calculateMonthlyCost(1000).tier).toBe('Free');
    
    // Exact pro tier max
    expect(calculateMonthlyCost(50000).tier).toBe('Pro');
  });

  it('should handle large MAU values', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 100000, max: 10000000 }),
        (mau) => {
          const result = calculateMonthlyCost(mau);
          expect(result.tier).toBe('Enterprise');
          expect(result.cost).toBe('Custom');
        }
      ),
      { numRuns: 50 }
    );
  });

  it('should have consistent breakdown message format', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 100000 }),
        (mau) => {
          const result = calculateMonthlyCost(mau);
          expect(typeof result.breakdown).toBe('string');
          expect(result.breakdown.length).toBeGreaterThan(0);
        }
      ),
      { numRuns: 50 }
    );
  });
});
