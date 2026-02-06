'use client';

import React from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import { cn } from '@/lib/utils';
import { Check, X, Minus } from 'lucide-react';

export interface FeatureComparisonTableProps {
  /** Additional CSS classes */
  className?: string;
  /** Test ID for testing */
  'data-testid'?: string;
}

type FeatureSupport = 'full' | 'partial' | 'none';

interface FeatureRow {
  name: string;
  category: string;
  free: FeatureSupport;
  pro: FeatureSupport;
  enterprise: FeatureSupport;
  tooltip?: string;
}

const features: FeatureRow[] = [
  // Authentication
  { name: 'Email/Password Auth', category: 'Authentication', free: 'full', pro: 'full', enterprise: 'full' },
  { name: 'Social Logins', category: 'Authentication', free: 'full', pro: 'full', enterprise: 'full' },
  { name: 'Passwordless (Magic Links)', category: 'Authentication', free: 'partial', pro: 'full', enterprise: 'full' },
  { name: 'WebAuthn/Passkeys', category: 'Authentication', free: 'none', pro: 'full', enterprise: 'full' },
  
  // Security
  { name: 'TOTP MFA', category: 'Security', free: 'partial', pro: 'full', enterprise: 'full' },
  { name: 'SMS MFA', category: 'Security', free: 'none', pro: 'partial', enterprise: 'full', tooltip: 'Not recommended due to SS7 vulnerabilities' },
  { name: 'Breach Detection', category: 'Security', free: 'none', pro: 'full', enterprise: 'full' },
  { name: 'Risk-based Auth', category: 'Security', free: 'none', pro: 'partial', enterprise: 'full' },
  
  // Organizations
  { name: 'Multi-tenant Support', category: 'Organizations', free: 'partial', pro: 'full', enterprise: 'full' },
  { name: 'Custom Roles', category: 'Organizations', free: 'none', pro: 'full', enterprise: 'full' },
  { name: 'Team Invitations', category: 'Organizations', free: 'partial', pro: 'full', enterprise: 'full' },
  { name: 'SCIM Provisioning', category: 'Organizations', free: 'none', pro: 'none', enterprise: 'full' },
  
  // Enterprise
  { name: 'SAML SSO', category: 'Enterprise', free: 'none', pro: 'none', enterprise: 'full' },
  { name: 'OIDC SSO', category: 'Enterprise', free: 'none', pro: 'partial', enterprise: 'full' },
  { name: 'Custom Domain', category: 'Enterprise', free: 'none', pro: 'full', enterprise: 'full' },
  { name: 'Audit Logs', category: 'Enterprise', free: 'partial', pro: 'full', enterprise: 'full' },
  
  // Support
  { name: 'Community Support', category: 'Support', free: 'full', pro: 'full', enterprise: 'full' },
  { name: 'Email Support', category: 'Support', free: 'none', pro: 'full', enterprise: 'full' },
  { name: 'Priority Support', category: 'Support', free: 'none', pro: 'partial', enterprise: 'full' },
  { name: 'Dedicated CSM', category: 'Support', free: 'none', pro: 'none', enterprise: 'full' },
];

// Group features by category
const groupedFeatures = features.reduce((acc, feature) => {
  if (!acc[feature.category]) {
    acc[feature.category] = [];
  }
  acc[feature.category].push(feature);
  return acc;
}, {} as Record<string, FeatureRow[]>);

/**
 * Feature Comparison Table Component
 * Displays feature matrix across all pricing tiers
 */
export function FeatureComparisonTable({
  className,
  'data-testid': testId = 'feature-comparison-table',
}: FeatureComparisonTableProps) {
  const shouldReduceMotion = useReducedMotion();
  const reducedMotion = shouldReduceMotion ?? false;

  return (
    <div
      className={cn(
        'overflow-x-auto rounded-2xl border border-neutral-200 dark:border-neutral-700',
        className
      )}
      data-testid={testId}
    >
      <table className="w-full min-w-[600px]">
        {/* Header */}
        <thead>
          <tr className="bg-neutral-50 dark:bg-neutral-800">
            <th className="text-left p-4 font-semibold text-neutral-900 dark:text-white">
              Features
            </th>
            <th className="text-center p-4 font-semibold text-neutral-900 dark:text-white w-28">
              Free
            </th>
            <th className="text-center p-4 font-semibold text-neutral-900 dark:text-white w-28 bg-primary/5">
              <div className="flex flex-col items-center">
                <span>Pro</span>
                <span className="text-xs font-normal text-primary">Popular</span>
              </div>
            </th>
            <th className="text-center p-4 font-semibold text-neutral-900 dark:text-white w-28">
              Enterprise
            </th>
          </tr>
        </thead>

        {/* Body */}
        <tbody>
          {Object.entries(groupedFeatures).map(([category, categoryFeatures], categoryIndex) => (
            <React.Fragment key={category}>
              {/* Category header */}
              <tr className="bg-neutral-100/50 dark:bg-neutral-800/50">
                <td 
                  colSpan={4} 
                  className="p-3 text-sm font-semibold text-neutral-700 dark:text-neutral-300"
                >
                  {category}
                </td>
              </tr>
              
              {/* Features in category */}
              {categoryFeatures.map((feature, featureIndex) => (
                <motion.tr
                  key={feature.name}
                  initial={{ opacity: reducedMotion ? 1 : 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: reducedMotion ? 0 : (categoryIndex * 0.1 + featureIndex * 0.02) }}
                  className="border-t border-neutral-100 dark:border-neutral-800 hover:bg-neutral-50 dark:hover:bg-neutral-800/50 transition-colors"
                >
                  <td className="p-4 text-sm text-neutral-700 dark:text-neutral-300">
                    <div className="flex items-center gap-2">
                      {feature.name}
                      {feature.tooltip && (
                        <span 
                          className="text-xs text-neutral-400 cursor-help"
                          title={feature.tooltip}
                        >
                          ⓘ
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="p-4 text-center">
                    <SupportIndicator support={feature.free} />
                  </td>
                  <td className="p-4 text-center bg-primary/5">
                    <SupportIndicator support={feature.pro} />
                  </td>
                  <td className="p-4 text-center">
                    <SupportIndicator support={feature.enterprise} />
                  </td>
                </motion.tr>
              ))}
            </React.Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// Support indicator component
function SupportIndicator({ support }: { support: FeatureSupport }) {
  switch (support) {
    case 'full':
      return (
        <div className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-green-100 dark:bg-green-900/30">
          <Check className="w-4 h-4 text-green-600 dark:text-green-400" />
        </div>
      );
    case 'partial':
      return (
        <div className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-yellow-100 dark:bg-yellow-900/30">
          <Minus className="w-4 h-4 text-yellow-600 dark:text-yellow-400" />
        </div>
      );
    case 'none':
      return (
        <div className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-neutral-100 dark:bg-neutral-800">
          <X className="w-4 h-4 text-neutral-400" />
        </div>
      );
  }
}

export default FeatureComparisonTable;
