'use client';

import React from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import { cn } from '@/lib/utils';
import { Shield, Lock, Globe, FileCheck } from 'lucide-react';

export interface TrustBadgesProps {
  /** Show aggregate statistics */
  showStats?: boolean;
  /** Additional CSS classes */
  className?: string;
  /** Test ID for testing */
  'data-testid'?: string;
}

interface ComplianceBadge {
  id: string;
  name: string;
  description: string;
  icon: React.ReactNode;
  color: string;
}

const complianceBadges: ComplianceBadge[] = [
  {
    id: 'soc2',
    name: 'SOC 2 Type II',
    description: 'Security & availability controls',
    icon: <Shield className="w-6 h-6" />,
    color: 'from-blue-500 to-blue-600',
  },
  {
    id: 'hipaa',
    name: 'HIPAA',
    description: 'Healthcare data protection',
    icon: <Lock className="w-6 h-6" />,
    color: 'from-green-500 to-green-600',
  },
  {
    id: 'gdpr',
    name: 'GDPR',
    description: 'EU data privacy compliance',
    icon: <Globe className="w-6 h-6" />,
    color: 'from-purple-500 to-purple-600',
  },
  {
    id: 'iso27001',
    name: 'ISO 27001',
    description: 'Information security management',
    icon: <FileCheck className="w-6 h-6" />,
    color: 'from-orange-500 to-orange-600',
  },
];

const aggregateStats = [
  { label: 'Protected Users', value: '50,000+' },
  { label: 'Uptime SLA', value: '99.99%' },
  { label: 'Security Incidents', value: '0' },
  { label: 'Countries', value: '15+' },
];

/**
 * Trust Badges Component
 * Displays SOC 2, HIPAA, GDPR, ISO 27001 compliance badges with aggregate statistics
 */
export function TrustBadges({
  showStats = true,
  className,
  'data-testid': testId = 'trust-badges',
}: TrustBadgesProps) {
  const shouldReduceMotion = useReducedMotion();
  const reducedMotion = shouldReduceMotion ?? false;

  return (
    <div
      className={cn('py-12', className)}
      data-testid={testId}
    >
      {/* Compliance Badges */}
      <div className="flex flex-wrap justify-center gap-4 md:gap-6 mb-8">
        {complianceBadges.map((badge, index) => (
          <motion.div
            key={badge.id}
            initial={{ opacity: reducedMotion ? 1 : 0, y: reducedMotion ? 0 : 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: reducedMotion ? 0 : index * 0.1 }}
            whileHover={reducedMotion ? {} : { scale: 1.05, y: -5 }}
            className="flex items-center gap-3 px-4 py-3 rounded-xl bg-white dark:bg-neutral-800 border border-neutral-200 dark:border-neutral-700 shadow-sm hover:shadow-md transition-shadow"
            data-testid={`badge-${badge.id}`}
          >
            <div className={cn(
              'w-10 h-10 rounded-lg bg-gradient-to-br flex items-center justify-center text-white',
              badge.color
            )}>
              {badge.icon}
            </div>
            <div>
              <p className="font-semibold text-neutral-900 dark:text-white text-sm">
                {badge.name}
              </p>
              <p className="text-xs text-neutral-500 dark:text-neutral-400">
                {badge.description}
              </p>
            </div>
          </motion.div>
        ))}
      </div>

      {/* Aggregate Statistics */}
      {showStats && (
        <motion.div
          initial={{ opacity: reducedMotion ? 1 : 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: reducedMotion ? 0 : 0.4 }}
          className="flex flex-wrap justify-center gap-8 md:gap-12 pt-8 border-t border-neutral-200 dark:border-neutral-700"
          data-testid="trust-stats"
        >
          {aggregateStats.map((stat, index) => (
            <motion.div
              key={stat.label}
              initial={{ opacity: reducedMotion ? 1 : 0, scale: reducedMotion ? 1 : 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: reducedMotion ? 0 : 0.5 + index * 0.1 }}
              className="text-center"
            >
              <p className="text-2xl md:text-3xl font-bold bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
                {stat.value}
              </p>
              <p className="text-sm text-neutral-500 dark:text-neutral-400">
                {stat.label}
              </p>
            </motion.div>
          ))}
        </motion.div>
      )}
    </div>
  );
}

export default TrustBadges;
