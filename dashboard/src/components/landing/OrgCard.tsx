'use client';

import React from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import { cn } from '@/lib/utils';
import { Users, Crown, Check, ChevronRight } from 'lucide-react';

export interface OrgData {
  id: string;
  name: string;
  slug: string;
  logo: string;
  memberCount: number;
  plan: 'Free' | 'Pro' | 'Enterprise';
  roles: string[];
}

export interface OrgCardProps {
  /** Organization data */
  org: OrgData;
  /** Whether this card is currently active/selected */
  isActive?: boolean;
  /** Click handler */
  onClick?: () => void;
  /** Show member avatars */
  showMembers?: boolean;
  /** Additional CSS classes */
  className?: string;
  /** Test ID for testing */
  'data-testid'?: string;
}

const planColors = {
  Free: 'bg-neutral-100 text-neutral-600 dark:bg-neutral-800 dark:text-neutral-400',
  Pro: 'bg-primary/10 text-primary',
  Enterprise: 'bg-gradient-to-r from-amber-500/10 to-orange-500/10 text-amber-600 dark:text-amber-400',
};

const planIcons = {
  Free: null,
  Pro: <Check className="w-3 h-3" />,
  Enterprise: <Crown className="w-3 h-3" />,
};

/**
 * Organization Card Component
 * Displays organization information with member count and role badges
 */
export function OrgCard({
  org,
  isActive = false,
  onClick,
  showMembers = true,
  className,
  'data-testid': testId = 'org-card',
}: OrgCardProps) {
  const shouldReduceMotion = useReducedMotion();
  const reducedMotion = shouldReduceMotion ?? false;

  // Generate sample member avatars
  const memberAvatars = ['JD', 'AS', 'MK', 'RB', 'TC'];

  return (
    <motion.div
      whileHover={reducedMotion ? {} : { scale: 1.02 }}
      whileTap={reducedMotion ? {} : { scale: 0.98 }}
      onClick={onClick}
      className={cn(
        'relative p-4 rounded-xl border-2 cursor-pointer transition-all',
        isActive
          ? 'border-primary bg-primary/5 dark:bg-primary/10'
          : 'border-neutral-200 dark:border-neutral-700 bg-white dark:bg-neutral-800 hover:border-neutral-300 dark:hover:border-neutral-600',
        className
      )}
      data-testid={testId}
      data-active={isActive}
      role="button"
      tabIndex={0}
      aria-pressed={isActive}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onClick?.();
        }
      }}
    >
      {/* Active indicator */}
      {isActive && (
        <motion.div
          layoutId="activeOrgIndicator"
          className="absolute -left-0.5 top-1/2 -translate-y-1/2 w-1 h-8 bg-primary rounded-full"
          transition={{ duration: reducedMotion ? 0 : 0.2 }}
        />
      )}

      <div className="flex items-start gap-4">
        {/* Organization Logo */}
        <div 
          className={cn(
            'w-12 h-12 rounded-xl flex items-center justify-center text-white font-bold text-lg flex-shrink-0',
            isActive ? 'bg-primary' : 'bg-gradient-to-br from-neutral-600 to-neutral-800'
          )}
        >
          {org.logo}
        </div>

        {/* Organization Info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <h3 className="font-semibold text-neutral-900 dark:text-white truncate">
              {org.name}
            </h3>
            <span className={cn(
              'inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium',
              planColors[org.plan]
            )}>
              {planIcons[org.plan]}
              {org.plan}
            </span>
          </div>

          <p className="text-sm text-neutral-500 dark:text-neutral-400 mb-2">
            @{org.slug}
          </p>

          {/* Member count and avatars */}
          {showMembers && (
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-1.5">
                <Users className="w-4 h-4 text-neutral-400" />
                <span className="text-sm text-neutral-600 dark:text-neutral-400">
                  {org.memberCount} members
                </span>
              </div>

              {/* Member avatars */}
              <div className="flex -space-x-2">
                {memberAvatars.slice(0, 4).map((initials, index) => (
                  <div
                    key={index}
                    className="w-6 h-6 rounded-full bg-neutral-200 dark:bg-neutral-700 border-2 border-white dark:border-neutral-800 flex items-center justify-center text-[10px] font-medium text-neutral-600 dark:text-neutral-400"
                  >
                    {initials}
                  </div>
                ))}
                {org.memberCount > 4 && (
                  <div className="w-6 h-6 rounded-full bg-neutral-100 dark:bg-neutral-700 border-2 border-white dark:border-neutral-800 flex items-center justify-center text-[10px] font-medium text-neutral-500">
                    +{org.memberCount - 4}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Role badges */}
          <div className="flex flex-wrap gap-1.5 mt-3">
            {org.roles.slice(0, 3).map((role) => (
              <span
                key={role}
                className="px-2 py-0.5 rounded-md bg-neutral-100 dark:bg-neutral-700 text-xs text-neutral-600 dark:text-neutral-400"
              >
                {role}
              </span>
            ))}
            {org.roles.length > 3 && (
              <span className="px-2 py-0.5 rounded-md bg-neutral-100 dark:bg-neutral-700 text-xs text-neutral-500">
                +{org.roles.length - 3} more
              </span>
            )}
          </div>
        </div>

        {/* Arrow indicator */}
        <ChevronRight className={cn(
          'w-5 h-5 flex-shrink-0 transition-colors',
          isActive ? 'text-primary' : 'text-neutral-400'
        )} />
      </div>
    </motion.div>
  );
}

export default OrgCard;
