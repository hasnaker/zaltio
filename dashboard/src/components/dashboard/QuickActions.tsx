'use client';

import React from 'react';
import Link from 'next/link';
import { GlassCard } from '../ui/GlassCard';

export interface QuickAction {
  id: string;
  title: string;
  description?: string;
  icon: React.ReactNode;
  href: string;
  color?: 'cyan' | 'purple' | 'pink' | 'blue';
}

export interface QuickActionsProps {
  actions?: QuickAction[];
  className?: string;
}

/**
 * Default quick actions for the dashboard
 */
const defaultActions: QuickAction[] = [
  {
    id: 'create-realm',
    title: 'Create Realm',
    description: 'Set up a new authentication realm',
    icon: '➕',
    href: '/dashboard/realms/new',
    color: 'cyan',
  },
  {
    id: 'manage-users',
    title: 'Manage Users',
    description: 'View and manage user accounts',
    icon: '👥',
    href: '/dashboard/users',
    color: 'purple',
  },
  {
    id: 'view-analytics',
    title: 'View Analytics',
    description: 'Monitor authentication metrics',
    icon: '📊',
    href: '/dashboard/analytics',
    color: 'pink',
  },
  {
    id: 'settings',
    title: 'Settings',
    description: 'Configure platform settings',
    icon: '⚙️',
    href: '/dashboard/settings',
    color: 'blue',
  },
];

/**
 * Color configuration for action cards
 */
const colorConfig: Record<string, {
  border: string;
  hoverBorder: string;
  iconBg: string;
  iconColor: string;
  glow: string;
}> = {
  cyan: {
    border: 'border-nexus-glow-cyan/20',
    hoverBorder: 'hover:border-nexus-glow-cyan/50',
    iconBg: 'bg-nexus-glow-cyan/10',
    iconColor: 'text-nexus-glow-cyan',
    glow: 'hover:shadow-glow-cyan',
  },
  purple: {
    border: 'border-nexus-glow-purple/20',
    hoverBorder: 'hover:border-nexus-glow-purple/50',
    iconBg: 'bg-nexus-glow-purple/10',
    iconColor: 'text-nexus-glow-purple',
    glow: 'hover:shadow-glow-purple',
  },
  pink: {
    border: 'border-nexus-glow-pink/20',
    hoverBorder: 'hover:border-nexus-glow-pink/50',
    iconBg: 'bg-nexus-glow-pink/10',
    iconColor: 'text-nexus-glow-pink',
    glow: 'hover:shadow-glow-pink',
  },
  blue: {
    border: 'border-nexus-glow-blue/20',
    hoverBorder: 'hover:border-nexus-glow-blue/50',
    iconBg: 'bg-nexus-glow-blue/10',
    iconColor: 'text-nexus-glow-blue',
    glow: 'hover:shadow-glow-blue',
  },
};

/**
 * Quick Action Card Component
 */
function QuickActionCard({ action }: { action: QuickAction }) {
  const config = colorConfig[action.color || 'cyan'];

  return (
    <Link
      href={action.href}
      className={`
        block p-4 rounded-xl
        bg-nexus-cosmic-nebula/30 backdrop-blur-sm
        border ${config.border} ${config.hoverBorder}
        transition-all duration-300
        hover:-translate-y-1
        ${config.glow}
        group
      `}
      data-testid="quick-action-card"
      data-action-id={action.id}
    >
      {/* Icon */}
      <div
        className={`
          w-12 h-12 rounded-lg mb-3
          flex items-center justify-center
          ${config.iconBg}
          transition-transform duration-300
          group-hover:scale-110
        `}
      >
        <span className={`text-2xl ${config.iconColor}`}>
          {action.icon}
        </span>
      </div>

      {/* Title */}
      <h3 className="font-medium text-nexus-text-primary mb-1">
        {action.title}
      </h3>

      {/* Description */}
      {action.description && (
        <p className="text-xs text-nexus-text-muted line-clamp-2">
          {action.description}
        </p>
      )}
    </Link>
  );
}

/**
 * QuickActions Component
 * 
 * Displays a grid of quick action cards with hover effects.
 * 
 * Requirements: 5.4
 */
export function QuickActions({
  actions = defaultActions,
  className = '',
}: QuickActionsProps) {
  return (
    <GlassCard variant="default" className={`p-6 ${className}`}>
      {/* Header */}
      <h2 className="text-lg font-semibold text-nexus-text-primary font-heading mb-4">
        Quick Actions
      </h2>

      {/* Actions Grid */}
      <div
        className="grid grid-cols-2 gap-4"
        data-testid="quick-actions-grid"
      >
        {actions.map((action) => (
          <QuickActionCard key={action.id} action={action} />
        ))}
      </div>
    </GlassCard>
  );
}

export default QuickActions;
