'use client';

import React from 'react';
import { GlassCard } from '../ui/GlassCard';

export type ActivityType = 'login' | 'logout' | 'create' | 'update' | 'delete' | 'error' | 'security';

export interface ActivityItem {
  id: string;
  type: ActivityType;
  title: string;
  description: string;
  timestamp: Date | string;
  user?: {
    name: string;
    avatar?: string;
  };
  metadata?: Record<string, string>;
}

export interface RecentActivityProps {
  activities: ActivityItem[];
  maxItems?: number;
  loading?: boolean;
  onViewAll?: () => void;
  className?: string;
}

/**
 * Activity type configuration for icons and colors
 */
const activityConfig: Record<ActivityType, {
  icon: string;
  color: string;
  bgColor: string;
}> = {
  login: {
    icon: '🔐',
    color: 'text-nexus-glow-cyan',
    bgColor: 'bg-nexus-glow-cyan/20',
  },
  logout: {
    icon: '🚪',
    color: 'text-nexus-text-secondary',
    bgColor: 'bg-nexus-cosmic-nebula/60',
  },
  create: {
    icon: '✨',
    color: 'text-nexus-success',
    bgColor: 'bg-nexus-success/20',
  },
  update: {
    icon: '📝',
    color: 'text-nexus-glow-blue',
    bgColor: 'bg-nexus-glow-blue/20',
  },
  delete: {
    icon: '🗑️',
    color: 'text-nexus-error',
    bgColor: 'bg-nexus-error/20',
  },
  error: {
    icon: '⚠️',
    color: 'text-nexus-warning',
    bgColor: 'bg-nexus-warning/20',
  },
  security: {
    icon: '🛡️',
    color: 'text-nexus-glow-purple',
    bgColor: 'bg-nexus-glow-purple/20',
  },
};

/**
 * Format timestamp to relative time
 */
function formatRelativeTime(timestamp: Date | string): string {
  const date = typeof timestamp === 'string' ? new Date(timestamp) : timestamp;
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffSec = Math.floor(diffMs / 1000);
  const diffMin = Math.floor(diffSec / 60);
  const diffHour = Math.floor(diffMin / 60);
  const diffDay = Math.floor(diffHour / 24);

  if (diffSec < 60) return 'Just now';
  if (diffMin < 60) return `${diffMin}m ago`;
  if (diffHour < 24) return `${diffHour}h ago`;
  if (diffDay < 7) return `${diffDay}d ago`;
  
  return date.toLocaleDateString();
}

/**
 * Activity Item Component
 */
function ActivityItemRow({ activity }: { activity: ActivityItem }) {
  const config = activityConfig[activity.type];

  return (
    <div
      className="flex items-start gap-3 p-3 rounded-lg hover:bg-white/5 transition-colors duration-200"
      data-testid="activity-item"
      data-type={activity.type}
    >
      {/* Icon */}
      <div
        className={`
          flex-shrink-0 w-8 h-8 rounded-lg
          flex items-center justify-center
          ${config.bgColor}
        `}
      >
        <span className="text-sm">{config.icon}</span>
      </div>

      {/* Content */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className={`font-medium text-sm ${config.color}`}>
            {activity.title}
          </span>
          {activity.user && (
            <span className="text-xs text-nexus-text-muted">
              by {activity.user.name}
            </span>
          )}
        </div>
        <p className="text-xs text-nexus-text-secondary mt-0.5 truncate">
          {activity.description}
        </p>
      </div>

      {/* Timestamp */}
      <span className="flex-shrink-0 text-xs text-nexus-text-muted">
        {formatRelativeTime(activity.timestamp)}
      </span>
    </div>
  );
}

/**
 * Loading Skeleton for Activity Items
 */
function ActivitySkeleton() {
  return (
    <div className="flex items-start gap-3 p-3 animate-pulse">
      <div className="w-8 h-8 rounded-lg bg-nexus-cosmic-nebula/60" />
      <div className="flex-1 space-y-2">
        <div className="h-4 bg-nexus-cosmic-nebula/60 rounded w-3/4" />
        <div className="h-3 bg-nexus-cosmic-nebula/60 rounded w-1/2" />
      </div>
      <div className="h-3 bg-nexus-cosmic-nebula/60 rounded w-12" />
    </div>
  );
}

/**
 * RecentActivity Component
 * 
 * Displays a feed of recent activity items with real-time update placeholder.
 * 
 * Requirements: 5.3
 */
export function RecentActivity({
  activities,
  maxItems = 5,
  loading = false,
  onViewAll,
  className = '',
}: RecentActivityProps) {
  const displayedActivities = activities.slice(0, maxItems);

  return (
    <GlassCard variant="default" className={`p-6 ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-nexus-text-primary font-heading">
          Recent Activity
        </h2>
        {/* Real-time indicator */}
        <div className="flex items-center gap-2">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-nexus-glow-cyan opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-nexus-glow-cyan" />
          </span>
          <span className="text-xs text-nexus-text-muted">Live</span>
        </div>
      </div>

      {/* Activity List */}
      <div className="space-y-1" data-testid="activity-list">
        {loading ? (
          // Loading skeletons
          Array.from({ length: maxItems }).map((_, index) => (
            <ActivitySkeleton key={index} />
          ))
        ) : displayedActivities.length > 0 ? (
          // Activity items
          displayedActivities.map((activity) => (
            <ActivityItemRow key={activity.id} activity={activity} />
          ))
        ) : (
          // Empty state
          <div className="text-center py-8">
            <span className="text-4xl mb-2 block">📭</span>
            <p className="text-nexus-text-muted text-sm">No recent activity</p>
          </div>
        )}
      </div>

      {/* View All Button */}
      {onViewAll && activities.length > maxItems && (
        <button
          onClick={onViewAll}
          className="
            w-full mt-4 py-2 text-sm text-nexus-glow-cyan
            hover:text-nexus-glow-cyan/80
            transition-colors duration-200
          "
        >
          View all activity →
        </button>
      )}
    </GlassCard>
  );
}

export default RecentActivity;
