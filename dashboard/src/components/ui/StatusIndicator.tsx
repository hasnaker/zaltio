'use client';

import React from 'react';

export type StatusIndicatorStatus = 'online' | 'offline' | 'degraded';

export interface StatusIndicatorProps {
  status: StatusIndicatorStatus;
  label?: string;
  pulse?: boolean;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

/**
 * StatusIndicator Component
 * 
 * A status indicator component that displays online/offline/degraded states
 * with pulse animation for online status.
 * 
 * Requirements: 2.3
 */
export function StatusIndicator({
  status,
  label,
  pulse = true,
  size = 'md',
  className = '',
}: StatusIndicatorProps) {
  const sizeClasses: Record<'sm' | 'md' | 'lg', { dot: string; text: string }> = {
    sm: { dot: 'w-2 h-2', text: 'text-xs' },
    md: { dot: 'w-2.5 h-2.5', text: 'text-sm' },
    lg: { dot: 'w-3 h-3', text: 'text-base' },
  };
  
  const statusColors: Record<StatusIndicatorStatus, string> = {
    online: 'bg-nexus-success',
    offline: 'bg-nexus-text-muted',
    degraded: 'bg-nexus-warning',
  };
  
  const statusLabels: Record<StatusIndicatorStatus, string> = {
    online: 'Online',
    offline: 'Offline',
    degraded: 'Degraded',
  };
  
  const statusTextColors: Record<StatusIndicatorStatus, string> = {
    online: 'text-nexus-success',
    offline: 'text-nexus-text-muted',
    degraded: 'text-nexus-warning',
  };
  
  const shouldPulse = pulse && status === 'online';
  
  const containerClasses = [
    'inline-flex items-center gap-2',
    className,
  ].filter(Boolean).join(' ');
  
  const dotClasses = [
    'rounded-full',
    sizeClasses[size].dot,
    statusColors[status],
    shouldPulse ? 'animate-pulse' : '',
  ].filter(Boolean).join(' ');
  
  const labelClasses = [
    sizeClasses[size].text,
    statusTextColors[status],
  ].join(' ');
  
  const displayLabel = label ?? statusLabels[status];
  
  return (
    <div
      className={containerClasses}
      data-status={status}
      data-pulse={shouldPulse}
      role="status"
      aria-label={`Status: ${displayLabel}`}
    >
      <span className="relative flex">
        {shouldPulse && (
          <span
            className={`absolute inline-flex h-full w-full rounded-full ${statusColors[status]} opacity-75 animate-ping`}
            aria-hidden="true"
          />
        )}
        <span className={dotClasses} />
      </span>
      {displayLabel && (
        <span className={labelClasses}>{displayLabel}</span>
      )}
    </div>
  );
}

export default StatusIndicator;
