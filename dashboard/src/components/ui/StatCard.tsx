'use client';

import React, { useEffect, useState, useRef } from 'react';

export type StatCardColor = 'cyan' | 'purple' | 'pink' | 'blue';
export type TrendDirection = 'up' | 'down';

export interface StatCardTrend {
  value: number;
  direction: TrendDirection;
}

export interface StatCardProps {
  title: string;
  value: number;
  icon: React.ReactNode;
  trend?: StatCardTrend;
  color?: StatCardColor;
  className?: string;
  animated?: boolean;
  animationDuration?: number;
}

/**
 * StatCard Component
 * 
 * A dashboard stat card with holographic gradient border,
 * animated count-up numbers, icon, and trend indicator.
 * 
 * Requirements: 5.1, 5.2
 */
export function StatCard({
  title,
  value,
  icon,
  trend,
  color = 'cyan',
  className = '',
  animated = true,
  animationDuration = 1000,
}: StatCardProps) {
  const [displayValue, setDisplayValue] = useState(animated ? 0 : value);
  const animationRef = useRef<number | null>(null);
  const startTimeRef = useRef<number | null>(null);

  // Color configurations for holographic gradient borders
  const colorConfig: Record<StatCardColor, {
    gradient: string;
    glow: string;
    iconBg: string;
    trendUp: string;
    trendDown: string;
  }> = {
    cyan: {
      gradient: 'from-nexus-glow-cyan/20 via-nexus-glow-blue/10 to-nexus-glow-cyan/20',
      glow: 'shadow-glow-cyan',
      iconBg: 'bg-nexus-glow-cyan/20 text-nexus-glow-cyan',
      trendUp: 'text-nexus-success',
      trendDown: 'text-nexus-error',
    },
    purple: {
      gradient: 'from-nexus-glow-purple/20 via-nexus-glow-pink/10 to-nexus-glow-purple/20',
      glow: 'shadow-glow-purple',
      iconBg: 'bg-nexus-glow-purple/20 text-nexus-glow-purple',
      trendUp: 'text-nexus-success',
      trendDown: 'text-nexus-error',
    },
    pink: {
      gradient: 'from-nexus-glow-pink/20 via-nexus-glow-purple/10 to-nexus-glow-pink/20',
      glow: 'shadow-glow-pink',
      iconBg: 'bg-nexus-glow-pink/20 text-nexus-glow-pink',
      trendUp: 'text-nexus-success',
      trendDown: 'text-nexus-error',
    },
    blue: {
      gradient: 'from-nexus-glow-blue/20 via-nexus-glow-cyan/10 to-nexus-glow-blue/20',
      glow: 'shadow-glow-blue',
      iconBg: 'bg-nexus-glow-blue/20 text-nexus-glow-blue',
      trendUp: 'text-nexus-success',
      trendDown: 'text-nexus-error',
    },
  };

  const config = colorConfig[color];

  // Animated count-up effect
  useEffect(() => {
    if (!animated) {
      setDisplayValue(value);
      return;
    }

    // Reset animation when value changes
    setDisplayValue(0);
    startTimeRef.current = null;

    const animate = (timestamp: number) => {
      if (!startTimeRef.current) {
        startTimeRef.current = timestamp;
      }

      const elapsed = timestamp - startTimeRef.current;
      const progress = Math.min(elapsed / animationDuration, 1);
      
      // Easing function for smooth animation
      const easeOutQuart = 1 - Math.pow(1 - progress, 4);
      const currentValue = Math.floor(easeOutQuart * value);
      
      setDisplayValue(currentValue);

      if (progress < 1) {
        animationRef.current = requestAnimationFrame(animate);
      } else {
        setDisplayValue(value);
      }
    };

    animationRef.current = requestAnimationFrame(animate);

    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [value, animated, animationDuration]);

  // Format number with locale
  const formatNumber = (num: number): string => {
    return num.toLocaleString();
  };

  return (
    <div
      className={`
        relative p-6 rounded-xl
        bg-nexus-cosmic-nebula/40 backdrop-blur-md
        border border-white/10
        hover:border-white/20
        transition-all duration-300
        hover:-translate-y-1
        ${config.glow}
        ${className}
      `}
      data-testid="stat-card"
      data-color={color}
      data-animated={animated}
    >
      {/* Holographic gradient border overlay */}
      <div
        className={`
          absolute inset-0 rounded-xl
          bg-gradient-to-r ${config.gradient}
          opacity-50 pointer-events-none
        `}
        data-testid="holographic-border"
      />

      {/* Content */}
      <div className="relative z-10">
        {/* Header: Title and Icon */}
        <div className="flex items-center justify-between mb-4">
          <span className="text-sm font-medium text-nexus-text-secondary">
            {title}
          </span>
          <div
            className={`
              p-2 rounded-lg
              ${config.iconBg}
            `}
            data-testid="stat-icon"
          >
            {icon}
          </div>
        </div>

        {/* Value with count-up animation */}
        <div className="flex items-end gap-2">
          <span
            className="text-3xl font-bold text-nexus-text-primary font-heading"
            data-testid="stat-value"
            data-target-value={value}
          >
            {formatNumber(displayValue)}
          </span>

          {/* Trend indicator */}
          {trend && (
            <div
              className={`
                flex items-center gap-1 text-sm font-medium mb-1
                ${trend.direction === 'up' ? config.trendUp : config.trendDown}
              `}
              data-testid="stat-trend"
              data-direction={trend.direction}
            >
              <span>
                {trend.direction === 'up' ? '↑' : '↓'}
              </span>
              <span>{trend.value}%</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default StatCard;
