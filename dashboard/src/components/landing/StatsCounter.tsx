'use client';

import React, { useEffect, useRef, useState } from 'react';
import { motion, useInView, useSpring, useTransform } from 'framer-motion';
import { cn } from '@/lib/utils';

export interface StatItem {
  value: number;
  suffix?: string;
  prefix?: string;
  label: string;
  icon?: React.ReactNode;
  decimals?: number;
}

export interface StatsCounterProps {
  stats: StatItem[];
  animateOnView?: boolean;
  duration?: number;
  className?: string;
  variant?: 'default' | 'card' | 'minimal';
}

// Single animated number component
function AnimatedNumber({
  value,
  prefix = '',
  suffix = '',
  decimals = 0,
  duration = 2,
  shouldAnimate = true,
}: {
  value: number;
  prefix?: string;
  suffix?: string;
  decimals?: number;
  duration?: number;
  shouldAnimate?: boolean;
}) {
  const spring = useSpring(0, {
    stiffness: 50,
    damping: 20,
    duration: duration * 1000,
  });

  const display = useTransform(spring, (current) => {
    if (decimals > 0) {
      return `${prefix}${current.toFixed(decimals)}${suffix}`;
    }
    return `${prefix}${Math.round(current).toLocaleString()}${suffix}`;
  });

  useEffect(() => {
    if (shouldAnimate) {
      spring.set(value);
    }
  }, [spring, value, shouldAnimate]);

  return <motion.span>{display}</motion.span>;
}

// Single stat item component
function StatItem({
  stat,
  index,
  shouldAnimate,
  duration,
  variant,
}: {
  stat: StatItem;
  index: number;
  shouldAnimate: boolean;
  duration: number;
  variant: 'default' | 'card' | 'minimal';
}) {
  const variantStyles = {
    default: 'text-center',
    card: 'bg-white rounded-xl p-6 shadow-sm border border-neutral-100 text-center',
    minimal: 'text-left',
  };

  return (
    <motion.div
      className={cn(variantStyles[variant])}
      initial={{ opacity: 0, y: 20 }}
      animate={shouldAnimate ? { opacity: 1, y: 0 } : {}}
      transition={{
        duration: 0.5,
        delay: index * 0.1,
        ease: [0.25, 0.46, 0.45, 0.94],
      }}
    >
      {/* Icon */}
      {stat.icon && (
        <div className="flex justify-center mb-3">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-primary/10 to-accent/10 flex items-center justify-center text-primary">
            {stat.icon}
          </div>
        </div>
      )}

      {/* Number */}
      <div className={cn(
        'font-bold tracking-tight',
        variant === 'minimal' ? 'text-3xl' : 'text-4xl md:text-5xl',
        'bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent'
      )}>
        <AnimatedNumber
          value={stat.value}
          prefix={stat.prefix}
          suffix={stat.suffix}
          decimals={stat.decimals}
          duration={duration}
          shouldAnimate={shouldAnimate}
        />
      </div>

      {/* Label */}
      <p className={cn(
        'text-neutral-500 mt-2',
        variant === 'minimal' ? 'text-sm' : 'text-base'
      )}>
        {stat.label}
      </p>
    </motion.div>
  );
}

export function StatsCounter({
  stats,
  animateOnView = true,
  duration = 2,
  className,
  variant = 'default',
}: StatsCounterProps) {
  const ref = useRef<HTMLDivElement>(null);
  const isInView = useInView(ref, { once: true, margin: '-100px' });
  const [hasAnimated, setHasAnimated] = useState(false);

  useEffect(() => {
    if (isInView && animateOnView && !hasAnimated) {
      setHasAnimated(true);
    }
  }, [isInView, animateOnView, hasAnimated]);

  const shouldAnimate = animateOnView ? hasAnimated : true;

  const gridCols = {
    1: 'grid-cols-1',
    2: 'grid-cols-2',
    3: 'grid-cols-3',
    4: 'grid-cols-2 md:grid-cols-4',
  };

  const cols = stats.length <= 4 ? stats.length : 4;

  return (
    <div
      ref={ref}
      className={cn(
        'grid gap-8',
        gridCols[cols as keyof typeof gridCols],
        className
      )}
    >
      {stats.map((stat, index) => (
        <StatItem
          key={index}
          stat={stat}
          index={index}
          shouldAnimate={shouldAnimate}
          duration={duration}
          variant={variant}
        />
      ))}
    </div>
  );
}

// Compact inline stats for hero section
export interface InlineStatsProps {
  stats: Array<{
    value: string;
    label: string;
  }>;
  className?: string;
}

export function InlineStats({ stats, className }: InlineStatsProps) {
  const ref = useRef<HTMLDivElement>(null);
  const isInView = useInView(ref, { once: true });

  return (
    <motion.div
      ref={ref}
      className={cn('flex items-center gap-8 flex-wrap', className)}
      initial={{ opacity: 0 }}
      animate={isInView ? { opacity: 1 } : {}}
      transition={{ duration: 0.5, delay: 0.5 }}
    >
      {stats.map((stat, index) => (
        <motion.div
          key={index}
          className="flex items-center gap-2"
          initial={{ opacity: 0, x: -10 }}
          animate={isInView ? { opacity: 1, x: 0 } : {}}
          transition={{ duration: 0.3, delay: 0.6 + index * 0.1 }}
        >
          <span className="text-2xl font-bold text-neutral-900">
            {stat.value}
          </span>
          <span className="text-sm text-neutral-500">
            {stat.label}
          </span>
        </motion.div>
      ))}
    </motion.div>
  );
}

export default StatsCounter;
