'use client';

import React from 'react';
import { motion } from 'framer-motion';
import { LucideIcon } from 'lucide-react';

export interface DashboardCardProps {
  title: string;
  value: string | number;
  description?: string;
  icon?: LucideIcon;
  trend?: {
    value: number;
    isPositive: boolean;
  };
  variant?: 'default' | 'gradient' | 'outlined';
  className?: string;
  onClick?: () => void;
}

export function DashboardCard({
  title,
  value,
  description,
  icon: Icon,
  trend,
  variant = 'default',
  className = '',
  onClick,
}: DashboardCardProps) {
  const baseStyles = 'rounded-xl p-6 transition-all duration-200';
  
  const variantStyles = {
    default: 'bg-white border border-neutral-200 shadow-sm hover:shadow-md hover:border-neutral-300',
    gradient: 'bg-gradient-to-br from-primary/5 to-accent/5 border border-primary/10 hover:border-primary/20 hover:shadow-lg hover:shadow-primary/5',
    outlined: 'bg-white border-2 border-neutral-200 hover:border-primary/30',
  };

  return (
    <motion.div
      whileHover={{ y: -2 }}
      transition={{ duration: 0.2 }}
      className={`${baseStyles} ${variantStyles[variant]} ${onClick ? 'cursor-pointer' : ''} ${className}`}
      onClick={onClick}
    >
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-sm font-medium text-neutral-500">{title}</p>
          <p className="mt-2 text-3xl font-semibold text-neutral-900">{value}</p>
          
          {description && (
            <p className="mt-1 text-sm text-neutral-500">{description}</p>
          )}
          
          {trend && (
            <div className="mt-3 flex items-center gap-1">
              <span
                className={`text-sm font-medium ${
                  trend.isPositive ? 'text-green-600' : 'text-red-600'
                }`}
              >
                {trend.isPositive ? '+' : ''}{trend.value}%
              </span>
              <span className="text-xs text-neutral-500">vs last month</span>
            </div>
          )}
        </div>
        
        {Icon && (
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-primary/10 to-accent/10 flex items-center justify-center">
            <Icon className="w-6 h-6 text-primary" />
          </div>
        )}
      </div>
    </motion.div>
  );
}

export interface DashboardStatGridProps {
  children: React.ReactNode;
  columns?: 2 | 3 | 4;
  className?: string;
}

export function DashboardStatGrid({ 
  children, 
  columns = 4,
  className = '' 
}: DashboardStatGridProps) {
  const gridCols = {
    2: 'grid-cols-1 sm:grid-cols-2',
    3: 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-3',
    4: 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-4',
  };

  return (
    <div className={`grid ${gridCols[columns]} gap-4 ${className}`}>
      {children}
    </div>
  );
}

export interface DashboardSectionProps {
  title: string;
  description?: string;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}

export function DashboardSection({
  title,
  description,
  action,
  children,
  className = '',
}: DashboardSectionProps) {
  return (
    <section className={`${className}`}>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-lg font-semibold text-neutral-900">{title}</h2>
          {description && (
            <p className="text-sm text-neutral-500 mt-0.5">{description}</p>
          )}
        </div>
        {action && <div>{action}</div>}
      </div>
      {children}
    </section>
  );
}

export interface DashboardTableCardProps {
  title: string;
  description?: string;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}

export function DashboardTableCard({
  title,
  description,
  action,
  children,
  className = '',
}: DashboardTableCardProps) {
  return (
    <div className={`bg-white rounded-xl border border-neutral-200 shadow-sm overflow-hidden ${className}`}>
      <div className="px-6 py-4 border-b border-neutral-100 flex items-center justify-between">
        <div>
          <h3 className="font-semibold text-neutral-900">{title}</h3>
          {description && (
            <p className="text-sm text-neutral-500 mt-0.5">{description}</p>
          )}
        </div>
        {action && <div>{action}</div>}
      </div>
      <div className="overflow-x-auto">
        {children}
      </div>
    </div>
  );
}

export default DashboardCard;
