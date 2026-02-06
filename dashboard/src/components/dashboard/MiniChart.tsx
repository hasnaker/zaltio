'use client';

import React from 'react';
import { GlassCard } from '../ui/GlassCard';

export interface ChartDataPoint {
  label: string;
  value: number;
}

export type ChartType = 'bar' | 'line';

export interface MiniChartProps {
  title: string;
  data: ChartDataPoint[];
  type?: ChartType;
  color?: 'cyan' | 'purple' | 'pink' | 'blue';
  loading?: boolean;
  className?: string;
}

/**
 * Color configuration for chart elements
 */
const colorConfig: Record<string, {
  bar: string;
  barHover: string;
  line: string;
  dot: string;
  gradient: string;
}> = {
  cyan: {
    bar: 'bg-nexus-glow-cyan',
    barHover: 'hover:bg-nexus-glow-cyan/80',
    line: 'stroke-nexus-glow-cyan',
    dot: 'fill-nexus-glow-cyan',
    gradient: 'from-nexus-glow-cyan/30 to-transparent',
  },
  purple: {
    bar: 'bg-nexus-glow-purple',
    barHover: 'hover:bg-nexus-glow-purple/80',
    line: 'stroke-nexus-glow-purple',
    dot: 'fill-nexus-glow-purple',
    gradient: 'from-nexus-glow-purple/30 to-transparent',
  },
  pink: {
    bar: 'bg-nexus-glow-pink',
    barHover: 'hover:bg-nexus-glow-pink/80',
    line: 'stroke-nexus-glow-pink',
    dot: 'fill-nexus-glow-pink',
    gradient: 'from-nexus-glow-pink/30 to-transparent',
  },
  blue: {
    bar: 'bg-nexus-glow-blue',
    barHover: 'hover:bg-nexus-glow-blue/80',
    line: 'stroke-nexus-glow-blue',
    dot: 'fill-nexus-glow-blue',
    gradient: 'from-nexus-glow-blue/30 to-transparent',
  },
};

/**
 * Bar Chart Component
 */
function BarChart({
  data,
  color,
}: {
  data: ChartDataPoint[];
  color: string;
}) {
  const config = colorConfig[color];
  const maxValue = Math.max(...data.map((d) => d.value), 1);

  return (
    <div className="flex items-end justify-between gap-2 h-32" data-testid="bar-chart">
      {data.map((point, index) => {
        const heightPercent = (point.value / maxValue) * 100;
        
        return (
          <div
            key={index}
            className="flex-1 flex flex-col items-center gap-1"
          >
            {/* Bar */}
            <div className="w-full flex-1 flex items-end">
              <div
                className={`
                  w-full rounded-t-sm
                  ${config.bar} ${config.barHover}
                  transition-all duration-300
                  group relative
                `}
                style={{ height: `${heightPercent}%`, minHeight: '4px' }}
                data-testid="chart-bar"
                data-value={point.value}
              >
                {/* Tooltip */}
                <div className="
                  absolute -top-8 left-1/2 -translate-x-1/2
                  px-2 py-1 rounded text-xs
                  bg-nexus-cosmic-void text-nexus-text-primary
                  opacity-0 group-hover:opacity-100
                  transition-opacity duration-200
                  whitespace-nowrap
                  pointer-events-none
                ">
                  {point.value.toLocaleString()}
                </div>
              </div>
            </div>
            {/* Label */}
            <span className="text-xs text-nexus-text-muted truncate w-full text-center">
              {point.label}
            </span>
          </div>
        );
      })}
    </div>
  );
}

/**
 * Line Chart Component
 */
function LineChart({
  data,
  color,
}: {
  data: ChartDataPoint[];
  color: string;
}) {
  const config = colorConfig[color];
  const maxValue = Math.max(...data.map((d) => d.value), 1);
  const chartHeight = 128;
  const chartWidth = 100;
  const padding = 8;

  // Calculate points for the line
  const points = data.map((point, index) => {
    const x = padding + (index / (data.length - 1)) * (chartWidth - padding * 2);
    const y = chartHeight - padding - (point.value / maxValue) * (chartHeight - padding * 2);
    return { x, y, value: point.value, label: point.label };
  });

  // Create SVG path
  const linePath = points
    .map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x} ${p.y}`)
    .join(' ');

  // Create area path (for gradient fill)
  const areaPath = `
    ${linePath}
    L ${points[points.length - 1].x} ${chartHeight - padding}
    L ${points[0].x} ${chartHeight - padding}
    Z
  `;

  return (
    <div className="relative h-32" data-testid="line-chart">
      <svg
        viewBox={`0 0 ${chartWidth} ${chartHeight}`}
        className="w-full h-full"
        preserveAspectRatio="none"
      >
        {/* Gradient fill */}
        <defs>
          <linearGradient id={`gradient-${color}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="currentColor" stopOpacity="0.3" />
            <stop offset="100%" stopColor="currentColor" stopOpacity="0" />
          </linearGradient>
        </defs>
        
        {/* Area fill */}
        <path
          d={areaPath}
          fill={`url(#gradient-${color})`}
          className={config.line.replace('stroke-', 'text-')}
        />
        
        {/* Line */}
        <path
          d={linePath}
          fill="none"
          className={config.line}
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        
        {/* Dots */}
        {points.map((point, index) => (
          <circle
            key={index}
            cx={point.x}
            cy={point.y}
            r="3"
            className={`${config.dot} ${config.line}`}
            strokeWidth="2"
          />
        ))}
      </svg>

      {/* Labels */}
      <div className="flex justify-between mt-2">
        {data.map((point, index) => (
          <span
            key={index}
            className="text-xs text-nexus-text-muted"
          >
            {point.label}
          </span>
        ))}
      </div>
    </div>
  );
}

/**
 * Loading Skeleton for Chart
 */
function ChartSkeleton() {
  return (
    <div className="h-32 flex items-end justify-between gap-2 animate-pulse">
      {Array.from({ length: 7 }).map((_, index) => (
        <div
          key={index}
          className="flex-1 bg-nexus-cosmic-nebula/60 rounded-t-sm"
          style={{ height: `${30 + Math.random() * 70}%` }}
        />
      ))}
    </div>
  );
}

/**
 * MiniChart Component
 * 
 * A simple chart component for displaying login trends (last 7 days).
 * Supports bar and line chart types.
 * 
 * Requirements: 5.5
 */
export function MiniChart({
  title,
  data,
  type = 'bar',
  color = 'cyan',
  loading = false,
  className = '',
}: MiniChartProps) {
  // Calculate total and trend
  const total = data.reduce((sum, point) => sum + point.value, 0);
  const lastValue = data[data.length - 1]?.value || 0;
  const prevValue = data[data.length - 2]?.value || 0;
  const trendPercent = prevValue > 0 
    ? Math.round(((lastValue - prevValue) / prevValue) * 100) 
    : 0;

  return (
    <GlassCard variant="default" className={`p-6 ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-lg font-semibold text-nexus-text-primary font-heading">
            {title}
          </h2>
          <div className="flex items-center gap-2 mt-1">
            <span className="text-2xl font-bold text-nexus-text-primary">
              {total.toLocaleString()}
            </span>
            {trendPercent !== 0 && (
              <span
                className={`
                  text-sm font-medium
                  ${trendPercent > 0 ? 'text-nexus-success' : 'text-nexus-error'}
                `}
              >
                {trendPercent > 0 ? '↑' : '↓'} {Math.abs(trendPercent)}%
              </span>
            )}
          </div>
        </div>
        <span className="text-xs text-nexus-text-muted">Last 7 days</span>
      </div>

      {/* Chart */}
      {loading ? (
        <ChartSkeleton />
      ) : type === 'bar' ? (
        <BarChart data={data} color={color} />
      ) : (
        <LineChart data={data} color={color} />
      )}
    </GlassCard>
  );
}

export default MiniChart;
