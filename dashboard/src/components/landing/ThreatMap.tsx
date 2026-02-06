'use client';

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { cn } from '@/lib/utils';

export interface ThreatConnection {
  id: string;
  from: { x: number; y: number; label: string };
  to: { x: number; y: number; label: string };
  severity: 'low' | 'medium' | 'high' | 'critical';
  blocked: boolean;
}

export interface ThreatMapProps {
  connections?: ThreatConnection[];
  autoAnimate?: boolean;
  showLabels?: boolean;
  className?: string;
}

const severityColors = {
  low: '#22C55E',
  medium: '#F59E0B',
  high: '#EF4444',
  critical: '#DC2626',
};

// Default threat connections for demo
const defaultConnections: ThreatConnection[] = [
  { id: '1', from: { x: 15, y: 35, label: 'Russia' }, to: { x: 50, y: 45, label: 'Server' }, severity: 'critical', blocked: true },
  { id: '2', from: { x: 85, y: 55, label: 'China' }, to: { x: 50, y: 45, label: 'Server' }, severity: 'high', blocked: true },
  { id: '3', from: { x: 25, y: 75, label: 'Brazil' }, to: { x: 50, y: 45, label: 'Server' }, severity: 'medium', blocked: false },
  { id: '4', from: { x: 70, y: 25, label: 'Germany' }, to: { x: 50, y: 45, label: 'Server' }, severity: 'low', blocked: false },
  { id: '5', from: { x: 10, y: 55, label: 'USA' }, to: { x: 50, y: 45, label: 'Server' }, severity: 'medium', blocked: true },
];

// Animated connection line
function ConnectionLine({
  connection,
  isActive,
}: {
  connection: ThreatConnection;
  isActive: boolean;
}) {
  const color = severityColors[connection.severity];
  const { from, to, blocked } = connection;

  return (
    <g>
      {/* Connection path */}
      <motion.line
        x1={`${from.x}%`}
        y1={`${from.y}%`}
        x2={`${to.x}%`}
        y2={`${to.y}%`}
        stroke={color}
        strokeWidth="2"
        strokeDasharray={blocked ? '5 5' : '0'}
        initial={{ pathLength: 0, opacity: 0 }}
        animate={isActive ? {
          pathLength: 1,
          opacity: blocked ? 0.3 : 0.8,
        } : { pathLength: 0, opacity: 0 }}
        transition={{ duration: 1, ease: 'easeOut' }}
      />

      {/* Animated pulse along the line */}
      {isActive && !blocked && (
        <motion.circle
          r="4"
          fill={color}
          initial={{ opacity: 0 }}
          animate={{
            cx: [`${from.x}%`, `${to.x}%`],
            cy: [`${from.y}%`, `${to.y}%`],
            opacity: [0, 1, 0],
          }}
          transition={{
            duration: 2,
            repeat: Infinity,
            ease: 'linear',
          }}
        />
      )}

      {/* Blocked indicator */}
      {blocked && isActive && (
        <motion.g
          initial={{ scale: 0, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ delay: 0.5 }}
        >
          <circle
            cx={`${(from.x + to.x) / 2}%`}
            cy={`${(from.y + to.y) / 2}%`}
            r="8"
            fill="#EF4444"
          />
          <text
            x={`${(from.x + to.x) / 2}%`}
            y={`${(from.y + to.y) / 2}%`}
            textAnchor="middle"
            dominantBaseline="central"
            fill="white"
            fontSize="10"
            fontWeight="bold"
          >
            ✕
          </text>
        </motion.g>
      )}
    </g>
  );
}

// Location marker
function LocationMarker({
  x,
  y,
  label,
  isServer,
  color,
  showLabel,
}: {
  x: number;
  y: number;
  label: string;
  isServer?: boolean;
  color: string;
  showLabel: boolean;
}) {
  return (
    <motion.g
      initial={{ scale: 0, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ type: 'spring', stiffness: 300 }}
    >
      {/* Pulse ring for server */}
      {isServer && (
        <motion.circle
          cx={`${x}%`}
          cy={`${y}%`}
          r="15"
          fill="none"
          stroke="#6C47FF"
          strokeWidth="2"
          animate={{
            r: [15, 25, 15],
            opacity: [0.8, 0, 0.8],
          }}
          transition={{
            duration: 2,
            repeat: Infinity,
          }}
        />
      )}

      {/* Marker dot */}
      <circle
        cx={`${x}%`}
        cy={`${y}%`}
        r={isServer ? 10 : 6}
        fill={isServer ? '#6C47FF' : color}
      />

      {/* Inner dot for server */}
      {isServer && (
        <circle
          cx={`${x}%`}
          cy={`${y}%`}
          r="4"
          fill="white"
        />
      )}

      {/* Label */}
      {showLabel && (
        <text
          x={`${x}%`}
          y={`${y + (isServer ? 8 : 5)}%`}
          textAnchor="middle"
          fill="white"
          fontSize="10"
          opacity={0.8}
        >
          {label}
        </text>
      )}
    </motion.g>
  );
}

export function ThreatMap({
  connections = defaultConnections,
  autoAnimate = true,
  showLabels = true,
  className,
}: ThreatMapProps) {
  const [activeConnections, setActiveConnections] = useState<string[]>([]);
  const [stats, setStats] = useState({ blocked: 0, allowed: 0 });

  // Auto-animate connections
  useEffect(() => {
    if (!autoAnimate) {
      setActiveConnections(connections.map(c => c.id));
      return;
    }

    let index = 0;
    const interval = setInterval(() => {
      const connection = connections[index % connections.length];
      setActiveConnections(prev => {
        if (prev.includes(connection.id)) return prev;
        return [...prev, connection.id];
      });
      index++;

      // Update stats
      const active = connections.slice(0, index);
      setStats({
        blocked: active.filter(c => c.blocked).length,
        allowed: active.filter(c => !c.blocked).length,
      });
    }, 800);

    // Reset periodically
    const resetInterval = setInterval(() => {
      setActiveConnections([]);
      setStats({ blocked: 0, allowed: 0 });
    }, 10000);

    return () => {
      clearInterval(interval);
      clearInterval(resetInterval);
    };
  }, [autoAnimate, connections]);

  return (
    <div className={cn('relative', className)}>
      {/* Map container */}
      <div
        className="relative w-full aspect-[2/1] rounded-2xl overflow-hidden"
        style={{
          background: 'linear-gradient(135deg, #0f0f1a 0%, #1a1a2e 100%)',
          border: '1px solid rgba(108, 71, 255, 0.2)',
        }}
      >
        {/* World map outline (simplified) */}
        <svg
          viewBox="0 0 100 50"
          className="absolute inset-0 w-full h-full"
          preserveAspectRatio="xMidYMid slice"
        >
          {/* Simplified continent outlines */}
          <path
            d="M 5 20 Q 15 15 25 20 Q 30 25 25 35 Q 15 40 5 35 Z"
            fill="rgba(108, 71, 255, 0.1)"
            stroke="rgba(108, 71, 255, 0.3)"
            strokeWidth="0.5"
          />
          <path
            d="M 30 15 Q 45 10 55 15 Q 60 25 55 35 Q 45 40 35 35 Q 30 25 30 15 Z"
            fill="rgba(108, 71, 255, 0.1)"
            stroke="rgba(108, 71, 255, 0.3)"
            strokeWidth="0.5"
          />
          <path
            d="M 60 20 Q 75 15 90 20 Q 95 30 90 40 Q 75 45 65 40 Q 60 30 60 20 Z"
            fill="rgba(108, 71, 255, 0.1)"
            stroke="rgba(108, 71, 255, 0.3)"
            strokeWidth="0.5"
          />

          {/* Grid lines */}
          {[20, 40, 60, 80].map(x => (
            <line
              key={`v-${x}`}
              x1={`${x}%`}
              y1="0"
              x2={`${x}%`}
              y2="100%"
              stroke="rgba(108, 71, 255, 0.1)"
              strokeWidth="0.5"
            />
          ))}
          {[25, 50, 75].map(y => (
            <line
              key={`h-${y}`}
              x1="0"
              y1={`${y}%`}
              x2="100%"
              y2={`${y}%`}
              stroke="rgba(108, 71, 255, 0.1)"
              strokeWidth="0.5"
            />
          ))}

          {/* Connection lines */}
          {connections.map(connection => (
            <ConnectionLine
              key={connection.id}
              connection={connection}
              isActive={activeConnections.includes(connection.id)}
            />
          ))}

          {/* Location markers */}
          {connections.map(connection => (
            <LocationMarker
              key={`from-${connection.id}`}
              x={connection.from.x}
              y={connection.from.y}
              label={connection.from.label}
              color={severityColors[connection.severity]}
              showLabel={showLabels}
            />
          ))}

          {/* Server marker (center) */}
          <LocationMarker
            x={50}
            y={45}
            label="Zalt Server"
            isServer
            color="#6C47FF"
            showLabel={showLabels}
          />
        </svg>

        {/* Stats overlay */}
        <div className="absolute bottom-4 left-4 flex gap-4">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-error" />
            <span className="text-xs text-white">
              <span className="font-bold">{stats.blocked}</span> Blocked
            </span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-success" />
            <span className="text-xs text-white">
              <span className="font-bold">{stats.allowed}</span> Allowed
            </span>
          </div>
        </div>

        {/* Legend */}
        <div className="absolute top-4 right-4 flex flex-col gap-1">
          {Object.entries(severityColors).map(([severity, color]) => (
            <div key={severity} className="flex items-center gap-2">
              <div
                className="w-2 h-2 rounded-full"
                style={{ backgroundColor: color }}
              />
              <span className="text-xs text-neutral-400 capitalize">
                {severity}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default ThreatMap;
