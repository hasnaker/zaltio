'use client';

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { cn } from '@/lib/utils';
import { easings } from '@/lib/motion';

export type ThreatLevel = 'safe' | 'monitoring' | 'blocking' | 'secured';

export interface SecurityShieldProps {
  threatLevel?: ThreatLevel;
  blockedCount?: number;
  autoAnimate?: boolean;
  size?: 'sm' | 'md' | 'lg';
  showPulse?: boolean;
  showScanLine?: boolean;
  className?: string;
}

const sizeConfig = {
  sm: { width: 80, height: 96 },
  md: { width: 120, height: 144 },
  lg: { width: 160, height: 192 },
};

const threatColors: Record<ThreatLevel, { primary: string; secondary: string; glow: string }> = {
  safe: {
    primary: '#22C55E',
    secondary: '#16A34A',
    glow: 'rgba(34, 197, 94, 0.4)',
  },
  monitoring: {
    primary: '#F59E0B',
    secondary: '#D97706',
    glow: 'rgba(245, 158, 11, 0.4)',
  },
  blocking: {
    primary: '#EF4444',
    secondary: '#DC2626',
    glow: 'rgba(239, 68, 68, 0.4)',
  },
  secured: {
    primary: '#6C47FF',
    secondary: '#5B3FD9',
    glow: 'rgba(108, 71, 255, 0.4)',
  },
};

const threatLabels: Record<ThreatLevel, string> = {
  safe: 'All Clear',
  monitoring: 'Monitoring',
  blocking: 'Blocking Threat',
  secured: 'Secured',
};

export function SecurityShield({
  threatLevel = 'safe',
  blockedCount = 0,
  autoAnimate = true,
  size = 'md',
  showPulse = true,
  showScanLine = true,
  className,
}: SecurityShieldProps) {
  const [currentLevel, setCurrentLevel] = useState<ThreatLevel>(threatLevel);
  const config = sizeConfig[size];
  const colors = threatColors[currentLevel];

  // Auto-animate through states
  useEffect(() => {
    if (!autoAnimate) return;

    const levels: ThreatLevel[] = ['safe', 'monitoring', 'blocking', 'secured'];
    let index = levels.indexOf(threatLevel);

    const interval = setInterval(() => {
      index = (index + 1) % levels.length;
      setCurrentLevel(levels[index]);
    }, 3000);

    return () => clearInterval(interval);
  }, [autoAnimate, threatLevel]);

  // Update when prop changes
  useEffect(() => {
    if (!autoAnimate) {
      setCurrentLevel(threatLevel);
    }
  }, [threatLevel, autoAnimate]);

  return (
    <div
      className={cn('relative flex flex-col items-center', className)}
      style={{ width: config.width, height: config.height + 40 }}
    >
      {/* Glow effect */}
      {showPulse && (
        <motion.div
          className="absolute inset-0 rounded-full"
          style={{
            background: `radial-gradient(circle, ${colors.glow} 0%, transparent 70%)`,
            filter: 'blur(20px)',
          }}
          animate={{
            scale: [1, 1.2, 1],
            opacity: [0.5, 0.8, 0.5],
          }}
          transition={{
            duration: 2,
            repeat: Infinity,
            ease: 'easeInOut',
          }}
        />
      )}

      {/* Shield SVG */}
      <motion.svg
        viewBox="0 0 100 120"
        width={config.width}
        height={config.height}
        className="relative z-10"
        initial={{ scale: 0.8, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ duration: 0.5, ease: easings.smoothOut }}
      >
        {/* Shield body */}
        <motion.path
          d="M 50 5 L 95 25 L 95 55 C 95 85 50 115 50 115 C 50 115 5 85 5 55 L 5 25 Z"
          fill={`url(#shieldGradient-${currentLevel})`}
          stroke={colors.primary}
          strokeWidth="3"
          initial={{ pathLength: 0 }}
          animate={{ pathLength: 1 }}
          transition={{ duration: 1, ease: easings.smoothOut }}
        />

        {/* Inner shield highlight */}
        <motion.path
          d="M 50 15 L 85 32 L 85 55 C 85 78 50 102 50 102 C 50 102 15 78 15 55 L 15 32 Z"
          fill="none"
          stroke="rgba(255,255,255,0.2)"
          strokeWidth="1"
        />

        {/* Scan line effect */}
        {showScanLine && (
          <motion.rect
            x="10"
            y="20"
            width="80"
            height="4"
            fill={`url(#scanGradient-${currentLevel})`}
            rx="2"
            animate={{
              y: [20, 100, 20],
            }}
            transition={{
              duration: 2,
              repeat: Infinity,
              ease: 'linear',
            }}
          />
        )}

        {/* Center icon based on threat level */}
        <AnimatePresence mode="wait">
          <motion.g
            key={currentLevel}
            initial={{ scale: 0, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0, opacity: 0 }}
            transition={{ duration: 0.3 }}
          >
            {currentLevel === 'safe' && (
              <motion.path
                d="M 35 55 L 45 65 L 65 45"
                fill="none"
                stroke="white"
                strokeWidth="5"
                strokeLinecap="round"
                strokeLinejoin="round"
                initial={{ pathLength: 0 }}
                animate={{ pathLength: 1 }}
                transition={{ duration: 0.5, delay: 0.2 }}
              />
            )}
            {currentLevel === 'monitoring' && (
              <>
                <circle cx="50" cy="50" r="8" fill="white" />
                <motion.circle
                  cx="50"
                  cy="50"
                  r="15"
                  fill="none"
                  stroke="white"
                  strokeWidth="2"
                  animate={{ scale: [1, 1.5, 1], opacity: [1, 0, 1] }}
                  transition={{ duration: 1.5, repeat: Infinity }}
                />
              </>
            )}
            {currentLevel === 'blocking' && (
              <>
                <motion.line
                  x1="35"
                  y1="40"
                  x2="65"
                  y2="70"
                  stroke="white"
                  strokeWidth="5"
                  strokeLinecap="round"
                  initial={{ pathLength: 0 }}
                  animate={{ pathLength: 1 }}
                  transition={{ duration: 0.3 }}
                />
                <motion.line
                  x1="65"
                  y1="40"
                  x2="35"
                  y2="70"
                  stroke="white"
                  strokeWidth="5"
                  strokeLinecap="round"
                  initial={{ pathLength: 0 }}
                  animate={{ pathLength: 1 }}
                  transition={{ duration: 0.3, delay: 0.1 }}
                />
              </>
            )}
            {currentLevel === 'secured' && (
              <>
                <rect x="40" y="45" width="20" height="25" rx="3" fill="white" />
                <path
                  d="M 43 45 L 43 40 C 43 33 57 33 57 40 L 57 45"
                  fill="none"
                  stroke="white"
                  strokeWidth="3"
                  strokeLinecap="round"
                />
              </>
            )}
          </motion.g>
        </AnimatePresence>

        {/* Gradients */}
        <defs>
          {Object.entries(threatColors).map(([level, levelColors]) => (
            <React.Fragment key={level}>
              <linearGradient
                id={`shieldGradient-${level}`}
                x1="0%"
                y1="0%"
                x2="100%"
                y2="100%"
              >
                <stop offset="0%" stopColor={levelColors.primary} />
                <stop offset="100%" stopColor={levelColors.secondary} />
              </linearGradient>
              <linearGradient
                id={`scanGradient-${level}`}
                x1="0%"
                y1="0%"
                x2="100%"
                y2="0%"
              >
                <stop offset="0%" stopColor="transparent" />
                <stop offset="50%" stopColor={levelColors.primary} stopOpacity="0.8" />
                <stop offset="100%" stopColor="transparent" />
              </linearGradient>
            </React.Fragment>
          ))}
        </defs>
      </motion.svg>

      {/* Status label */}
      <AnimatePresence mode="wait">
        <motion.div
          key={currentLevel}
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -10 }}
          transition={{ duration: 0.3 }}
          className="mt-2 text-center"
        >
          <span
            className="text-sm font-semibold"
            style={{ color: colors.primary }}
          >
            {threatLabels[currentLevel]}
          </span>
          {blockedCount > 0 && currentLevel === 'blocking' && (
            <motion.p
              className="text-xs text-neutral-500 mt-1"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
            >
              {blockedCount.toLocaleString()} threats blocked
            </motion.p>
          )}
        </motion.div>
      </AnimatePresence>
    </div>
  );
}

export default SecurityShield;
