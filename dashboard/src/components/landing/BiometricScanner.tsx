'use client';

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { cn } from '@/lib/utils';
import { easings } from '@/lib/motion';

export type ScannerType = 'fingerprint' | 'face' | 'iris';
export type ScannerState = 'idle' | 'scanning' | 'success' | 'failed';

export interface BiometricScannerProps {
  type?: ScannerType;
  state?: ScannerState;
  progress?: number;
  autoAnimate?: boolean;
  showGrid?: boolean;
  size?: 'sm' | 'md' | 'lg';
  onComplete?: () => void;
  className?: string;
}

const sizeConfig = {
  sm: { width: 100, height: 100 },
  md: { width: 150, height: 150 },
  lg: { width: 200, height: 200 },
};

const stateColors = {
  idle: '#6C47FF',
  scanning: '#00D4FF',
  success: '#22C55E',
  failed: '#EF4444',
};

const stateLabels: Record<ScannerState, string> = {
  idle: 'Place finger',
  scanning: 'Scanning...',
  success: 'Verified',
  failed: 'Try again',
};

export function BiometricScanner({
  type = 'fingerprint',
  state: initialState = 'idle',
  progress: initialProgress = 0,
  autoAnimate = true,
  showGrid = true,
  size = 'md',
  onComplete,
  className,
}: BiometricScannerProps) {
  const [state, setState] = useState<ScannerState>(initialState);
  const [progress, setProgress] = useState(initialProgress);
  const config = sizeConfig[size];
  const color = stateColors[state];

  // Auto-animate scanning sequence
  useEffect(() => {
    if (!autoAnimate) return;

    const sequence = async () => {
      // Start scanning
      setState('scanning');
      setProgress(0);

      // Animate progress
      for (let i = 0; i <= 100; i += 2) {
        await new Promise(resolve => setTimeout(resolve, 30));
        setProgress(i);
      }

      // Success
      setState('success');
      onComplete?.();

      // Reset after delay
      await new Promise(resolve => setTimeout(resolve, 2000));
      setState('idle');
      setProgress(0);
    };

    const timer = setTimeout(sequence, 1000);
    const interval = setInterval(sequence, 6000);

    return () => {
      clearTimeout(timer);
      clearInterval(interval);
    };
  }, [autoAnimate, onComplete]);

  // Update when props change
  useEffect(() => {
    if (!autoAnimate) {
      setState(initialState);
      setProgress(initialProgress);
    }
  }, [initialState, initialProgress, autoAnimate]);

  return (
    <div
      className={cn('relative flex flex-col items-center', className)}
      style={{ width: config.width, height: config.height + 40 }}
    >
      {/* Scanner container */}
      <motion.div
        className="relative rounded-2xl overflow-hidden"
        style={{
          width: config.width,
          height: config.height,
          background: 'linear-gradient(135deg, #1a1a2e 0%, #0f0f1a 100%)',
          boxShadow: `0 0 30px ${color}40`,
        }}
        animate={{
          boxShadow: state === 'scanning' 
            ? [`0 0 30px ${color}40`, `0 0 50px ${color}60`, `0 0 30px ${color}40`]
            : `0 0 30px ${color}40`,
        }}
        transition={{ duration: 1, repeat: state === 'scanning' ? Infinity : 0 }}
      >
        {/* Grid overlay */}
        {showGrid && (
          <div
            className="absolute inset-0 opacity-20"
            style={{
              backgroundImage: `
                linear-gradient(${color}40 1px, transparent 1px),
                linear-gradient(90deg, ${color}40 1px, transparent 1px)
              `,
              backgroundSize: '20px 20px',
            }}
          />
        )}

        {/* Fingerprint icon */}
        {type === 'fingerprint' && (
          <motion.svg
            viewBox="0 0 100 100"
            className="absolute inset-0 w-full h-full p-6"
            initial={{ opacity: 0.3 }}
            animate={{ opacity: state === 'scanning' ? [0.3, 0.8, 0.3] : 0.5 }}
            transition={{ duration: 1.5, repeat: state === 'scanning' ? Infinity : 0 }}
          >
            {/* Fingerprint ridges */}
            {[0, 1, 2, 3, 4].map((i) => (
              <motion.ellipse
                key={i}
                cx="50"
                cy="50"
                rx={15 + i * 8}
                ry={20 + i * 10}
                fill="none"
                stroke={color}
                strokeWidth="2"
                strokeDasharray="5 3"
                initial={{ pathLength: 0, opacity: 0 }}
                animate={{ 
                  pathLength: state === 'scanning' ? 1 : 0.7,
                  opacity: state === 'idle' ? 0.3 : 1,
                }}
                transition={{ 
                  duration: 0.5, 
                  delay: i * 0.1,
                  ease: easings.smoothOut,
                }}
              />
            ))}
            {/* Center whorl */}
            <motion.circle
              cx="50"
              cy="45"
              r="8"
              fill="none"
              stroke={color}
              strokeWidth="2"
              animate={{
                scale: state === 'success' ? [1, 1.2, 1] : 1,
              }}
              transition={{ duration: 0.3 }}
            />
          </motion.svg>
        )}

        {/* Face icon */}
        {type === 'face' && (
          <motion.svg
            viewBox="0 0 100 100"
            className="absolute inset-0 w-full h-full p-6"
          >
            <motion.ellipse
              cx="50"
              cy="50"
              rx="30"
              ry="38"
              fill="none"
              stroke={color}
              strokeWidth="2"
              animate={{ opacity: state === 'scanning' ? [0.5, 1, 0.5] : 0.7 }}
              transition={{ duration: 1, repeat: state === 'scanning' ? Infinity : 0 }}
            />
            {/* Eyes */}
            <circle cx="38" cy="42" r="4" fill={color} opacity={0.8} />
            <circle cx="62" cy="42" r="4" fill={color} opacity={0.8} />
            {/* Nose */}
            <line x1="50" y1="48" x2="50" y2="58" stroke={color} strokeWidth="2" opacity={0.6} />
            {/* Mouth */}
            <motion.path
              d="M 40 68 Q 50 75 60 68"
              fill="none"
              stroke={color}
              strokeWidth="2"
              opacity={0.6}
              animate={{
                d: state === 'success' ? 'M 40 65 Q 50 78 60 65' : 'M 40 68 Q 50 75 60 68',
              }}
            />
          </motion.svg>
        )}

        {/* Iris icon */}
        {type === 'iris' && (
          <motion.svg
            viewBox="0 0 100 100"
            className="absolute inset-0 w-full h-full p-6"
          >
            {/* Outer eye */}
            <motion.ellipse
              cx="50"
              cy="50"
              rx="40"
              ry="25"
              fill="none"
              stroke={color}
              strokeWidth="2"
              animate={{ opacity: state === 'scanning' ? [0.5, 1, 0.5] : 0.7 }}
              transition={{ duration: 1, repeat: state === 'scanning' ? Infinity : 0 }}
            />
            {/* Iris */}
            <motion.circle
              cx="50"
              cy="50"
              r="18"
              fill="none"
              stroke={color}
              strokeWidth="3"
              animate={{
                r: state === 'scanning' ? [18, 20, 18] : 18,
              }}
              transition={{ duration: 0.5, repeat: state === 'scanning' ? Infinity : 0 }}
            />
            {/* Pupil */}
            <motion.circle
              cx="50"
              cy="50"
              r="8"
              fill={color}
              animate={{
                r: state === 'scanning' ? [8, 6, 8] : 8,
              }}
              transition={{ duration: 0.5, repeat: state === 'scanning' ? Infinity : 0 }}
            />
            {/* Iris pattern */}
            {[0, 45, 90, 135, 180, 225, 270, 315].map((angle) => (
              <motion.line
                key={angle}
                x1={50 + Math.cos(angle * Math.PI / 180) * 10}
                y1={50 + Math.sin(angle * Math.PI / 180) * 10}
                x2={50 + Math.cos(angle * Math.PI / 180) * 17}
                y2={50 + Math.sin(angle * Math.PI / 180) * 17}
                stroke={color}
                strokeWidth="1"
                opacity={0.5}
              />
            ))}
          </motion.svg>
        )}

        {/* Scan line */}
        {state === 'scanning' && (
          <motion.div
            className="absolute left-0 right-0 h-1"
            style={{
              background: `linear-gradient(90deg, transparent, ${color}, transparent)`,
              boxShadow: `0 0 10px ${color}`,
            }}
            animate={{
              top: ['0%', '100%', '0%'],
            }}
            transition={{
              duration: 2,
              repeat: Infinity,
              ease: 'linear',
            }}
          />
        )}

        {/* Progress ring */}
        {state === 'scanning' && (
          <svg
            className="absolute inset-0 w-full h-full"
            style={{ transform: 'rotate(-90deg)' }}
          >
            <circle
              cx="50%"
              cy="50%"
              r="45%"
              fill="none"
              stroke={color}
              strokeWidth="2"
              strokeDasharray={`${progress * 2.83} 283`}
              opacity={0.8}
            />
          </svg>
        )}

        {/* Success/Failed overlay */}
        <AnimatePresence>
          {(state === 'success' || state === 'failed') && (
            <motion.div
              className="absolute inset-0 flex items-center justify-center"
              initial={{ opacity: 0, scale: 0.5 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.5 }}
              style={{ backgroundColor: `${color}20` }}
            >
              {state === 'success' && (
                <motion.svg
                  viewBox="0 0 50 50"
                  className="w-16 h-16"
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                  transition={{ type: 'spring', stiffness: 300 }}
                >
                  <motion.path
                    d="M 10 25 L 20 35 L 40 15"
                    fill="none"
                    stroke={color}
                    strokeWidth="4"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    initial={{ pathLength: 0 }}
                    animate={{ pathLength: 1 }}
                    transition={{ duration: 0.3 }}
                  />
                </motion.svg>
              )}
              {state === 'failed' && (
                <motion.svg
                  viewBox="0 0 50 50"
                  className="w-16 h-16"
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                  transition={{ type: 'spring', stiffness: 300 }}
                >
                  <motion.path
                    d="M 15 15 L 35 35 M 35 15 L 15 35"
                    fill="none"
                    stroke={color}
                    strokeWidth="4"
                    strokeLinecap="round"
                    initial={{ pathLength: 0 }}
                    animate={{ pathLength: 1 }}
                    transition={{ duration: 0.3 }}
                  />
                </motion.svg>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>

      {/* Status label */}
      <motion.div
        className="mt-3 text-center"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
      >
        <span
          className="text-sm font-medium"
          style={{ color }}
        >
          {stateLabels[state]}
        </span>
        {state === 'scanning' && (
          <p className="text-xs text-neutral-500 mt-1">
            {progress}%
          </p>
        )}
      </motion.div>
    </div>
  );
}

export default BiometricScanner;
