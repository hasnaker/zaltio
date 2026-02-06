'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence, useAnimation } from 'framer-motion';
import { cn } from '@/lib/utils';
import { easings } from '@/lib/motion';

export interface HeroLockProps {
  autoPlay?: boolean;
  loop?: boolean;
  size?: 'md' | 'lg' | 'xl' | 'hero';
  showParticles?: boolean;
  showGlow?: boolean;
  onUnlock?: () => void;
  className?: string;
}

const sizeConfig = {
  md: { width: 120, height: 150, strokeWidth: 3 },
  lg: { width: 180, height: 225, strokeWidth: 4 },
  xl: { width: 240, height: 300, strokeWidth: 5 },
  hero: { width: 320, height: 400, strokeWidth: 6 },
};

// Particle component for explosion effect
const Particle = ({ 
  index, 
  isActive 
}: { 
  index: number; 
  isActive: boolean;
}) => {
  const angle = (index / 20) * Math.PI * 2;
  const distance = 80 + Math.random() * 60;
  const x = Math.cos(angle) * distance;
  const y = Math.sin(angle) * distance;
  const size = 4 + Math.random() * 6;
  const colors = ['#6C47FF', '#00D4FF', '#8B5CF6', '#0EA5E9'];
  const color = colors[index % colors.length];

  return (
    <motion.div
      className="absolute rounded-full"
      style={{
        width: size,
        height: size,
        backgroundColor: color,
        left: '50%',
        top: '50%',
        marginLeft: -size / 2,
        marginTop: -size / 2,
      }}
      initial={{ scale: 0, x: 0, y: 0, opacity: 1 }}
      animate={isActive ? {
        scale: [0, 1, 0.5],
        x: [0, x * 0.5, x],
        y: [0, y * 0.5, y],
        opacity: [1, 1, 0],
      } : { scale: 0, opacity: 0 }}
      transition={{
        duration: 0.8,
        ease: 'easeOut',
        delay: index * 0.02,
      }}
    />
  );
};

export function HeroLock({
  autoPlay = true,
  loop = true,
  size = 'hero',
  showParticles = true,
  showGlow = true,
  onUnlock,
  className,
}: HeroLockProps) {
  const [state, setState] = useState<'locked' | 'unlocking' | 'unlocked'>('locked');
  const [showParticleExplosion, setShowParticleExplosion] = useState(false);
  const controls = useAnimation();
  const config = sizeConfig[size];

  const runUnlockSequence = useCallback(async () => {
    setState('unlocking');
    
    // Shackle rises
    await controls.start({
      y: -config.height * 0.15,
      transition: { duration: 0.5, ease: easings.smoothOut },
    });

    // Trigger particle explosion
    if (showParticles) {
      setShowParticleExplosion(true);
    }

    setState('unlocked');
    onUnlock?.();

    // Reset after delay if looping
    if (loop) {
      await new Promise(resolve => setTimeout(resolve, 3000));
      setShowParticleExplosion(false);
      await controls.start({
        y: 0,
        transition: { duration: 0.3, ease: easings.smoothOut },
      });
      setState('locked');
    }
  }, [controls, config.height, loop, onUnlock, showParticles]);

  useEffect(() => {
    if (autoPlay) {
      const timer = setTimeout(() => {
        runUnlockSequence();
      }, 2000);

      const loopTimer = loop ? setInterval(() => {
        runUnlockSequence();
      }, 8000) : null;

      return () => {
        clearTimeout(timer);
        if (loopTimer) clearInterval(loopTimer);
      };
    }
  }, [autoPlay, loop, runUnlockSequence]);

  return (
    <div 
      className={cn(
        'relative flex items-center justify-center',
        className
      )}
      style={{ width: config.width, height: config.height }}
    >
      {/* Glow effect */}
      {showGlow && (
        <motion.div
          className="absolute inset-0 rounded-full"
          style={{
            background: 'radial-gradient(circle, rgba(108, 71, 255, 0.3) 0%, transparent 70%)',
            filter: 'blur(40px)',
          }}
          animate={state === 'unlocked' ? {
            scale: [1, 1.3, 1.1],
            opacity: [0.5, 0.8, 0.6],
          } : {
            scale: 1,
            opacity: 0.3,
          }}
          transition={{ duration: 1, ease: 'easeInOut' }}
        />
      )}

      {/* Particle explosion */}
      {showParticles && (
        <div className="absolute inset-0 pointer-events-none">
          {Array.from({ length: 20 }).map((_, i) => (
            <Particle key={i} index={i} isActive={showParticleExplosion} />
          ))}
        </div>
      )}

      {/* Lock SVG */}
      <motion.svg
        viewBox="0 0 100 125"
        width={config.width}
        height={config.height}
        className="relative z-10"
        initial={{ opacity: 0, scale: 0.5, rotateY: -30 }}
        animate={{ 
          opacity: 1, 
          scale: 1, 
          rotateY: 0,
        }}
        transition={{ 
          duration: 1.2, 
          ease: easings.dramatic,
          delay: 0.3,
        }}
        style={{ 
          transformStyle: 'preserve-3d',
          filter: state === 'unlocked' ? 'drop-shadow(0 0 20px rgba(108, 71, 255, 0.5))' : 'none',
        }}
      >
        {/* Lock body */}
        <rect
          x="15"
          y="50"
          width="70"
          height="55"
          rx="8"
          fill={state === 'unlocked' ? 'url(#lockGradientUnlocked)' : 'url(#lockGradient)'}
          stroke="url(#strokeGradient)"
          strokeWidth={config.strokeWidth}
          style={{ transition: 'fill 0.3s ease' }}
        />

        {/* Keyhole */}
        <motion.circle
          cx="50"
          cy="72"
          r="8"
          initial={{ fill: '#0F0F10' }}
          animate={{ 
            fill: state === 'unlocked' ? '#22C55E' : '#0F0F10',
            scale: state === 'unlocked' ? 1.1 : 1,
          }}
          transition={{ duration: 0.3 }}
        />
        <motion.rect
          x="47"
          y="75"
          width="6"
          height="15"
          rx="2"
          initial={{ fill: '#0F0F10' }}
          animate={{ fill: state === 'unlocked' ? '#22C55E' : '#0F0F10' }}
          transition={{ duration: 0.3 }}
        />

        {/* Shackle (animated part) */}
        <motion.path
          d="M 30 50 L 30 35 C 30 20 70 20 70 35 L 70 50"
          fill="none"
          stroke="url(#strokeGradient)"
          strokeWidth={config.strokeWidth}
          strokeLinecap="round"
          animate={controls}
          style={{ originX: '70%', originY: '100%' }}
        />

        {/* Gradients */}
        <defs>
          <linearGradient id="lockGradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#6C47FF" />
            <stop offset="100%" stopColor="#8B5CF6" />
          </linearGradient>
          <linearGradient id="lockGradientUnlocked" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#22C55E" />
            <stop offset="100%" stopColor="#16A34A" />
          </linearGradient>
          <linearGradient id="strokeGradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#00D4FF" />
            <stop offset="100%" stopColor="#6C47FF" />
          </linearGradient>
        </defs>
      </motion.svg>

      {/* Status text */}
      <AnimatePresence mode="wait">
        <motion.div
          key={state}
          className="absolute -bottom-8 left-1/2 -translate-x-1/2 whitespace-nowrap"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -10 }}
          transition={{ duration: 0.3 }}
        >
          <span className={cn(
            'text-sm font-medium',
            state === 'locked' && 'text-neutral-500',
            state === 'unlocking' && 'text-primary',
            state === 'unlocked' && 'text-success',
          )}>
            {state === 'locked' && 'Secured'}
            {state === 'unlocking' && 'Authenticating...'}
            {state === 'unlocked' && 'Access Granted'}
          </span>
        </motion.div>
      </AnimatePresence>

      {/* Floating animation when idle */}
      <motion.div
        className="absolute inset-0"
        animate={{
          y: [0, -8, 0],
        }}
        transition={{
          duration: 4,
          repeat: Infinity,
          ease: 'easeInOut',
        }}
      />
    </div>
  );
}

export default HeroLock;
