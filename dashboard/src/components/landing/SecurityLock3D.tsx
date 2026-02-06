'use client';

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { motion, AnimatePresence, useAnimation, useReducedMotion } from 'framer-motion';
import { cn } from '@/lib/utils';
import { easings, springs } from '@/lib/motion';

export interface SecurityLock3DProps {
  /** Auto-play the unlock animation */
  autoPlay?: boolean;
  /** Loop the animation */
  loop?: boolean;
  /** Size variant */
  size?: 'sm' | 'md' | 'lg' | 'xl' | 'hero';
  /** Show particle explosion effect */
  showParticles?: boolean;
  /** Show glow effect */
  showGlow?: boolean;
  /** Show rotating ring */
  showRing?: boolean;
  /** Callback when unlock completes */
  onUnlock?: () => void;
  /** Additional CSS classes */
  className?: string;
  /** Test ID for testing */
  'data-testid'?: string;
}

const sizeConfig = {
  sm: { width: 80, height: 100, strokeWidth: 2, particleCount: 10 },
  md: { width: 120, height: 150, strokeWidth: 3, particleCount: 15 },
  lg: { width: 180, height: 225, strokeWidth: 4, particleCount: 20 },
  xl: { width: 240, height: 300, strokeWidth: 5, particleCount: 25 },
  hero: { width: 320, height: 400, strokeWidth: 6, particleCount: 30 },
};

// Particle component for explosion effect
const Particle = ({ 
  index, 
  isActive,
  reducedMotion,
}: { 
  index: number; 
  isActive: boolean;
  reducedMotion: boolean;
}) => {
  const angle = (index / 20) * Math.PI * 2;
  const distance = 80 + Math.random() * 60;
  const x = Math.cos(angle) * distance;
  const y = Math.sin(angle) * distance;
  const size = 4 + Math.random() * 6;
  const colors = ['#6C47FF', '#00D4FF', '#8B5CF6', '#0EA5E9', '#22C55E'];
  const color = colors[index % colors.length];

  if (reducedMotion) {
    return isActive ? (
      <div
        className="absolute rounded-full"
        style={{
          width: size,
          height: size,
          backgroundColor: color,
          left: '50%',
          top: '50%',
          marginLeft: -size / 2,
          marginTop: -size / 2,
          transform: `translate(${x}px, ${y}px)`,
          opacity: 0.5,
        }}
      />
    ) : null;
  }

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

// Rotating ring component
const RotatingRing = ({ 
  size, 
  reducedMotion 
}: { 
  size: number; 
  reducedMotion: boolean;
}) => {
  if (reducedMotion) {
    return (
      <div
        className="absolute rounded-full border-2 border-dashed"
        style={{
          width: size * 1.4,
          height: size * 1.4,
          borderColor: 'rgba(108, 71, 255, 0.3)',
          left: '50%',
          top: '50%',
          transform: 'translate(-50%, -50%)',
        }}
      />
    );
  }

  return (
    <motion.div
      className="absolute rounded-full border-2 border-dashed"
      style={{
        width: size * 1.4,
        height: size * 1.4,
        borderColor: 'rgba(108, 71, 255, 0.3)',
        left: '50%',
        top: '50%',
        marginLeft: -(size * 1.4) / 2,
        marginTop: -(size * 1.4) / 2,
      }}
      animate={{ rotate: 360 }}
      transition={{
        duration: 20,
        repeat: Infinity,
        ease: 'linear',
      }}
    />
  );
};

export function SecurityLock3D({
  autoPlay = true,
  loop = true,
  size = 'hero',
  showParticles = true,
  showGlow = true,
  showRing = true,
  onUnlock,
  className,
  'data-testid': testId = 'security-lock-3d',
}: SecurityLock3DProps) {
  const [state, setState] = useState<'locked' | 'unlocking' | 'unlocked'>('locked');
  const [showParticleExplosion, setShowParticleExplosion] = useState(false);
  const controls = useAnimation();
  const config = sizeConfig[size];
  
  // Use Framer Motion's built-in reduced motion hook
  const shouldReduceMotion = useReducedMotion();
  const reducedMotion = shouldReduceMotion ?? false;

  // Memoize particles array
  const particles = useMemo(() => 
    Array.from({ length: config.particleCount }), 
    [config.particleCount]
  );

  const runUnlockSequence = useCallback(async () => {
    if (reducedMotion) {
      // Instant state change for reduced motion
      setState('unlocking');
      await new Promise(resolve => setTimeout(resolve, 100));
      if (showParticles) {
        setShowParticleExplosion(true);
      }
      setState('unlocked');
      onUnlock?.();

      if (loop) {
        await new Promise(resolve => setTimeout(resolve, 2000));
        setShowParticleExplosion(false);
        setState('locked');
      }
      return;
    }

    setState('unlocking');
    
    // Shackle rises with 3D rotation
    await controls.start({
      y: -config.height * 0.15,
      rotateX: -15,
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
        rotateX: 0,
        transition: { duration: 0.3, ease: easings.smoothOut },
      });
      setState('locked');
    }
  }, [controls, config.height, loop, onUnlock, showParticles, reducedMotion]);

  useEffect(() => {
    if (autoPlay) {
      const initialDelay = reducedMotion ? 500 : 2000;
      const loopInterval = reducedMotion ? 4000 : 8000;

      const timer = setTimeout(() => {
        runUnlockSequence();
      }, initialDelay);

      const loopTimer = loop ? setInterval(() => {
        runUnlockSequence();
      }, loopInterval) : null;

      return () => {
        clearTimeout(timer);
        if (loopTimer) clearInterval(loopTimer);
      };
    }
  }, [autoPlay, loop, runUnlockSequence, reducedMotion]);

  // Static version for reduced motion
  if (reducedMotion) {
    return (
      <div 
        className={cn(
          'relative flex items-center justify-center',
          className
        )}
        style={{ width: config.width, height: config.height }}
        data-testid={testId}
        data-reduced-motion="true"
      >
        {/* Static glow */}
        {showGlow && (
          <div
            className="absolute inset-0 rounded-full"
            style={{
              background: state === 'unlocked' 
                ? 'radial-gradient(circle, rgba(34, 197, 94, 0.3) 0%, transparent 70%)'
                : 'radial-gradient(circle, rgba(108, 71, 255, 0.3) 0%, transparent 70%)',
              filter: 'blur(40px)',
            }}
          />
        )}

        {/* Static ring */}
        {showRing && <RotatingRing size={config.width} reducedMotion={true} />}

        {/* Static particles */}
        {showParticles && (
          <div className="absolute inset-0 pointer-events-none">
            {particles.map((_, i) => (
              <Particle key={i} index={i} isActive={showParticleExplosion} reducedMotion={true} />
            ))}
          </div>
        )}

        {/* Static Lock SVG */}
        <svg
          viewBox="0 0 100 125"
          width={config.width}
          height={config.height}
          className="relative z-10"
          style={{ 
            filter: state === 'unlocked' ? 'drop-shadow(0 0 20px rgba(34, 197, 94, 0.5))' : 'none',
          }}
        >
          {/* Lock body */}
          <rect
            x="15"
            y="50"
            width="70"
            height="55"
            rx="8"
            fill={state === 'unlocked' ? 'url(#lockGradientUnlocked3D)' : 'url(#lockGradient3D)'}
            stroke="url(#strokeGradient3D)"
            strokeWidth={config.strokeWidth}
          />

          {/* Keyhole */}
          <circle
            cx="50"
            cy="72"
            r="8"
            fill={state === 'unlocked' ? '#22C55E' : '#0F0F10'}
          />
          <rect
            x="47"
            y="75"
            width="6"
            height="15"
            rx="2"
            fill={state === 'unlocked' ? '#22C55E' : '#0F0F10'}
          />

          {/* Shackle */}
          <path
            d="M 30 50 L 30 35 C 30 20 70 20 70 35 L 70 50"
            fill="none"
            stroke="url(#strokeGradient3D)"
            strokeWidth={config.strokeWidth}
            strokeLinecap="round"
            style={{
              transform: state === 'unlocked' ? 'translateY(-15px)' : 'none',
              transformOrigin: '70% 100%',
            }}
          />

          {/* Gradients */}
          <defs>
            <linearGradient id="lockGradient3D" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#6C47FF" />
              <stop offset="100%" stopColor="#8B5CF6" />
            </linearGradient>
            <linearGradient id="lockGradientUnlocked3D" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#22C55E" />
              <stop offset="100%" stopColor="#16A34A" />
            </linearGradient>
            <linearGradient id="strokeGradient3D" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#00D4FF" />
              <stop offset="100%" stopColor="#6C47FF" />
            </linearGradient>
          </defs>
        </svg>

        {/* Status text */}
        <div className="absolute -bottom-8 left-1/2 -translate-x-1/2 whitespace-nowrap">
          <span className={cn(
            'text-sm font-medium',
            state === 'locked' && 'text-neutral-500',
            state === 'unlocking' && 'text-primary',
            state === 'unlocked' && 'text-green-500',
          )}>
            {state === 'locked' && 'Secured'}
            {state === 'unlocking' && 'Authenticating...'}
            {state === 'unlocked' && 'Access Granted'}
          </span>
        </div>
      </div>
    );
  }

  // Full animated version
  return (
    <div 
      className={cn(
        'relative flex items-center justify-center',
        className
      )}
      style={{ 
        width: config.width, 
        height: config.height,
        perspective: '1000px',
      }}
      data-testid={testId}
      data-reduced-motion="false"
    >
      {/* Animated glow effect */}
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
            background: 'radial-gradient(circle, rgba(34, 197, 94, 0.4) 0%, transparent 70%)',
          } : {
            scale: [1, 1.1, 1],
            opacity: [0.3, 0.5, 0.3],
          }}
          transition={{ 
            duration: state === 'unlocked' ? 1 : 3, 
            ease: 'easeInOut',
            repeat: state === 'unlocked' ? 0 : Infinity,
          }}
        />
      )}

      {/* Rotating ring */}
      {showRing && <RotatingRing size={config.width} reducedMotion={false} />}

      {/* Particle explosion */}
      {showParticles && (
        <div className="absolute inset-0 pointer-events-none">
          {particles.map((_, i) => (
            <Particle key={i} index={i} isActive={showParticleExplosion} reducedMotion={false} />
          ))}
        </div>
      )}

      {/* 3D Lock SVG */}
      <motion.svg
        viewBox="0 0 100 125"
        width={config.width}
        height={config.height}
        className="relative z-10"
        initial={{ opacity: 0, scale: 0.5, rotateY: -30, rotateX: 15 }}
        animate={{ 
          opacity: 1, 
          scale: 1, 
          rotateY: 0,
          rotateX: 0,
        }}
        transition={{ 
          duration: 1.2, 
          ease: easings.dramatic,
          delay: 0.3,
        }}
        style={{ 
          transformStyle: 'preserve-3d',
          filter: state === 'unlocked' 
            ? 'drop-shadow(0 0 30px rgba(34, 197, 94, 0.6))' 
            : 'drop-shadow(0 0 15px rgba(108, 71, 255, 0.3))',
        }}
      >
        {/* Lock body with 3D effect */}
        <motion.rect
          x="15"
          y="50"
          width="70"
          height="55"
          rx="8"
          fill={state === 'unlocked' ? 'url(#lockGradientUnlocked3D)' : 'url(#lockGradient3D)'}
          stroke="url(#strokeGradient3D)"
          strokeWidth={config.strokeWidth}
          animate={{
            fill: state === 'unlocked' ? 'url(#lockGradientUnlocked3D)' : 'url(#lockGradient3D)',
          }}
          transition={{ duration: 0.3 }}
        />

        {/* 3D highlight on lock body */}
        <rect
          x="18"
          y="53"
          width="30"
          height="8"
          rx="4"
          fill="rgba(255, 255, 255, 0.1)"
        />

        {/* Keyhole with glow */}
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

        {/* Shackle (animated part) with 3D rotation */}
        <motion.path
          d="M 30 50 L 30 35 C 30 20 70 20 70 35 L 70 50"
          fill="none"
          stroke="url(#strokeGradient3D)"
          strokeWidth={config.strokeWidth}
          strokeLinecap="round"
          animate={controls}
          style={{ originX: '70%', originY: '100%' }}
        />

        {/* Gradients */}
        <defs>
          <linearGradient id="lockGradient3D" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#6C47FF" />
            <stop offset="50%" stopColor="#8B5CF6" />
            <stop offset="100%" stopColor="#6C47FF" />
          </linearGradient>
          <linearGradient id="lockGradientUnlocked3D" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#22C55E" />
            <stop offset="50%" stopColor="#4ADE80" />
            <stop offset="100%" stopColor="#16A34A" />
          </linearGradient>
          <linearGradient id="strokeGradient3D" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#00D4FF" />
            <stop offset="50%" stopColor="#6C47FF" />
            <stop offset="100%" stopColor="#00D4FF" />
          </linearGradient>
          <filter id="glow3D">
            <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
            <feMerge>
              <feMergeNode in="coloredBlur"/>
              <feMergeNode in="SourceGraphic"/>
            </feMerge>
          </filter>
        </defs>
      </motion.svg>

      {/* Status text with animation */}
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
            state === 'unlocked' && 'text-green-500',
          )}>
            {state === 'locked' && 'Secured'}
            {state === 'unlocking' && 'Authenticating...'}
            {state === 'unlocked' && 'Access Granted'}
          </span>
        </motion.div>
      </AnimatePresence>

      {/* Floating animation when idle */}
      <motion.div
        className="absolute inset-0 pointer-events-none"
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

export default SecurityLock3D;
