'use client';

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { cn } from '@/lib/utils';
import { Lock, Unlock, Shield } from 'lucide-react';

export type EncryptionAlgorithm = 'AES-256' | 'RSA-4096' | 'Argon2id';
export type EncryptionState = 'idle' | 'encrypting' | 'encrypted' | 'decrypting';

export interface EncryptionVisualizerProps {
  algorithm?: EncryptionAlgorithm;
  state?: EncryptionState;
  autoAnimate?: boolean;
  showDataFlow?: boolean;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

const sizeConfig = {
  sm: { width: 200, height: 120 },
  md: { width: 300, height: 160 },
  lg: { width: 400, height: 200 },
};

const algorithmInfo: Record<EncryptionAlgorithm, { name: string; bits: string; type: string }> = {
  'AES-256': { name: 'AES-256-GCM', bits: '256-bit', type: 'Symmetric' },
  'RSA-4096': { name: 'RSA-4096', bits: '4096-bit', type: 'Asymmetric' },
  'Argon2id': { name: 'Argon2id', bits: '32MB', type: 'Password Hash' },
};

const stateColors = {
  idle: '#6C47FF',
  encrypting: '#00D4FF',
  encrypted: '#22C55E',
  decrypting: '#F59E0B',
};

// Data particle component
function DataParticle({ 
  index, 
  isActive, 
  direction,
  color,
}: { 
  index: number; 
  isActive: boolean;
  direction: 'encrypt' | 'decrypt';
  color: string;
}) {
  const startX = direction === 'encrypt' ? 0 : 100;
  const endX = direction === 'encrypt' ? 100 : 0;
  const delay = index * 0.1;

  return (
    <motion.div
      className="absolute w-2 h-2 rounded-full"
      style={{
        backgroundColor: color,
        boxShadow: `0 0 8px ${color}`,
        top: `${30 + (index % 3) * 20}%`,
      }}
      initial={{ left: `${startX}%`, opacity: 0, scale: 0 }}
      animate={isActive ? {
        left: [`${startX}%`, '50%', `${endX}%`],
        opacity: [0, 1, 0],
        scale: [0, 1, 0],
      } : { opacity: 0 }}
      transition={{
        duration: 1.5,
        delay,
        repeat: isActive ? Infinity : 0,
        repeatDelay: 0.5,
      }}
    />
  );
}

export function EncryptionVisualizer({
  algorithm = 'AES-256',
  state: initialState = 'idle',
  autoAnimate = true,
  showDataFlow = true,
  size = 'md',
  className,
}: EncryptionVisualizerProps) {
  const [state, setState] = useState<EncryptionState>(initialState);
  const [currentAlgorithm, setCurrentAlgorithm] = useState<EncryptionAlgorithm>(algorithm);
  const config = sizeConfig[size];
  const color = stateColors[state];
  const info = algorithmInfo[currentAlgorithm];

  // Auto-animate through states
  useEffect(() => {
    if (!autoAnimate) return;

    const algorithms: EncryptionAlgorithm[] = ['AES-256', 'RSA-4096', 'Argon2id'];
    let algIndex = 0;

    const sequence = async () => {
      // Encrypting
      setState('encrypting');
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Encrypted
      setState('encrypted');
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      // Decrypting
      setState('decrypting');
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Back to idle, change algorithm
      setState('idle');
      algIndex = (algIndex + 1) % algorithms.length;
      setCurrentAlgorithm(algorithms[algIndex]);
    };

    const timer = setTimeout(sequence, 500);
    const interval = setInterval(sequence, 6500);

    return () => {
      clearTimeout(timer);
      clearInterval(interval);
    };
  }, [autoAnimate]);

  // Update when props change
  useEffect(() => {
    if (!autoAnimate) {
      setState(initialState);
      setCurrentAlgorithm(algorithm);
    }
  }, [initialState, algorithm, autoAnimate]);

  const isProcessing = state === 'encrypting' || state === 'decrypting';

  return (
    <div
      className={cn('relative', className)}
      style={{ width: config.width, height: config.height }}
    >
      {/* Background */}
      <div
        className="absolute inset-0 rounded-2xl"
        style={{
          background: 'linear-gradient(135deg, #1a1a2e 0%, #0f0f1a 100%)',
          border: `1px solid ${color}30`,
        }}
      />

      {/* Data flow particles */}
      {showDataFlow && isProcessing && (
        <div className="absolute inset-0 overflow-hidden rounded-2xl">
          {Array.from({ length: 6 }).map((_, i) => (
            <DataParticle
              key={i}
              index={i}
              isActive={isProcessing}
              direction={state === 'encrypting' ? 'encrypt' : 'decrypt'}
              color={color}
            />
          ))}
        </div>
      )}

      {/* Left side - Plain data */}
      <motion.div
        className="absolute left-4 top-1/2 -translate-y-1/2 flex flex-col items-center"
        animate={{
          opacity: state === 'encrypted' ? 0.3 : 1,
        }}
      >
        <div
          className="w-12 h-12 rounded-lg flex items-center justify-center"
          style={{ backgroundColor: `${color}20` }}
        >
          <Unlock size={24} style={{ color }} />
        </div>
        <span className="text-xs text-neutral-400 mt-2">Plain</span>
      </motion.div>

      {/* Center - Algorithm */}
      <motion.div
        className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 flex flex-col items-center"
        animate={{
          scale: isProcessing ? [1, 1.05, 1] : 1,
        }}
        transition={{
          duration: 0.5,
          repeat: isProcessing ? Infinity : 0,
        }}
      >
        <motion.div
          className="w-16 h-16 rounded-xl flex items-center justify-center"
          style={{
            backgroundColor: `${color}20`,
            border: `2px solid ${color}`,
            boxShadow: isProcessing ? `0 0 20px ${color}40` : 'none',
          }}
          animate={{
            rotate: isProcessing ? 360 : 0,
          }}
          transition={{
            duration: 3,
            repeat: isProcessing ? Infinity : 0,
            ease: 'linear',
          }}
        >
          <Shield size={28} style={{ color }} />
        </motion.div>
        
        <AnimatePresence mode="wait">
          <motion.div
            key={currentAlgorithm}
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -5 }}
            className="text-center mt-2"
          >
            <p className="text-sm font-semibold" style={{ color }}>
              {info.name}
            </p>
            <p className="text-xs text-neutral-500">
              {info.bits} • {info.type}
            </p>
          </motion.div>
        </AnimatePresence>
      </motion.div>

      {/* Right side - Encrypted data */}
      <motion.div
        className="absolute right-4 top-1/2 -translate-y-1/2 flex flex-col items-center"
        animate={{
          opacity: state === 'idle' ? 0.3 : 1,
        }}
      >
        <div
          className="w-12 h-12 rounded-lg flex items-center justify-center"
          style={{ backgroundColor: `${color}20` }}
        >
          <Lock size={24} style={{ color }} />
        </div>
        <span className="text-xs text-neutral-400 mt-2">Encrypted</span>
      </motion.div>

      {/* Status indicator */}
      <motion.div
        className="absolute bottom-3 left-1/2 -translate-x-1/2"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
      >
        <div className="flex items-center gap-2">
          <motion.div
            className="w-2 h-2 rounded-full"
            style={{ backgroundColor: color }}
            animate={{
              scale: isProcessing ? [1, 1.5, 1] : 1,
              opacity: isProcessing ? [1, 0.5, 1] : 1,
            }}
            transition={{
              duration: 0.5,
              repeat: isProcessing ? Infinity : 0,
            }}
          />
          <span className="text-xs font-medium" style={{ color }}>
            {state === 'idle' && 'Ready'}
            {state === 'encrypting' && 'Encrypting...'}
            {state === 'encrypted' && 'Secured'}
            {state === 'decrypting' && 'Decrypting...'}
          </span>
        </div>
      </motion.div>
    </div>
  );
}

export default EncryptionVisualizer;
