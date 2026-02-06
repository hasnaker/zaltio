'use client';

import React, { useEffect, useState, useRef } from 'react';
import { motion, useReducedMotion, useInView } from 'framer-motion';
import { cn } from '@/lib/utils';
import { easings } from '@/lib/motion';
import { Shield, Lock, Key, AlertTriangle, CheckCircle, Zap } from 'lucide-react';

export interface SecurityVisualizationProps {
  /** Visualization type */
  type?: 'encryption' | 'threat' | 'combined';
  /** Auto-play animation */
  autoPlay?: boolean;
  /** Loop animation */
  loop?: boolean;
  /** Animation speed multiplier */
  speed?: number;
  /** Additional CSS classes */
  className?: string;
  /** Test ID for testing */
  'data-testid'?: string;
}

interface DataPacket {
  id: number;
  x: number;
  y: number;
  encrypted: boolean;
  color: string;
}

interface ThreatIndicator {
  id: number;
  type: 'blocked' | 'detected' | 'analyzing';
  x: number;
  y: number;
  label: string;
}

/**
 * Security Visualization Component
 * Animated visualization showing encryption flow and threat detection
 */
export function SecurityVisualization({
  type = 'combined',
  autoPlay = true,
  loop = true,
  speed = 1,
  className,
  'data-testid': testId = 'security-visualization',
}: SecurityVisualizationProps) {
  const shouldReduceMotion = useReducedMotion();
  const reducedMotion = shouldReduceMotion ?? false;
  const ref = useRef<HTMLDivElement>(null);
  const isInView = useInView(ref, { once: false, margin: '-50px' });
  
  const [packets, setPackets] = useState<DataPacket[]>([]);
  const [threats, setThreats] = useState<ThreatIndicator[]>([]);
  const [isPlaying, setIsPlaying] = useState(autoPlay);

  // Generate encryption flow packets
  useEffect(() => {
    if (!isPlaying || reducedMotion || !isInView) return;
    if (type !== 'encryption' && type !== 'combined') return;

    const interval = setInterval(() => {
      setPackets(prev => {
        // Add new packet
        const newPacket: DataPacket = {
          id: Date.now(),
          x: 0,
          y: Math.random() * 60 + 20,
          encrypted: false,
          color: '#6C47FF',
        };
        
        // Update existing packets
        const updated = prev
          .map(p => ({
            ...p,
            x: p.x + 5,
            encrypted: p.x > 50,
            color: p.x > 50 ? '#22C55E' : '#6C47FF',
          }))
          .filter(p => p.x < 110);
        
        return [...updated, newPacket].slice(-10);
      });
    }, 500 / speed);

    return () => clearInterval(interval);
  }, [isPlaying, reducedMotion, isInView, type, speed]);

  // Generate threat indicators
  useEffect(() => {
    if (!isPlaying || reducedMotion || !isInView) return;
    if (type !== 'threat' && type !== 'combined') return;

    const interval = setInterval(() => {
      setThreats(prev => {
        const types: ThreatIndicator['type'][] = ['blocked', 'detected', 'analyzing'];
        const labels = {
          blocked: 'Blocked',
          detected: 'Detected',
          analyzing: 'Analyzing',
        };
        
        const threatType = types[Math.floor(Math.random() * types.length)];
        const newThreat: ThreatIndicator = {
          id: Date.now(),
          type: threatType,
          x: Math.random() * 80 + 10,
          y: Math.random() * 60 + 20,
          label: labels[threatType],
        };
        
        return [...prev.slice(-4), newThreat];
      });
    }, 2000 / speed);

    return () => clearInterval(interval);
  }, [isPlaying, reducedMotion, isInView, type, speed]);

  // Clear old threats
  useEffect(() => {
    const cleanup = setInterval(() => {
      setThreats(prev => prev.filter(t => Date.now() - t.id < 3000));
    }, 1000);
    return () => clearInterval(cleanup);
  }, []);

  return (
    <div
      ref={ref}
      className={cn(
        'relative w-full h-64 md:h-80 rounded-2xl overflow-hidden',
        'bg-gradient-to-br from-neutral-900 via-neutral-800 to-neutral-900',
        'border border-neutral-700',
        className
      )}
      data-testid={testId}
      data-reduced-motion={reducedMotion ? 'true' : 'false'}
    >
      {/* Grid background */}
      <div 
        className="absolute inset-0 opacity-10"
        style={{
          backgroundImage: `
            linear-gradient(rgba(108, 71, 255, 0.3) 1px, transparent 1px),
            linear-gradient(90deg, rgba(108, 71, 255, 0.3) 1px, transparent 1px)
          `,
          backgroundSize: '20px 20px',
        }}
      />

      {/* Encryption Flow Visualization */}
      {(type === 'encryption' || type === 'combined') && (
        <EncryptionFlow 
          packets={packets} 
          reducedMotion={reducedMotion}
        />
      )}

      {/* Threat Detection Visualization */}
      {(type === 'threat' || type === 'combined') && (
        <ThreatDetection 
          threats={threats} 
          reducedMotion={reducedMotion}
        />
      )}

      {/* Central Shield */}
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
        <motion.div
          className="relative"
          animate={reducedMotion ? {} : {
            scale: [1, 1.05, 1],
          }}
          transition={{
            duration: 3,
            repeat: loop ? Infinity : 0,
            ease: 'easeInOut',
          }}
        >
          <div className="w-20 h-20 md:w-24 md:h-24 rounded-full bg-gradient-to-br from-primary/20 to-accent/20 flex items-center justify-center backdrop-blur-sm border border-primary/30">
            <Shield className="w-10 h-10 md:w-12 md:h-12 text-primary" />
          </div>
          
          {/* Pulse rings */}
          {!reducedMotion && (
            <>
              <motion.div
                className="absolute inset-0 rounded-full border-2 border-primary/30"
                animate={{
                  scale: [1, 1.5, 1.5],
                  opacity: [0.5, 0, 0],
                }}
                transition={{
                  duration: 2,
                  repeat: Infinity,
                  ease: 'easeOut',
                }}
              />
              <motion.div
                className="absolute inset-0 rounded-full border-2 border-accent/30"
                animate={{
                  scale: [1, 1.8, 1.8],
                  opacity: [0.3, 0, 0],
                }}
                transition={{
                  duration: 2,
                  repeat: Infinity,
                  ease: 'easeOut',
                  delay: 0.5,
                }}
              />
            </>
          )}
        </motion.div>
      </div>

      {/* Status indicators */}
      <div className="absolute bottom-4 left-4 right-4 flex items-center justify-between text-xs">
        <div className="flex items-center gap-2 text-green-400">
          <CheckCircle className="w-4 h-4" />
          <span>Protected</span>
        </div>
        <div className="flex items-center gap-4 text-neutral-400">
          <span className="flex items-center gap-1">
            <Lock className="w-3 h-3" />
            AES-256
          </span>
          <span className="flex items-center gap-1">
            <Key className="w-3 h-3" />
            RS256
          </span>
          <span className="flex items-center gap-1">
            <Zap className="w-3 h-3" />
            Real-time
          </span>
        </div>
      </div>
    </div>
  );
}

// Encryption flow sub-component
function EncryptionFlow({ 
  packets, 
  reducedMotion 
}: { 
  packets: DataPacket[]; 
  reducedMotion: boolean;
}) {
  return (
    <svg className="absolute inset-0 w-full h-full" viewBox="0 0 100 100" preserveAspectRatio="none">
      {/* Flow path */}
      <path
        d="M 0 50 Q 25 30, 50 50 T 100 50"
        fill="none"
        stroke="rgba(108, 71, 255, 0.2)"
        strokeWidth="0.5"
        strokeDasharray="2 2"
      />
      
      {/* Encryption zone indicator */}
      <rect
        x="45"
        y="35"
        width="10"
        height="30"
        fill="rgba(108, 71, 255, 0.1)"
        stroke="rgba(108, 71, 255, 0.3)"
        strokeWidth="0.3"
        rx="2"
      />
      <text x="50" y="68" textAnchor="middle" fill="rgba(108, 71, 255, 0.6)" fontSize="3">
        ENCRYPT
      </text>

      {/* Data packets */}
      {packets.map((packet) => (
        <motion.g
          key={packet.id}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
        >
          <circle
            cx={packet.x}
            cy={packet.y}
            r="2"
            fill={packet.color}
            opacity={0.8}
          />
          {packet.encrypted && (
            <circle
              cx={packet.x}
              cy={packet.y}
              r="3"
              fill="none"
              stroke="#22C55E"
              strokeWidth="0.3"
              opacity={0.5}
            />
          )}
        </motion.g>
      ))}
    </svg>
  );
}

// Threat detection sub-component
function ThreatDetection({ 
  threats, 
  reducedMotion 
}: { 
  threats: ThreatIndicator[]; 
  reducedMotion: boolean;
}) {
  const getColor = (type: ThreatIndicator['type']) => {
    switch (type) {
      case 'blocked': return '#EF4444';
      case 'detected': return '#F59E0B';
      case 'analyzing': return '#3B82F6';
    }
  };

  const getIcon = (type: ThreatIndicator['type']) => {
    switch (type) {
      case 'blocked': return '✕';
      case 'detected': return '!';
      case 'analyzing': return '?';
    }
  };

  return (
    <>
      {threats.map((threat) => (
        <motion.div
          key={threat.id}
          className="absolute flex items-center gap-1"
          style={{
            left: `${threat.x}%`,
            top: `${threat.y}%`,
          }}
          initial={{ scale: 0, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0, opacity: 0 }}
          transition={{ duration: reducedMotion ? 0.1 : 0.3 }}
        >
          <div 
            className="w-6 h-6 rounded-full flex items-center justify-center text-white text-xs font-bold"
            style={{ backgroundColor: getColor(threat.type) }}
          >
            {getIcon(threat.type)}
          </div>
          <span 
            className="text-xs font-medium px-2 py-0.5 rounded"
            style={{ 
              backgroundColor: `${getColor(threat.type)}20`,
              color: getColor(threat.type),
            }}
          >
            {threat.label}
          </span>
        </motion.div>
      ))}
    </>
  );
}

export default SecurityVisualization;
