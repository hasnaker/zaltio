'use client';

import React, { useRef } from 'react';
import { motion, useInView } from 'framer-motion';
import { Shield, Lock, Eye } from 'lucide-react';
import { GradientText } from '@/components/ui/GradientText';
import { ThreatMap } from './ThreatMap';
import { EncryptionVisualizer } from './EncryptionVisualizer';
import { BiometricScanner } from './BiometricScanner';
import { SecurityShield } from './SecurityShield';
import { cn } from '@/lib/utils';
import { staggerVariants, staggerItemVariants } from '@/lib/motion';

export function SecurityTheater() {
  const ref = useRef<HTMLElement>(null);
  const isInView = useInView(ref, { once: true, margin: '-100px' });

  return (
    <section
      ref={ref}
      className="py-24 md:py-32 px-6 bg-[#0a0a0f] relative overflow-hidden"
    >
      {/* Background effects */}
      <div className="absolute inset-0">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_50%_at_50%_-20%,rgba(108,71,255,0.15),transparent)]" />
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_60%_40%_at_80%_80%,rgba(0,212,255,0.1),transparent)]" />
      </div>

      {/* Grid pattern */}
      <div
        className="absolute inset-0 opacity-[0.03]"
        style={{
          backgroundImage: `
            linear-gradient(rgba(108, 71, 255, 0.5) 1px, transparent 1px),
            linear-gradient(90deg, rgba(108, 71, 255, 0.5) 1px, transparent 1px)
          `,
          backgroundSize: '40px 40px',
        }}
      />

      <div className="max-w-7xl mx-auto relative">
        {/* Section header */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={isInView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.6 }}
          className="text-center mb-16"
        >
          <motion.div
            className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 mb-6"
            initial={{ opacity: 0, scale: 0.9 }}
            animate={isInView ? { opacity: 1, scale: 1 } : {}}
            transition={{ delay: 0.2 }}
          >
            <Shield size={16} className="text-primary" />
            <span className="text-sm font-medium text-primary">
              Enterprise Security
            </span>
          </motion.div>

          <h2 className="text-4xl md:text-5xl font-bold text-white mb-4">
            Security that{' '}
            <GradientText gradient="primary" className="text-4xl md:text-5xl font-bold">
              never sleeps
            </GradientText>
          </h2>

          <p className="text-lg text-neutral-400 max-w-2xl mx-auto">
            Real-time threat detection, military-grade encryption, and biometric
            authentication working together to protect your users.
          </p>
        </motion.div>

        {/* Main visualization grid */}
        <motion.div
          initial="hidden"
          animate={isInView ? 'visible' : 'hidden'}
          variants={staggerVariants}
          className="grid lg:grid-cols-2 gap-8"
        >
          {/* Threat Map - Full width on mobile, half on desktop */}
          <motion.div
            variants={staggerItemVariants}
            className="lg:col-span-2"
          >
            <div className="bg-neutral-900/50 rounded-2xl p-6 border border-neutral-800">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 rounded-lg bg-error/20 flex items-center justify-center">
                  <Eye size={20} className="text-error" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-white">
                    Global Threat Monitor
                  </h3>
                  <p className="text-sm text-neutral-500">
                    Real-time attack detection and blocking
                  </p>
                </div>
              </div>
              <ThreatMap autoAnimate showLabels />
            </div>
          </motion.div>

          {/* Encryption Visualizer */}
          <motion.div variants={staggerItemVariants}>
            <div className="bg-neutral-900/50 rounded-2xl p-6 border border-neutral-800 h-full">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 rounded-lg bg-primary/20 flex items-center justify-center">
                  <Lock size={20} className="text-primary" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-white">
                    Data Encryption
                  </h3>
                  <p className="text-sm text-neutral-500">
                    AES-256, RSA-4096, Argon2id
                  </p>
                </div>
              </div>
              <div className="flex justify-center">
                <EncryptionVisualizer
                  autoAnimate
                  showDataFlow
                  size="md"
                />
              </div>
            </div>
          </motion.div>

          {/* Biometric + Shield */}
          <motion.div variants={staggerItemVariants}>
            <div className="bg-neutral-900/50 rounded-2xl p-6 border border-neutral-800 h-full">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 rounded-lg bg-accent/20 flex items-center justify-center">
                  <Shield size={20} className="text-accent" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-white">
                    Biometric Auth
                  </h3>
                  <p className="text-sm text-neutral-500">
                    WebAuthn passkeys & fingerprint
                  </p>
                </div>
              </div>
              <div className="flex justify-center items-center gap-8">
                <BiometricScanner
                  type="fingerprint"
                  autoAnimate
                  showGrid
                  size="sm"
                />
                <SecurityShield
                  autoAnimate
                  size="sm"
                  showPulse
                  showScanLine
                />
              </div>
            </div>
          </motion.div>
        </motion.div>

        {/* Security stats */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={isInView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.8, duration: 0.6 }}
          className="mt-16 grid grid-cols-2 md:grid-cols-4 gap-8"
        >
          {[
            { value: '2.3B+', label: 'Threats Blocked', color: 'text-error' },
            { value: '0', label: 'Data Breaches', color: 'text-success' },
            { value: '256-bit', label: 'Encryption', color: 'text-primary' },
            { value: '24/7', label: 'Monitoring', color: 'text-accent' },
          ].map((stat, index) => (
            <motion.div
              key={stat.label}
              initial={{ opacity: 0, y: 20 }}
              animate={isInView ? { opacity: 1, y: 0 } : {}}
              transition={{ delay: 1 + index * 0.1 }}
              className="text-center"
            >
              <p className={cn('text-3xl md:text-4xl font-bold', stat.color)}>
                {stat.value}
              </p>
              <p className="text-sm text-neutral-500 mt-1">{stat.label}</p>
            </motion.div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}

export default SecurityTheater;
