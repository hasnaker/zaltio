'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { motion, useReducedMotion } from 'framer-motion';
import { ArrowRight, BookOpen, Monitor, Tablet, Smartphone } from 'lucide-react';
import { cn } from '@/lib/utils';
import { easings } from '@/lib/motion';
import { SecurityLock3D } from './SecurityLock3D';
import { DeviceMockups } from './DeviceMockups';

export interface HeroSectionProps {
  /** Show the 3D security lock */
  showSecurityLock?: boolean;
  /** Show device mockups */
  showDeviceMockups?: boolean;
  /** Primary CTA text */
  primaryCTAText?: string;
  /** Primary CTA href */
  primaryCTAHref?: string;
  /** Secondary CTA text */
  secondaryCTAText?: string;
  /** Secondary CTA href */
  secondaryCTAHref?: string;
  /** Additional CSS classes */
  className?: string;
  /** Test ID for testing */
  'data-testid'?: string;
}

/**
 * Enterprise Hero Section
 * Features animated gradient text, 3D security lock, and device mockups
 */
export function HeroSection({
  showSecurityLock = true,
  showDeviceMockups = true,
  primaryCTAText = 'Start building for free',
  primaryCTAHref = '/signup',
  secondaryCTAText = 'View documentation',
  secondaryCTAHref = '/docs',
  className,
  'data-testid': testId = 'hero-section',
}: HeroSectionProps) {
  const [activeDevice, setActiveDevice] = useState<'desktop' | 'tablet' | 'mobile'>('desktop');
  const shouldReduceMotion = useReducedMotion();
  const reducedMotion = shouldReduceMotion ?? false;

  // Animation variants
  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: reducedMotion ? 0 : 0.1,
        delayChildren: reducedMotion ? 0 : 0.2,
      },
    },
  };

  const itemVariants = {
    hidden: { opacity: 0, y: reducedMotion ? 0 : 20 },
    visible: { 
      opacity: 1, 
      y: 0,
      transition: { duration: reducedMotion ? 0.1 : 0.6, ease: easings.smoothOut },
    },
  };

  return (
    <section 
      className={cn(
        'relative pt-24 md:pt-32 pb-16 md:pb-24 overflow-hidden',
        className
      )}
      data-testid={testId}
      data-reduced-motion={reducedMotion ? 'true' : 'false'}
    >
      {/* Background gradient */}
      <div className="absolute inset-0 bg-gradient-to-b from-white via-neutral-50/50 to-white dark:from-neutral-950 dark:via-neutral-900/50 dark:to-neutral-950" />
      
      {/* Subtle grid background */}
      <div 
        className="absolute inset-0 opacity-[0.03] dark:opacity-[0.05]"
        style={{
          backgroundImage: `
            linear-gradient(rgba(108, 71, 255, 0.3) 1px, transparent 1px),
            linear-gradient(90deg, rgba(108, 71, 255, 0.3) 1px, transparent 1px)
          `,
          backgroundSize: '60px 60px',
        }}
      />

      {/* Gradient orbs */}
      {!reducedMotion && (
        <>
          <motion.div
            className="absolute top-20 left-1/4 w-96 h-96 rounded-full opacity-20"
            style={{
              background: 'radial-gradient(circle, rgba(108, 71, 255, 0.4) 0%, transparent 70%)',
              filter: 'blur(60px)',
            }}
            animate={{
              scale: [1, 1.2, 1],
              opacity: [0.2, 0.3, 0.2],
            }}
            transition={{
              duration: 8,
              repeat: Infinity,
              ease: 'easeInOut',
            }}
          />
          <motion.div
            className="absolute top-40 right-1/4 w-80 h-80 rounded-full opacity-15"
            style={{
              background: 'radial-gradient(circle, rgba(0, 212, 255, 0.4) 0%, transparent 70%)',
              filter: 'blur(60px)',
            }}
            animate={{
              scale: [1.2, 1, 1.2],
              opacity: [0.15, 0.25, 0.15],
            }}
            transition={{
              duration: 10,
              repeat: Infinity,
              ease: 'easeInOut',
            }}
          />
        </>
      )}

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="text-center"
        >
          {/* Badge */}
          <motion.div variants={itemVariants} className="mb-6">
            <span className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-primary/10 text-primary text-sm font-medium">
              <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
              Enterprise-grade security
            </span>
          </motion.div>

          {/* Main Headline with Gradient */}
          <motion.h1
            variants={itemVariants}
            className="text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-bold tracking-tight leading-[1.1] mb-6"
          >
            <span className="text-neutral-900 dark:text-white">
              More than authentication,
            </span>
            <br />
            <span className="bg-gradient-to-r from-primary via-purple-500 to-cyan-500 bg-clip-text text-transparent">
              Complete User Management
            </span>
          </motion.h1>

          {/* Subheadline */}
          <motion.p
            variants={itemVariants}
            className="mt-6 text-lg md:text-xl text-neutral-600 dark:text-neutral-400 max-w-3xl mx-auto leading-relaxed"
          >
            Need more than sign-in? Zalt gives you full stack auth and user management —
            so you can launch faster, scale easier, and stay focused on building your business.
          </motion.p>

          {/* CTA Buttons */}
          <motion.div
            variants={itemVariants}
            className="mt-10 flex flex-col sm:flex-row items-center justify-center gap-4"
          >
            <Link href={primaryCTAHref}>
              <button 
                className="inline-flex items-center gap-2 px-8 py-4 bg-primary hover:bg-primary/90 text-white font-medium rounded-xl transition-all shadow-lg shadow-primary/25 hover:shadow-xl hover:shadow-primary/30 hover:-translate-y-0.5"
                aria-label={primaryCTAText}
              >
                {primaryCTAText}
                <ArrowRight className="w-5 h-5" />
              </button>
            </Link>
            <Link href={secondaryCTAHref}>
              <button 
                className="inline-flex items-center gap-2 px-8 py-4 bg-white dark:bg-neutral-800 hover:bg-neutral-50 dark:hover:bg-neutral-700 text-neutral-900 dark:text-white font-medium rounded-xl border border-neutral-200 dark:border-neutral-700 transition-all hover:-translate-y-0.5"
                aria-label={secondaryCTAText}
              >
                <BookOpen className="w-5 h-5" />
                {secondaryCTAText}
              </button>
            </Link>
          </motion.div>

          {/* Security Lock and Device Mockups Section */}
          <motion.div
            variants={itemVariants}
            className="mt-16 md:mt-24"
          >
            {showSecurityLock && (
              <div className="flex justify-center mb-12">
                <SecurityLock3D 
                  size="lg" 
                  showParticles={true}
                  showGlow={true}
                  showRing={true}
                  autoPlay={true}
                  loop={true}
                />
              </div>
            )}

            {showDeviceMockups && (
              <>
                {/* Device selector */}
                <div className="flex justify-center mb-8">
                  <div className="inline-flex items-center gap-1 p-1.5 bg-neutral-100 dark:bg-neutral-800 rounded-xl">
                    <DeviceButton
                      active={activeDevice === 'desktop'}
                      onClick={() => setActiveDevice('desktop')}
                      icon={<Monitor className="w-4 h-4" />}
                      label="Desktop"
                    />
                    <DeviceButton
                      active={activeDevice === 'tablet'}
                      onClick={() => setActiveDevice('tablet')}
                      icon={<Tablet className="w-4 h-4" />}
                      label="Tablet"
                    />
                    <DeviceButton
                      active={activeDevice === 'mobile'}
                      onClick={() => setActiveDevice('mobile')}
                      icon={<Smartphone className="w-4 h-4" />}
                      label="Mobile"
                    />
                  </div>
                </div>

                {/* Device mockups */}
                <div className="flex justify-center">
                  <DeviceMockups
                    activeDevice={activeDevice}
                    onDeviceClick={setActiveDevice}
                    showDesktop={true}
                    showTablet={true}
                    showMobile={true}
                  />
                </div>
              </>
            )}
          </motion.div>

          {/* Trust indicators */}
          <motion.div
            variants={itemVariants}
            className="mt-16 pt-8 border-t border-neutral-200 dark:border-neutral-800"
          >
            <p className="text-sm text-neutral-500 dark:text-neutral-400 mb-4">
              Trusted by security-conscious companies worldwide
            </p>
            <div className="flex flex-wrap items-center justify-center gap-8 opacity-60">
              {/* Placeholder logos - replace with actual customer logos */}
              {['SOC 2', 'HIPAA', 'GDPR', 'ISO 27001'].map((badge) => (
                <div 
                  key={badge}
                  className="px-4 py-2 bg-neutral-100 dark:bg-neutral-800 rounded-lg text-sm font-medium text-neutral-600 dark:text-neutral-400"
                >
                  {badge}
                </div>
              ))}
            </div>
          </motion.div>
        </motion.div>
      </div>
    </section>
  );
}

// Device selector button component
function DeviceButton({
  active,
  onClick,
  icon,
  label,
}: {
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all',
        active
          ? 'bg-white dark:bg-neutral-700 text-neutral-900 dark:text-white shadow-sm'
          : 'text-neutral-500 dark:text-neutral-400 hover:text-neutral-700 dark:hover:text-neutral-300'
      )}
      aria-label={`View ${label} preview`}
      aria-pressed={active}
    >
      {icon}
      <span className="hidden sm:inline">{label}</span>
    </button>
  );
}

export default HeroSection;
