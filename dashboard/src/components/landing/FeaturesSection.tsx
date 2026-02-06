'use client';

import React, { useRef } from 'react';
import { motion, useInView, useReducedMotion } from 'framer-motion';
import { 
  Shield, Key, Fingerprint, Users, Lock, 
  Webhook, BarChart3, Globe, Zap, Building2
} from 'lucide-react';
import { Card } from '@/components/ui/Card';
import { GradientText } from '@/components/ui/GradientText';
import { cn } from '@/lib/utils';
import { staggerVariants, staggerItemVariants, scrollAnimations } from '@/lib/motion';
import { SecurityVisualization } from './SecurityVisualization';
import { StatsCounter, type StatItem } from './StatsCounter';

interface Feature {
  icon: React.ElementType;
  title: string;
  description: string;
  gradient: string;
}

const features: Feature[] = [
  {
    icon: Shield,
    title: 'Authentication',
    description: 'Secure email/password, social logins, and passwordless authentication out of the box.',
    gradient: 'from-primary to-primary-600',
  },
  {
    icon: Fingerprint,
    title: 'Multi-Factor Auth',
    description: 'WebAuthn passkeys, TOTP authenticator apps, and backup codes for maximum security.',
    gradient: 'from-accent to-accent-600',
  },
  {
    icon: Building2,
    title: 'Single Sign-On',
    description: 'Enterprise SSO with SAML 2.0 and OIDC. Connect to Okta, Azure AD, and more.',
    gradient: 'from-info to-info-600',
  },
  {
    icon: Users,
    title: 'Organizations',
    description: 'Multi-tenant support with roles, permissions, and team management built-in.',
    gradient: 'from-success to-success-600',
  },
  {
    icon: Webhook,
    title: 'Webhooks',
    description: 'Real-time event notifications for user actions, security events, and more.',
    gradient: 'from-warning to-warning-600',
  },
  {
    icon: BarChart3,
    title: 'Analytics',
    description: 'Detailed insights into user activity, authentication patterns, and security metrics.',
    gradient: 'from-error to-error-600',
  },
];

const stats: StatItem[] = [
  { value: 99.99, suffix: '%', label: 'Uptime SLA', decimals: 2 },
  { value: 25, prefix: '<', suffix: 'ms', label: 'API Latency' },
  { value: 10, suffix: 'M+', label: 'Auth/day' },
  { value: 150, suffix: '+', label: 'Countries' },
];

// Feature card with 3D tilt effect
function FeatureCard({ feature, index }: { feature: Feature; index: number }) {
  const Icon = feature.icon;

  return (
    <motion.div
      variants={staggerItemVariants}
      whileHover={{ y: -8, transition: { duration: 0.3 } }}
    >
      <Card 
        variant="default" 
        padding="lg"
        hoverable
        glowOnHover
        className="h-full group"
      >
        {/* Icon with gradient background */}
        <div className={cn(
          'w-14 h-14 rounded-xl flex items-center justify-center mb-5',
          'bg-gradient-to-br',
          feature.gradient,
          'shadow-lg group-hover:scale-110 transition-transform duration-300'
        )}>
          <Icon size={24} className="text-white" />
        </div>

        {/* Title */}
        <h3 className="text-xl font-semibold text-neutral-900 mb-2">
          {feature.title}
        </h3>

        {/* Description */}
        <p className="text-neutral-500 leading-relaxed">
          {feature.description}
        </p>

        {/* Hover indicator */}
        <div className="mt-4 flex items-center gap-2 text-primary opacity-0 group-hover:opacity-100 transition-opacity">
          <span className="text-sm font-medium">Learn more</span>
          <motion.span
            animate={{ x: [0, 4, 0] }}
            transition={{ duration: 1.5, repeat: Infinity }}
          >
            →
          </motion.span>
        </div>
      </Card>
    </motion.div>
  );
}

export function FeaturesSection() {
  const ref = useRef<HTMLElement>(null);
  const isInView = useInView(ref, { once: true, margin: '-100px' });
  const shouldReduceMotion = useReducedMotion();
  const reducedMotion = shouldReduceMotion ?? false;

  return (
    <section 
      id="features" 
      ref={ref}
      className="py-24 md:py-32 px-6 bg-neutral-50 relative overflow-hidden"
      data-testid="features-section"
      data-reduced-motion={reducedMotion ? 'true' : 'false'}
    >
      {/* Background decoration */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(108,71,255,0.05),transparent)]" />

      <div className="max-w-7xl mx-auto relative">
        {/* Section header */}
        <motion.div
          initial={{ opacity: 0, y: reducedMotion ? 0 : 30 }}
          animate={isInView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: reducedMotion ? 0.1 : 0.6 }}
          className="text-center mb-16"
        >
          <motion.div 
            className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/5 border border-primary/10 mb-6"
            initial={{ opacity: 0, scale: reducedMotion ? 1 : 0.9 }}
            animate={isInView ? { opacity: 1, scale: 1 } : {}}
            transition={{ delay: reducedMotion ? 0 : 0.2 }}
          >
            <Zap size={16} className="text-primary" />
            <span className="text-sm font-medium text-primary">
              Everything you need
            </span>
          </motion.div>

          <h2 className="text-4xl md:text-5xl font-bold text-neutral-900 mb-4">
            Built for{' '}
            <GradientText gradient="primary">
              modern apps
            </GradientText>
          </h2>

          <p className="text-lg text-neutral-500 max-w-2xl mx-auto">
            Complete authentication infrastructure with enterprise-grade security.
            Ship faster without compromising on features.
          </p>
        </motion.div>

        {/* Security Visualization */}
        <motion.div
          initial={{ opacity: 0, y: reducedMotion ? 0 : 30 }}
          animate={isInView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: reducedMotion ? 0 : 0.3, duration: reducedMotion ? 0.1 : 0.6 }}
          className="mb-16"
        >
          <SecurityVisualization 
            type="combined" 
            autoPlay={true} 
            loop={true}
          />
        </motion.div>

        {/* Features grid - exactly 6 feature cards */}
        <motion.div
          initial="hidden"
          animate={isInView ? "visible" : "hidden"}
          variants={staggerVariants}
          className="grid md:grid-cols-2 lg:grid-cols-3 gap-6"
          data-testid="features-grid"
        >
          {features.map((feature, index) => (
            <FeatureCard 
              key={feature.title} 
              feature={feature} 
              index={index} 
            />
          ))}
        </motion.div>

        {/* Stats Counter with scroll-triggered animation */}
        <motion.div
          initial={{ opacity: 0, y: reducedMotion ? 0 : 30 }}
          animate={isInView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: reducedMotion ? 0 : 0.8, duration: reducedMotion ? 0.1 : 0.6 }}
          className="mt-20"
        >
          <StatsCounter 
            stats={stats}
            animateOnView={true}
            duration={2}
            variant="default"
          />
        </motion.div>
      </div>
    </section>
  );
}

export default FeaturesSection;
