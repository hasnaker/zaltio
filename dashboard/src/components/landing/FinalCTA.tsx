'use client';

import React from 'react';
import { motion } from 'framer-motion';
import { ArrowRight, Sparkles, Shield, Zap } from 'lucide-react';
import { scrollAnimations, microInteractions } from '@/lib/motion';
import { HeroLock } from './HeroLock';

interface FinalCTAProps {
  className?: string;
}

export function FinalCTA({ className = '' }: FinalCTAProps) {
  return (
    <section className={`py-24 md:py-32 px-6 bg-gradient-to-b from-white to-neutral-50 relative overflow-hidden ${className}`}>
      {/* Background decorations */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(108,71,255,0.08),transparent_70%)]" />
      <div className="absolute top-0 left-1/4 w-96 h-96 bg-primary/5 rounded-full blur-3xl" />
      <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-accent/5 rounded-full blur-3xl" />

      <div className="max-w-4xl mx-auto relative">
        <motion.div
          {...scrollAnimations.scaleUp}
          className="text-center"
        >
          {/* Badge */}
          <motion.div 
            className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/5 border border-primary/10 mb-8"
            whileHover={{ scale: 1.02 }}
          >
            <Sparkles size={16} className="text-primary" />
            <span className="text-sm font-medium text-primary">Start for free, scale as you grow</span>
          </motion.div>

          {/* Headline */}
          <h2 className="text-4xl md:text-5xl lg:text-6xl font-bold text-neutral-900 mb-6 leading-tight">
            Ready to secure your{' '}
            <span className="bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
              application
            </span>
            ?
          </h2>

          {/* Subheadline */}
          <p className="text-lg md:text-xl text-neutral-600 mb-10 max-w-2xl mx-auto">
            Join hundreds of companies using Zalt for enterprise-grade authentication. 
            Get started in minutes with our generous free tier.
          </p>

          {/* CTA Buttons */}
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-12">
            <motion.a
              href="/signup"
              className="group inline-flex items-center gap-2 px-8 py-4 rounded-xl 
                         bg-gradient-to-r from-primary to-primary/90 text-white font-semibold text-lg
                         shadow-lg shadow-primary/25 hover:shadow-xl hover:shadow-primary/30
                         transition-all duration-300"
              whileHover={{ scale: 1.02, y: -2 }}
              whileTap={{ scale: 0.98 }}
            >
              Start Building Free
              <ArrowRight size={20} className="group-hover:translate-x-1 transition-transform" />
            </motion.a>

            <motion.a
              href="/docs"
              className="inline-flex items-center gap-2 px-8 py-4 rounded-xl 
                         bg-white text-neutral-700 font-semibold text-lg
                         border border-neutral-200 hover:border-primary/30 hover:bg-primary/5
                         transition-all duration-300"
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              Read Documentation
            </motion.a>
          </div>

          {/* Trust indicators */}
          <div className="flex flex-wrap items-center justify-center gap-6 text-sm text-neutral-500">
            <div className="flex items-center gap-2">
              <Shield size={16} className="text-green-500" />
              <span>SOC 2 Type II</span>
            </div>
            <div className="flex items-center gap-2">
              <Shield size={16} className="text-green-500" />
              <span>HIPAA Compliant</span>
            </div>
            <div className="flex items-center gap-2">
              <Shield size={16} className="text-green-500" />
              <span>GDPR Ready</span>
            </div>
            <div className="flex items-center gap-2">
              <Zap size={16} className="text-yellow-500" />
              <span>99.99% Uptime SLA</span>
            </div>
          </div>

          {/* Mini HeroLock animation */}
          <motion.div
            initial={{ opacity: 0, y: 40 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.3 }}
            className="mt-16 flex justify-center"
          >
            <div className="w-32 h-32 opacity-50">
              <HeroLock size="md" />
            </div>
          </motion.div>
        </motion.div>
      </div>
    </section>
  );
}

export default FinalCTA;
