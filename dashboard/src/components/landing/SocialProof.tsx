'use client';

import React from 'react';
import { motion } from 'framer-motion';
import { Building2, Users, Shield, Globe } from 'lucide-react';
import { scrollAnimations, staggerVariants, staggerItemVariants } from '@/lib/motion';

// Company logos (using text-based logos for simplicity)
const companies = [
  { name: 'Clinisyn', industry: 'Healthcare' },
  { name: 'TechCorp', industry: 'Technology' },
  { name: 'FinanceHub', industry: 'Finance' },
  { name: 'EduLearn', industry: 'Education' },
  { name: 'RetailMax', industry: 'Retail' },
  { name: 'MediaFlow', industry: 'Media' },
];

// Stats to display
const stats = [
  { icon: Users, value: '50K+', label: 'Active Users', color: 'text-primary' },
  { icon: Shield, value: '99.99%', label: 'Uptime SLA', color: 'text-green-500' },
  { icon: Globe, value: '11', label: 'Countries', color: 'text-accent' },
  { icon: Building2, value: '100+', label: 'Companies', color: 'text-purple-500' },
];

interface SocialProofProps {
  className?: string;
}

export function SocialProof({ className = '' }: SocialProofProps) {
  return (
    <section className={`py-16 md:py-20 px-6 bg-neutral-50 border-y border-neutral-100 ${className}`}>
      <div className="max-w-6xl mx-auto">
        {/* Section label */}
        <motion.p
          {...scrollAnimations.fadeUp}
          className="text-center text-sm font-medium text-neutral-500 uppercase tracking-wider mb-10"
        >
          Trusted by innovative companies worldwide
        </motion.p>

        {/* Company logos */}
        <motion.div
          variants={staggerVariants}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true }}
          className="flex flex-wrap justify-center items-center gap-8 md:gap-12 mb-16"
        >
          {companies.map((company) => (
            <motion.div
              key={company.name}
              variants={staggerItemVariants}
              className="group relative"
            >
              <motion.div
                className="px-6 py-3 rounded-lg bg-white border border-neutral-200 shadow-sm
                           grayscale opacity-60 hover:grayscale-0 hover:opacity-100 
                           hover:border-primary/20 hover:shadow-md
                           transition-all duration-300 cursor-default"
                whileHover={{ scale: 1.05, y: -2 }}
              >
                <span className="text-lg font-semibold text-neutral-700 group-hover:text-primary transition-colors">
                  {company.name}
                </span>
              </motion.div>
              
              {/* Tooltip */}
              <div className="absolute -bottom-8 left-1/2 -translate-x-1/2 opacity-0 group-hover:opacity-100 
                              transition-opacity duration-200 pointer-events-none">
                <span className="text-xs text-neutral-500 whitespace-nowrap">
                  {company.industry}
                </span>
              </div>
            </motion.div>
          ))}
        </motion.div>

        {/* Stats grid */}
        <motion.div
          variants={staggerVariants}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true }}
          className="grid grid-cols-2 md:grid-cols-4 gap-6 md:gap-8"
        >
          {stats.map((stat) => (
            <motion.div
              key={stat.label}
              variants={staggerItemVariants}
              className="text-center p-6 rounded-xl bg-white border border-neutral-100 shadow-sm
                         hover:shadow-md hover:border-primary/10 transition-all duration-300"
            >
              <motion.div
                className={`inline-flex items-center justify-center w-12 h-12 rounded-full 
                           bg-gradient-to-br from-primary/10 to-accent/10 mb-4`}
                whileHover={{ scale: 1.1, rotate: 5 }}
              >
                <stat.icon className={`w-6 h-6 ${stat.color}`} />
              </motion.div>
              
              <div className="text-3xl md:text-4xl font-bold bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent mb-1">
                {stat.value}
              </div>
              
              <div className="text-sm text-neutral-600">
                {stat.label}
              </div>
            </motion.div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}

export default SocialProof;
