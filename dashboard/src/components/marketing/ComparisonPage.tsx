'use client';

import { motion } from 'framer-motion';
import Link from 'next/link';
import { Check, X, ArrowRight, Shield, LucideIcon } from 'lucide-react';
import { ReactNode } from 'react';

export interface ComparisonFeature {
  feature: string;
  zalt: boolean | string;
  competitor: boolean | string;
  advantage: 'zalt' | 'competitor' | 'equal';
}

export interface ComparisonHighlight {
  icon: LucideIcon;
  title: string;
  description: string;
}

export interface MigrationStep {
  step: number;
  title: string;
  description: string;
}

export interface ComparisonPageProps {
  competitorName: string;
  tagline: string;
  description: string;
  features: ComparisonFeature[];
  highlights: ComparisonHighlight[];
  migrationSteps: MigrationStep[];
  migrationGuideUrl: string;
  children?: ReactNode;
}

export function ComparisonPage({
  competitorName,
  tagline,
  description,
  features,
  highlights,
  migrationSteps,
  migrationGuideUrl,
  children,
}: ComparisonPageProps) {
  const renderValue = (value: boolean | string) => {
    if (value === true) return <Check size={18} className="text-emerald-400" />;
    if (value === false) return <X size={18} className="text-red-400" />;
    return <span className="text-sm text-neutral-300">{value}</span>;
  };

  const zaltAdvantages = features.filter(f => f.advantage === 'zalt').length;
  const competitorAdvantages = features.filter(f => f.advantage === 'competitor').length;

  return (
    <div className="min-h-screen bg-neutral-950">
      <div className="max-w-5xl mx-auto px-4 py-16">
        {/* Header */}
        <motion.div 
          initial={{ opacity: 0, y: 20 }} 
          animate={{ opacity: 1, y: 0 }} 
          className="text-center mb-12"
        >
          <div className="flex items-center justify-center gap-2 text-emerald-400 text-sm font-mono mb-4">
            <Shield size={14} />
            COMPARISON
          </div>
          <h1 className="font-outfit text-4xl md:text-5xl font-bold text-white mb-4">
            Zalt vs {competitorName}
          </h1>
          <p className="text-neutral-400 max-w-2xl mx-auto text-lg">
            {description}
          </p>
        </motion.div>

        {/* Score Summary */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="grid md:grid-cols-2 gap-4 mb-12"
        >
          <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-lg p-6 text-center">
            <div className="text-4xl font-bold text-emerald-400 mb-2">{zaltAdvantages}</div>
            <div className="text-white font-medium">Zalt Advantages</div>
          </div>
          <div className="bg-neutral-800/50 border border-neutral-700 rounded-lg p-6 text-center">
            <div className="text-4xl font-bold text-neutral-400 mb-2">{competitorAdvantages}</div>
            <div className="text-neutral-400 font-medium">{competitorName} Advantages</div>
          </div>
        </motion.div>

        {/* Key Differentiators */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="grid md:grid-cols-3 gap-4 mb-12"
        >
          {highlights.map((item, i) => (
            <div key={i} className="bg-neutral-900 border border-emerald-500/20 rounded-lg p-5">
              <item.icon size={24} className="text-emerald-400 mb-3" />
              <h3 className="text-white font-medium mb-1">{item.title}</h3>
              <p className="text-sm text-neutral-400">{item.description}</p>
            </div>
          ))}
        </motion.div>

        {/* Custom Content (e.g., pricing comparison) */}
        {children}

        {/* Comparison Table */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-neutral-900 border border-emerald-500/10 rounded-lg overflow-hidden mb-12"
        >
          <div className="px-4 py-3 border-b border-emerald-500/10 bg-neutral-800/50">
            <h2 className="text-white font-medium">Feature Comparison</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-emerald-500/10">
                  <th className="text-left px-4 py-3 text-sm text-neutral-400 font-normal">Feature</th>
                  <th className="text-center px-4 py-3 text-sm font-medium text-emerald-400 w-32">Zalt</th>
                  <th className="text-center px-4 py-3 text-sm text-neutral-400 font-normal w-32">{competitorName}</th>
                </tr>
              </thead>
              <tbody>
                {features.map((item, i) => (
                  <tr 
                    key={i} 
                    className={`border-b border-emerald-500/5 ${
                      item.advantage === 'zalt' ? 'bg-emerald-500/5' : ''
                    }`}
                  >
                    <td className="px-4 py-3 text-sm text-neutral-300">{item.feature}</td>
                    <td className="px-4 py-3 text-center">{renderValue(item.zalt)}</td>
                    <td className="px-4 py-3 text-center">{renderValue(item.competitor)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </motion.div>

        {/* Migration Guide */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="mb-12"
        >
          <h2 className="text-2xl font-bold text-white mb-6">
            Migrate from {competitorName}
          </h2>
          <div className="grid md:grid-cols-2 gap-4">
            {migrationSteps.map((step, i) => (
              <div 
                key={i} 
                className="flex items-start gap-4 bg-neutral-900 border border-emerald-500/10 rounded-lg p-4"
              >
                <div className="w-8 h-8 rounded-full bg-emerald-500/20 flex items-center justify-center text-emerald-400 font-bold shrink-0">
                  {step.step}
                </div>
                <div>
                  <h3 className="text-white font-medium">{step.title}</h3>
                  <p className="text-sm text-neutral-400">{step.description}</p>
                </div>
              </div>
            ))}
          </div>
        </motion.div>

        {/* CTA */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="bg-gradient-to-r from-emerald-500/10 to-emerald-500/5 border border-emerald-500/20 rounded-lg p-8 text-center"
        >
          <h2 className="text-2xl font-bold text-white mb-2">
            Ready to switch from {competitorName}?
          </h2>
          <p className="text-neutral-400 mb-6">
            Get started free with 1,000 MAU. Migration takes less than an hour.
          </p>
          <div className="flex items-center justify-center gap-4 flex-wrap">
            <Link
              href="/signup"
              className="inline-flex items-center gap-2 px-6 py-3 bg-emerald-500 text-neutral-950 rounded-lg font-medium"
            >
              Start Free Migration
              <ArrowRight size={16} />
            </Link>
            <Link
              href={migrationGuideUrl}
              className="inline-flex items-center gap-2 px-6 py-3 border border-neutral-700 text-neutral-300 rounded-lg hover:bg-neutral-800"
            >
              Full Migration Guide
            </Link>
          </div>
        </motion.div>
      </div>
    </div>
  );
}

export default ComparisonPage;
