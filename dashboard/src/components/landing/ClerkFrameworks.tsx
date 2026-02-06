'use client';

import React from 'react';
import { motion } from 'framer-motion';
import { ChevronRight } from 'lucide-react';

// Framework icons (simplified representations)
const frameworks = [
  { name: 'Next.js', icon: 'N' },
  { name: 'React', icon: '⚛' },
  { name: 'Expo', icon: '▲' },
  { name: 'TanStack', icon: '🔶' },
  { name: 'Astro', icon: '🚀' },
  { name: 'Chrome', icon: '🌐' },
  { name: 'Express', icon: 'Ex' },
];

const integrations = [
  { name: 'Supabase', icon: '⚡' },
  { name: 'Convex', icon: '◯' },
  { name: 'Vercel', icon: '▲' },
];

export function ClerkFrameworks() {
  return (
    <section className="py-24 bg-[#0F0F10] text-white">
      <div className="max-w-7xl mx-auto px-6">
        <div className="grid lg:grid-cols-2 gap-16">
          {/* Frameworks */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
          >
            <span className="text-[#6C47FF] text-sm font-medium">Frameworks</span>
            <h2 className="mt-2 text-3xl md:text-4xl font-bold">
              Build with SDKs for
              <br />
              modern frameworks
            </h2>
            <p className="mt-4 text-neutral-400">
              Zalt keeps developer experience front-and-center by providing helpful SDKs for most modern frameworks on web and mobile.
            </p>
            <a href="#" className="inline-flex items-center gap-1 mt-4 text-white font-medium hover:text-[#6C47FF] transition-colors">
              All frameworks
              <ChevronRight size={16} />
            </a>

            {/* Framework grid */}
            <div className="mt-8 grid grid-cols-3 gap-4">
              {frameworks.map((fw, i) => (
                <motion.div
                  key={fw.name}
                  initial={{ opacity: 0, scale: 0.9 }}
                  whileInView={{ opacity: 1, scale: 1 }}
                  viewport={{ once: true }}
                  transition={{ delay: i * 0.05 }}
                  className="aspect-square border border-neutral-800 rounded-xl flex items-center justify-center hover:border-neutral-700 transition-colors cursor-pointer group"
                >
                  <span className="text-2xl text-neutral-500 group-hover:text-white transition-colors">
                    {fw.icon}
                  </span>
                </motion.div>
              ))}
            </div>
          </motion.div>

          {/* Integrations */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.2 }}
          >
            <span className="text-cyan-400 text-sm font-medium">Integrations</span>
            <h2 className="mt-2 text-3xl md:text-4xl font-bold">
              Integrate with
              <br />
              the tools you love
            </h2>
            <p className="mt-4 text-neutral-400">
              Leverage Zalt as the source of truth for your user data and integrate with the tools that you already depend on.
            </p>
            <a href="#" className="inline-flex items-center gap-1 mt-4 text-white font-medium hover:text-cyan-400 transition-colors">
              All integrations
              <ChevronRight size={16} />
            </a>

            {/* Integration grid */}
            <div className="mt-8 grid grid-cols-3 gap-4">
              {integrations.map((int, i) => (
                <motion.div
                  key={int.name}
                  initial={{ opacity: 0, scale: 0.9 }}
                  whileInView={{ opacity: 1, scale: 1 }}
                  viewport={{ once: true }}
                  transition={{ delay: 0.2 + i * 0.05 }}
                  className="aspect-square border border-neutral-800 rounded-xl flex items-center justify-center hover:border-neutral-700 transition-colors cursor-pointer group"
                >
                  <span className="text-2xl text-neutral-500 group-hover:text-white transition-colors">
                    {int.icon}
                  </span>
                </motion.div>
              ))}
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}

export default ClerkFrameworks;
