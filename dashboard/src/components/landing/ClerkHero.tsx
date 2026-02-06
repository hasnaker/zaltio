'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { motion } from 'framer-motion';
import { ArrowRight, Monitor, Tablet, Smartphone, Tv, Watch } from 'lucide-react';

// Device icons for the device selector
const devices = [
  { icon: Monitor, label: 'Desktop' },
  { icon: Tablet, label: 'Tablet' },
  { icon: Smartphone, label: 'Mobile' },
  { icon: Tv, label: 'TV' },
  { icon: Watch, label: 'Watch' },
];

export function ClerkHero() {
  const [selectedDevice, setSelectedDevice] = useState(0);

  return (
    <section className="relative pt-32 pb-20 overflow-hidden">
      {/* Subtle grid background */}
      <div 
        className="absolute inset-0 opacity-[0.03]"
        style={{
          backgroundImage: `
            linear-gradient(rgba(0, 0, 0, 0.1) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0, 0, 0, 0.1) 1px, transparent 1px)
          `,
          backgroundSize: '60px 60px',
        }}
      />

      <div className="max-w-7xl mx-auto px-6">
        {/* Main headline */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="text-center max-w-4xl mx-auto"
        >
          <h1 className="text-5xl md:text-6xl lg:text-7xl font-bold text-neutral-900 leading-[1.1] tracking-tight">
            More than authentication,
            <br />
            <span className="text-neutral-900">Complete User Management</span>
          </h1>
          
          <p className="mt-6 text-lg md:text-xl text-neutral-500 max-w-2xl mx-auto">
            Need more than sign-in? Zalt gives you full stack auth and user management — 
            so you can launch faster, scale easier, and stay focused on building your business.
          </p>

          {/* CTA Button */}
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="mt-10"
          >
            <Link href="/signup">
              <button className="inline-flex items-center gap-2 px-6 py-3 bg-[#6C47FF] hover:bg-[#5a3ad9] text-white font-medium rounded-lg transition-colors">
                Start building for free
                <ArrowRight size={18} />
              </button>
            </Link>
          </motion.div>
        </motion.div>

        {/* Device Selector Bar */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.3 }}
          className="mt-16 flex justify-center"
        >
          <div className="inline-flex items-center gap-1 p-1.5 bg-neutral-100 rounded-xl">
            {devices.map((device, index) => {
              const Icon = device.icon;
              return (
                <button
                  key={device.label}
                  onClick={() => setSelectedDevice(index)}
                  className={`p-3 rounded-lg transition-all ${
                    selectedDevice === index
                      ? 'bg-white shadow-sm text-neutral-900'
                      : 'text-neutral-400 hover:text-neutral-600'
                  }`}
                >
                  <Icon size={20} />
                </button>
              );
            })}
            <div className="h-8 w-px bg-neutral-200 mx-2" />
            <button className="px-4 py-2 text-sm text-neutral-500 hover:text-neutral-700">
              Seçenekler
            </button>
            <button className="px-4 py-2 bg-[#6C47FF] text-white text-sm font-medium rounded-lg">
              Çek
            </button>
          </div>
        </motion.div>

        {/* Social Proof */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.6, delay: 0.5 }}
          className="mt-20 border-t border-neutral-100 pt-12"
        >
          <div className="flex flex-col md:flex-row items-center justify-between gap-8">
            <p className="text-sm text-neutral-400">
              Trusted by fast-growing
              <br />
              companies around the world.
            </p>
            <div className="flex items-center gap-12">
              {/* Placeholder logos - replace with actual SVGs */}
              <span className="text-xl font-semibold text-neutral-300">◆ Profound</span>
              <span className="text-xl font-semibold text-neutral-300">↗ OpenRouter</span>
              <span className="text-xl font-semibold text-neutral-300">samaya</span>
              <span className="text-xl font-semibold text-neutral-300">▦ David AI</span>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}

export default ClerkHero;
