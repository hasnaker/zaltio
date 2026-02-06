'use client';

import React from 'react';
import { motion } from 'framer-motion';
import { Shield, Bot, Key, Fingerprint, Mail, Smartphone, Link2, Sparkles } from 'lucide-react';

// Feature cards data
const features = [
  {
    title: 'Session Management',
    description: 'Zalt manages the full session lifecycle, including critical security functionality like active device monitoring and session revocation.',
    icon: null,
    preview: (
      <div className="bg-neutral-800 rounded-lg p-4 space-y-3">
        <div className="flex items-center gap-2 text-xs text-neutral-400">
          <div className="w-2 h-2 bg-green-500 rounded-full" />
          <span>Device</span>
        </div>
        <div className="flex items-center gap-2 text-xs text-neutral-400">
          <div className="w-2 h-2 bg-green-500 rounded-full" />
          <span>Browser</span>
        </div>
        <div className="flex items-center gap-2 text-xs text-neutral-400">
          <div className="w-2 h-2 bg-green-500 rounded-full" />
          <span>Location</span>
        </div>
        <button className="mt-2 text-xs text-red-400 hover:text-red-300">
          Sign out device
        </button>
      </div>
    ),
  },
  {
    title: 'Email and SMS one-time passcodes',
    description: 'Fast and reliable one-time passcode delivery with built-in brute force prevention.',
    icon: null,
    preview: (
      <div className="flex gap-2">
        {['Phone', 'SMS', 'Books', 'TV'].map((item, i) => (
          <div key={item} className={`w-10 h-10 rounded-lg flex items-center justify-center ${i === 0 ? 'bg-[#6C47FF]' : 'bg-neutral-800'}`}>
            <span className="text-xs text-white">{item[0]}</span>
          </div>
        ))}
      </div>
    ),
  },
  {
    title: 'Multifactor Authentication',
    description: "Each user's self-serve multifactor settings are enforced automatically during sign-in.",
    icon: Fingerprint,
    preview: null,
  },
  {
    title: 'Magic Links',
    description: 'Improve sign-up conversion rates and filter out spam/fraud with Magic Links.',
    icon: Link2,
    preview: null,
  },
  {
    title: 'Fraud and Abuse Prevention',
    description: 'Reduce fraudulent sign-ups and free trial abuse by blocking high-risk disposable email domains and restricting the use of email subaddresses with the "+" separator.',
    icon: null,
    preview: (
      <div className="flex items-center gap-2 bg-neutral-800 rounded-lg px-3 py-2">
        <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />
        <span className="text-xs text-neutral-400">Fraudulent sign-ups detected</span>
        <span className="ml-auto text-xs text-red-400">1609</span>
      </div>
    ),
  },
  {
    title: 'Bot Detection',
    description: 'Dramatically reduce fraudulent sign-ups with built-in, continually updated machine learning.',
    icon: Bot,
    preview: (
      <div className="relative">
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="w-16 h-16 border-2 border-[#6C47FF]/30 rounded-full animate-ping" />
        </div>
        <div className="relative w-16 h-16 bg-neutral-800 rounded-full flex items-center justify-center">
          <Fingerprint className="w-8 h-8 text-[#6C47FF]" />
        </div>
      </div>
    ),
  },
  {
    title: 'Social Sign-On',
    description: 'Add high-conversion Social Sign-on (SSO) to your application in minutes. 20+ options and growing.',
    icon: null,
    preview: (
      <div className="flex gap-3">
        <div className="w-12 h-12 bg-neutral-800 rounded-xl flex items-center justify-center">
          <svg className="w-6 h-6" fill="white" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
        </div>
        <div className="w-12 h-12 bg-neutral-800 rounded-xl flex items-center justify-center">
          <span className="text-white font-bold">N</span>
        </div>
        <div className="w-12 h-12 bg-[#1DA1F2] rounded-xl flex items-center justify-center">
          <span className="text-white">☁</span>
        </div>
        <div className="w-12 h-12 bg-neutral-800 rounded-xl flex items-center justify-center">
          <span className="text-white">▲</span>
        </div>
      </div>
    ),
  },
  {
    title: 'Passwords',
    description: 'Simple and secure password authentication, complete with breach detection and recovery options.',
    icon: Key,
    preview: (
      <div className="space-y-2">
        <div className="h-2 bg-neutral-700 rounded-full overflow-hidden">
          <div className="h-full w-3/4 bg-gradient-to-r from-[#6C47FF] to-cyan-400 rounded-full" />
        </div>
        <div className="flex gap-1">
          {Array(10).fill(0).map((_, i) => (
            <span key={i} className="text-cyan-400">•</span>
          ))}
        </div>
      </div>
    ),
  },
];

// User profile card
function UserProfileCard() {
  return (
    <div className="bg-neutral-800 rounded-xl p-4 w-[200px]">
      <div className="text-xs text-neutral-500 mb-2">TPeSWDBg35DwBs</div>
      <div className="flex flex-col items-center">
        <div className="w-16 h-16 bg-gradient-to-br from-purple-500 to-pink-500 rounded-full mb-3" />
        <div className="text-sm font-medium text-white">Arielle Harding</div>
        <div className="text-xs text-neutral-400">a.harding@example.com</div>
      </div>
    </div>
  );
}

export function ClerkDarkFeatures() {
  return (
    <section className="py-24 bg-[#0F0F10] text-white">
      <div className="max-w-7xl mx-auto px-6">
        {/* Section header */}
        <div className="text-center mb-16">
          <span className="text-[#6C47FF] text-sm font-medium">User authentication</span>
          <h2 className="mt-2 text-4xl md:text-5xl font-bold">
            Everything you need for authentication
          </h2>
          <p className="mt-4 text-lg text-neutral-400 max-w-2xl mx-auto">
            Ever feel like authentication requirements change with the season?
            Zalt keeps up with the latest trends and security best practices.
          </p>
          <a href="#" className="inline-flex items-center gap-1 mt-4 text-white font-medium hover:text-[#6C47FF] transition-colors">
            Explore user authentication
            <span>→</span>
          </a>
        </div>

        {/* Features grid */}
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
          {/* Large feature card - Fraud Prevention */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="bg-neutral-900 rounded-2xl p-6 border border-neutral-800"
          >
            <div className="h-32 mb-6 flex items-center justify-center">
              <div className="relative">
                <div className="absolute -inset-4 bg-[#6C47FF]/10 rounded-full blur-xl" />
                <Shield className="w-16 h-16 text-[#6C47FF] relative" />
              </div>
            </div>
            <h3 className="text-lg font-semibold mb-2">Advanced security</h3>
            <p className="text-sm text-neutral-400">
              Zalt is SOC 2 type 2 compliant and CCPA compliant. We conduct regular third-party audits and penetration tests.
            </p>
          </motion.div>

          {/* Session Management */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.1 }}
            className="bg-neutral-900 rounded-2xl p-6 border border-neutral-800"
          >
            <h3 className="text-lg font-semibold mb-2">Session Management</h3>
            <p className="text-sm text-neutral-400 mb-4">
              Zalt manages the full session lifecycle, including critical security functionality like active device monitoring and session revocation.
            </p>
            <div className="bg-neutral-800 rounded-lg p-4 space-y-2">
              {['Device', 'Browser', 'Location'].map((item) => (
                <div key={item} className="flex items-center gap-2 text-xs text-neutral-400">
                  <div className="w-1.5 h-1.5 bg-green-500 rounded-full" />
                  <span>{item}</span>
                </div>
              ))}
              <button className="mt-2 text-xs text-neutral-500 hover:text-red-400 transition-colors">
                Sign out device
              </button>
            </div>
          </motion.div>

          {/* User Profile Card */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.2 }}
            className="bg-neutral-900 rounded-2xl p-6 border border-neutral-800 flex items-center justify-center"
          >
            <UserProfileCard />
          </motion.div>

          {/* MFA */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.3 }}
            className="bg-neutral-900 rounded-2xl p-6 border border-neutral-800"
          >
            <div className="h-24 mb-4 flex items-center justify-center">
              <div className="relative">
                <div className="absolute inset-0 bg-[#6C47FF]/20 rounded-full blur-xl animate-pulse" />
                <Fingerprint className="w-12 h-12 text-[#6C47FF] relative" />
              </div>
            </div>
            <h3 className="text-lg font-semibold mb-2">Multifactor Authentication</h3>
            <p className="text-sm text-neutral-400">
              Each user's self-serve multifactor settings are enforced automatically during sign-in.
            </p>
          </motion.div>

          {/* Bot Detection */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.4 }}
            className="bg-neutral-900 rounded-2xl p-6 border border-neutral-800"
          >
            <div className="h-24 mb-4 flex items-center justify-center">
              <div className="grid grid-cols-3 gap-2">
                {Array(9).fill(0).map((_, i) => (
                  <div key={i} className={`w-3 h-3 rounded-full ${i === 4 ? 'bg-[#6C47FF]' : 'bg-neutral-700'}`} />
                ))}
              </div>
            </div>
            <h3 className="text-lg font-semibold mb-2">Bot Detection</h3>
            <p className="text-sm text-neutral-400">
              Dramatically reduce fraudulent sign-ups with built-in, continually updated machine learning.
            </p>
          </motion.div>

          {/* OTP */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.5 }}
            className="bg-neutral-900 rounded-2xl p-6 border border-neutral-800"
          >
            <div className="flex gap-2 mb-4">
              {['📱', '💬', '📚', '📺'].map((emoji, i) => (
                <div key={i} className={`w-10 h-10 rounded-lg flex items-center justify-center ${i === 0 ? 'bg-[#6C47FF]' : 'bg-neutral-800'}`}>
                  <span>{emoji}</span>
                </div>
              ))}
            </div>
            <h3 className="text-lg font-semibold mb-2">Email and SMS one-time passcodes</h3>
            <p className="text-sm text-neutral-400">
              Fast and reliable one-time passcode delivery with built-in brute force prevention.
            </p>
          </motion.div>

          {/* Fraud Prevention */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.6 }}
            className="bg-neutral-900 rounded-2xl p-6 border border-neutral-800"
          >
            <div className="flex items-center gap-2 bg-neutral-800 rounded-lg px-3 py-2 mb-4">
              <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />
              <span className="text-xs text-neutral-400">Fraudulent sign-ups detected</span>
              <span className="ml-auto text-xs text-red-400">1609</span>
            </div>
            <h3 className="text-lg font-semibold mb-2">Fraud and Abuse Prevention</h3>
            <p className="text-sm text-neutral-400">
              Reduce fraudulent sign-ups and free trial abuse by blocking high-risk disposable email domains.
            </p>
          </motion.div>

          {/* Social Sign-On */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.7 }}
            className="bg-neutral-900 rounded-2xl p-6 border border-neutral-800"
          >
            <div className="flex gap-2 mb-4">
              <div className="w-10 h-10 bg-neutral-800 rounded-xl flex items-center justify-center">
                <svg className="w-5 h-5" fill="white" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
              </div>
              <div className="w-10 h-10 bg-neutral-800 rounded-xl flex items-center justify-center text-white font-bold">N</div>
              <div className="w-10 h-10 bg-[#1DA1F2] rounded-xl flex items-center justify-center text-white">☁</div>
              <div className="w-10 h-10 bg-neutral-800 rounded-xl flex items-center justify-center text-white">▲</div>
            </div>
            <h3 className="text-lg font-semibold mb-2">Social Sign-On</h3>
            <p className="text-sm text-neutral-400">
              Add high-conversion Social Sign-on (SSO) to your application in minutes. 20+ options and growing.
            </p>
          </motion.div>

          {/* Passwords */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.8 }}
            className="bg-neutral-900 rounded-2xl p-6 border border-neutral-800"
          >
            <div className="mb-4">
              <div className="bg-neutral-800 rounded-lg px-4 py-3 border border-cyan-500/30">
                <div className="flex gap-1">
                  {Array(10).fill(0).map((_, i) => (
                    <span key={i} className="text-cyan-400 text-lg">•</span>
                  ))}
                </div>
              </div>
            </div>
            <h3 className="text-lg font-semibold mb-2">Passwords</h3>
            <p className="text-sm text-neutral-400">
              Simple and secure password authentication, complete with breach detection and recovery options.
            </p>
          </motion.div>
        </div>
      </div>
    </section>
  );
}

export default ClerkDarkFeatures;
