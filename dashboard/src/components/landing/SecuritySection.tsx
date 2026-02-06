'use client';

import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Lock, Key, Cpu, CheckCircle, Shield } from 'lucide-react';

const encryptionFlow = [
  { step: 'INPUT', value: 'password123' },
  { step: 'SALT', value: 'a7f3b2c1d8e9...' },
  { step: 'ARGON2ID', value: '32MB | t=5 | p=2' },
  { step: 'HASH', value: '$argon2id$v=19$m=32768...' },
];

export function SecuritySection() {
  const [activeStep, setActiveStep] = useState(0);
  const [keyAge, setKeyAge] = useState(15);

  useEffect(() => {
    const interval = setInterval(() => {
      setActiveStep(prev => (prev + 1) % encryptionFlow.length);
    }, 1500);
    return () => clearInterval(interval);
  }, []);

  return (
    <section id="security" className="py-32 px-6 bg-neutral-900 relative overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 bg-[linear-gradient(rgba(16,185,129,0.015)_1px,transparent_1px),linear-gradient(90deg,rgba(16,185,129,0.015)_1px,transparent_1px)] bg-[size:80px_80px]" />

      <div className="max-w-7xl mx-auto relative">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-20"
        >
          <motion.div className="inline-flex items-center gap-2 px-4 py-2 rounded border border-emerald-500/30 bg-emerald-500/5 mb-6">
            <Lock size={14} className="text-emerald-500" />
            <span className="text-emerald-400 text-sm font-mono">ENCRYPTION_LAYER</span>
          </motion.div>
          <h2 className="font-outfit text-4xl md:text-5xl font-bold text-white mb-4">
            Military-Grade <span className="text-emerald-400">Cryptography</span>
          </h2>
          <p className="text-neutral-400 max-w-2xl mx-auto">
            Every byte encrypted. Every key rotated. Every access logged.
          </p>
        </motion.div>

        <div className="grid lg:grid-cols-2 gap-12">
          {/* Left: Encryption visualization */}
          <motion.div
            initial={{ opacity: 0, x: -30 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            className="bg-neutral-950 border border-emerald-500/10 rounded-lg overflow-hidden"
          >
            <div className="px-6 py-4 border-b border-emerald-500/10 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Cpu size={18} className="text-emerald-500" />
                <span className="text-white font-semibold text-sm">Password Hashing Pipeline</span>
              </div>
              <span className="text-xs text-emerald-500/50 font-mono">ARGON2ID</span>
            </div>
            
            <div className="p-6 space-y-4">
              {encryptionFlow.map((item, i) => (
                <motion.div
                  key={item.step}
                  animate={{
                    opacity: i <= activeStep ? 1 : 0.3,
                    x: i <= activeStep ? 0 : 10,
                  }}
                  className="flex items-center gap-4 p-4 rounded bg-neutral-900 border border-emerald-500/10"
                >
                  <div className={`w-10 h-10 rounded flex items-center justify-center ${
                    i < activeStep ? 'bg-emerald-500/20' : 
                    i === activeStep ? 'bg-emerald-500/10' : 'bg-neutral-800'
                  }`}>
                    {i < activeStep ? (
                      <CheckCircle size={18} className="text-emerald-500" />
                    ) : i === activeStep ? (
                      <motion.div
                        animate={{ rotate: 360 }}
                        transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
                        className="w-4 h-4 border-2 border-emerald-500 border-t-transparent rounded-full"
                      />
                    ) : (
                      <span className="text-neutral-600 text-xs font-mono">{i + 1}</span>
                    )}
                  </div>
                  <div className="flex-1">
                    <p className="text-xs text-emerald-500/70 font-mono">{item.step}</p>
                    <p className={`font-mono text-sm ${i <= activeStep ? 'text-white' : 'text-neutral-600'}`}>
                      {item.value}
                    </p>
                  </div>
                </motion.div>
              ))}
            </div>
          </motion.div>

          {/* Right: Security features */}
          <div className="space-y-6">
            {/* KMS */}
            <motion.div
              initial={{ opacity: 0, x: 30 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              className="bg-neutral-950 border border-emerald-500/10 rounded-lg p-6"
            >
              <div className="flex items-center gap-4 mb-4">
                <div className="w-12 h-12 rounded border border-emerald-500/30 bg-emerald-500/5 flex items-center justify-center">
                  <Shield size={24} className="text-emerald-500" />
                </div>
                <div>
                  <h4 className="text-white font-semibold text-sm">AWS KMS HSM</h4>
                  <p className="text-xs text-neutral-500">Hardware Security Modules</p>
                </div>
              </div>
              <p className="text-sm text-neutral-400 mb-4">
                Keys generated and stored in FIPS 140-2 Level 3 validated hardware.
              </p>
              <div className="flex flex-wrap gap-2">
                {['FIPS-140-2', 'Level 3', 'HSM', 'GovCloud'].map(tag => (
                  <span key={tag} className="px-2 py-1 rounded bg-emerald-500/10 text-emerald-400 text-2xs font-mono">
                    {tag}
                  </span>
                ))}
              </div>
            </motion.div>

            {/* JWT Rotation */}
            <motion.div
              initial={{ opacity: 0, x: 30 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ delay: 0.1 }}
              className="bg-neutral-950 border border-emerald-500/10 rounded-lg p-6"
            >
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 rounded border border-emerald-500/30 bg-emerald-500/5 flex items-center justify-center">
                    <Key size={24} className="text-emerald-500" />
                  </div>
                  <div>
                    <h4 className="text-white font-semibold text-sm">JWT Key Rotation</h4>
                    <p className="text-xs text-neutral-500">RS256 with auto-rotation</p>
                  </div>
                </div>
                <div className="text-right">
                  <p className="text-2xl font-bold text-emerald-400 font-mono">{keyAge}d</p>
                  <p className="text-2xs text-neutral-500">until rotation</p>
                </div>
              </div>
              <div className="h-2 bg-neutral-800 rounded-full overflow-hidden">
                <motion.div
                  initial={{ width: 0 }}
                  whileInView={{ width: `${((30 - keyAge) / 30) * 100}%` }}
                  viewport={{ once: true }}
                  className="h-full bg-emerald-500"
                />
              </div>
            </motion.div>

            {/* Compliance */}
            <motion.div
              initial={{ opacity: 0, x: 30 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ delay: 0.2 }}
              className="grid grid-cols-3 gap-4"
            >
              {[
                { label: 'HIPAA', desc: 'Healthcare' },
                { label: 'GDPR', desc: 'EU Privacy' },
                { label: 'SOC 2', desc: 'Type II' },
              ].map(cert => (
                <div key={cert.label} className="bg-neutral-950 border border-emerald-500/10 rounded-lg p-4 text-center">
                  <p className="text-white font-semibold text-sm">{cert.label}</p>
                  <p className="text-2xs text-neutral-500">{cert.desc}</p>
                </div>
              ))}
            </motion.div>
          </div>
        </div>
      </div>
    </section>
  );
}

export default SecuritySection;