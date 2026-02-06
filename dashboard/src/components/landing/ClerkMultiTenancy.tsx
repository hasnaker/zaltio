'use client';

import React from 'react';
import { motion } from 'framer-motion';
import { ChevronRight, Settings, Plus } from 'lucide-react';

export function ClerkMultiTenancy() {
  return (
    <section className="py-24 bg-white">
      <div className="max-w-7xl mx-auto px-6">
        {/* Section header */}
        <div className="mb-16">
          <h2 className="text-4xl md:text-5xl font-bold text-neutral-900">
            The easy solution to multi-tenancy
          </h2>
          <p className="mt-4 text-lg text-neutral-500 max-w-2xl">
            Zalt has all the features you need to onboard and manage the 
            users and organizations of your multi-tenant SaaS application.
          </p>
          <a href="#" className="inline-flex items-center gap-1 mt-4 text-[#6C47FF] font-medium hover:underline">
            Explore B2B features
            <ChevronRight size={16} />
          </a>
        </div>

        {/* Features grid */}
        <div className="grid lg:grid-cols-3 gap-6">
          {/* Custom roles and permissions */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="bg-white rounded-2xl border border-neutral-200 p-6"
          >
            <h3 className="text-lg font-semibold text-neutral-900 mb-2">
              Custom roles and permissions
            </h3>
            <p className="text-sm text-neutral-500 mb-6">
              Powerful primitives to fully customize your app's authorization story.
            </p>
            
            {/* Avatar grid */}
            <div className="grid grid-cols-3 gap-3 mb-6">
              {[1, 2, 3, 4, 5, 6].map((i) => (
                <div 
                  key={i} 
                  className={`aspect-square rounded-xl border-2 border-dashed ${
                    i <= 4 ? 'border-neutral-300 bg-neutral-50' : 'border-neutral-200'
                  } flex items-center justify-center overflow-hidden`}
                >
                  {i <= 4 && (
                    <div className={`w-full h-full bg-gradient-to-br ${
                      i === 1 ? 'from-orange-300 to-orange-500' :
                      i === 2 ? 'from-blue-300 to-blue-500' :
                      i === 3 ? 'from-pink-300 to-pink-500' :
                      'from-green-300 to-green-500'
                    }`} />
                  )}
                </div>
              ))}
            </div>

            {/* Role tabs */}
            <div className="flex gap-2 text-xs">
              <span className="px-3 py-1.5 bg-neutral-100 rounded-full text-neutral-500">Product Member</span>
              <span className="px-3 py-1.5 bg-neutral-900 text-white rounded-full">Administrator</span>
              <span className="px-3 py-1.5 bg-neutral-100 rounded-full text-neutral-500">Editor</span>
              <span className="px-3 py-1.5 bg-neutral-100 rounded-full text-neutral-500">QA Tester</span>
            </div>
          </motion.div>

          {/* Auto-join & Invitations */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.1 }}
            className="space-y-6"
          >
            {/* Auto-join card */}
            <div className="bg-white rounded-2xl border border-neutral-200 p-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="flex -space-x-2">
                  <div className="w-8 h-8 rounded-full bg-gradient-to-br from-green-400 to-green-600 border-2 border-white" />
                  <div className="w-8 h-8 rounded-full bg-gradient-to-br from-blue-400 to-blue-600 border-2 border-white" />
                  <div className="w-8 h-8 rounded-full bg-gradient-to-br from-purple-400 to-purple-600 border-2 border-white" />
                </div>
                <span className="text-xs bg-neutral-100 px-2 py-1 rounded-full text-neutral-500 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 bg-green-500 rounded-full" />
                  Auto-join
                </span>
              </div>
              <h3 className="text-lg font-semibold text-neutral-900 mb-2">Auto-join</h3>
              <p className="text-sm text-neutral-500">
                Let your users discover and join organizations based on their email domain.
              </p>
            </div>

            {/* Invitations card */}
            <div className="bg-white rounded-2xl border border-neutral-200 p-6">
              <div className="mb-4">
                <button className="inline-flex items-center gap-2 px-4 py-2 bg-neutral-900 text-white text-sm rounded-lg">
                  <span>✉</span>
                  Invite this person
                </button>
              </div>
              <h3 className="text-lg font-semibold text-neutral-900 mb-2">Invitations</h3>
              <p className="text-sm text-neutral-500">
                Fuel your application's growth by making it simple for your customers to invite their team.
              </p>
            </div>
          </motion.div>

          {/* Organization UI Components */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.2 }}
            className="bg-white rounded-2xl border border-neutral-200 p-6"
          >
            <h3 className="text-lg font-semibold text-neutral-900 mb-2">
              Organization UI Components
            </h3>
            <p className="text-sm text-neutral-500 mb-6">
              Zalt's UI components add turn-key simplicity to complex Organization management tasks.
            </p>

            {/* Organization switcher preview */}
            <div className="bg-neutral-50 rounded-xl p-4">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium">⚡ Zalt</span>
                  <ChevronRight size={14} className="text-neutral-400 rotate-90" />
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center gap-3 p-2 bg-white rounded-lg">
                  <div className="w-8 h-8 bg-green-500 rounded-full flex items-center justify-center text-white text-xs font-bold">B</div>
                  <div className="flex-1">
                    <div className="text-sm font-medium">Bluth Company</div>
                    <div className="text-xs text-neutral-400">Mr. Manager</div>
                  </div>
                  <Settings size={14} className="text-neutral-400" />
                </div>

                <div className="flex items-center gap-3 p-2 hover:bg-white rounded-lg cursor-pointer">
                  <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center text-white text-xs font-bold">D</div>
                  <div className="flex-1">
                    <div className="text-sm font-medium">Dunder Mifflin</div>
                    <div className="text-xs text-neutral-400">Asst. to the Regional Manager</div>
                  </div>
                </div>

                <div className="flex items-center gap-3 p-2 hover:bg-white rounded-lg cursor-pointer">
                  <div className="w-8 h-8 bg-gradient-to-br from-orange-400 to-pink-500 rounded-full" />
                  <div className="flex-1">
                    <div className="text-sm font-medium">Personal account</div>
                  </div>
                </div>

                <div className="flex items-center gap-3 p-2 hover:bg-white rounded-lg cursor-pointer text-neutral-500">
                  <div className="w-8 h-8 border-2 border-dashed border-neutral-300 rounded-full flex items-center justify-center">
                    <Plus size={14} />
                  </div>
                  <span className="text-sm">Create organization</span>
                </div>
              </div>

              <div className="mt-4 pt-4 border-t border-neutral-200 flex items-center justify-center gap-2 text-xs text-neutral-400">
                <span>Secured by</span>
                <span className="font-semibold text-neutral-600">⚡ zalt</span>
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}

export default ClerkMultiTenancy;
