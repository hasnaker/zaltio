'use client';

import React from 'react';
import { motion } from 'framer-motion';
import { Check, ChevronRight } from 'lucide-react';

export function ClerkBilling() {
  return (
    <section className="py-24 bg-neutral-50">
      <div className="max-w-7xl mx-auto px-6">
        <div className="grid lg:grid-cols-2 gap-16 items-center">
          {/* Left content */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
          >
            <div className="flex items-center gap-2 mb-4">
              <span className="text-[#6C47FF] text-sm font-medium">Billing</span>
              <span className="px-2 py-0.5 bg-[#6C47FF]/10 text-[#6C47FF] text-xs font-medium rounded-full">Beta</span>
            </div>
            
            <h2 className="text-4xl md:text-5xl font-bold text-neutral-900 leading-tight">
              Subscription billing,
              <br />
              without the headache
            </h2>
            
            <p className="mt-6 text-lg text-neutral-500">
              Add subscriptions to your B2C or B2B application without having to write payment code, custom UI, or wrangle webhooks. Just drop in React components and start earning recurring revenue.
            </p>

            <p className="mt-6 text-neutral-700 font-medium">
              Here's what you can do out of the box:
            </p>

            <ul className="mt-4 space-y-3">
              {[
                'Define and manage plans',
                'Unify user and subscription data',
                'Gate access to content',
              ].map((item) => (
                <li key={item} className="flex items-center gap-3 text-neutral-600">
                  <div className="w-5 h-5 rounded-full bg-[#6C47FF]/10 flex items-center justify-center">
                    <Check size={12} className="text-[#6C47FF]" />
                  </div>
                  {item}
                </li>
              ))}
            </ul>

            <a href="#" className="inline-flex items-center gap-1 mt-8 text-[#6C47FF] font-medium hover:underline">
              Explore Billing features
              <ChevronRight size={16} />
            </a>
          </motion.div>

          {/* Right: Browser mockup */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.2 }}
            className="relative"
          >
            {/* Browser window */}
            <div className="bg-white rounded-xl shadow-2xl border border-neutral-200 overflow-hidden">
              {/* Browser header */}
              <div className="flex items-center gap-2 px-4 py-3 border-b border-neutral-100">
                <div className="flex gap-1.5">
                  <div className="w-3 h-3 rounded-full bg-red-400" />
                  <div className="w-3 h-3 rounded-full bg-yellow-400" />
                  <div className="w-3 h-3 rounded-full bg-green-400" />
                </div>
                <div className="flex-1 text-center text-xs text-neutral-400">Acme, Inc.</div>
              </div>

              {/* Browser content */}
              <div className="p-6">
                {/* Nav */}
                <div className="flex items-center gap-6 mb-8 text-sm">
                  <div className="w-8 h-8 bg-neutral-100 rounded-lg" />
                  <span className="text-neutral-600">Product</span>
                  <span className="text-neutral-600">Pricing</span>
                  <span className="text-neutral-600">Integrations</span>
                  <span className="text-neutral-600">Blog</span>
                </div>

                {/* Pricing header */}
                <div className="text-center mb-8">
                  <h3 className="text-2xl font-bold text-neutral-900">Tailor made pricing from Acme</h3>
                  <p className="text-sm text-neutral-400 mt-1">Free 365-day trial, no credit card required</p>
                </div>

                {/* Pricing cards */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="border border-neutral-200 rounded-xl p-4">
                    <div className="text-sm text-neutral-500 mb-2">Starter Acme Plan</div>
                    <div className="text-2xl font-bold">$9<span className="text-sm font-normal text-neutral-400">/month</span></div>
                    <div className="flex items-center gap-2 mt-2 text-xs text-neutral-400">
                      <input type="radio" className="w-3 h-3" />
                      <span>Billed annually</span>
                    </div>
                    <button className="w-full mt-4 py-2 bg-[#6C47FF] text-white text-sm rounded-lg">
                      Get started
                    </button>
                    <ul className="mt-4 space-y-2 text-xs text-neutral-500">
                      <li>Custom branding</li>
                      <li>Mobile app integration</li>
                      <li>Data Transfers</li>
                    </ul>
                  </div>

                  <div className="border border-neutral-200 rounded-xl p-4">
                    <div className="text-sm text-neutral-500 mb-2">Pro Acme Plan</div>
                    <div className="text-2xl font-bold">$19<span className="text-sm font-normal text-neutral-400">/month</span></div>
                    <div className="flex items-center gap-2 mt-2 text-xs text-neutral-400">
                      <input type="radio" className="w-3 h-3" />
                      <span>Billed annually</span>
                    </div>
                    <button className="w-full mt-4 py-2 border border-neutral-200 text-neutral-700 text-sm rounded-lg">
                      Get started
                    </button>
                    <ul className="mt-4 space-y-2 text-xs text-neutral-500">
                      <li>Everything in Starter</li>
                      <li>Unlimited</li>
                      <li>24/7 priority support</li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>

            {/* Checkout modal overlay */}
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true }}
              transition={{ delay: 0.4 }}
              className="absolute top-20 -right-4 bg-white rounded-xl shadow-2xl border border-neutral-200 p-6 w-[280px]"
            >
              <div className="flex items-center justify-between mb-6">
                <span className="font-medium">Checkout</span>
                <button className="text-neutral-400 hover:text-neutral-600">×</button>
              </div>

              {/* Success state */}
              <div className="text-center py-6">
                <div className="w-12 h-12 bg-neutral-100 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Check size={24} className="text-neutral-600" />
                </div>
                <h4 className="font-semibold text-neutral-900">Payment was successful!</h4>
                <p className="text-sm text-neutral-400 mt-1">Your new subscription is all set.</p>
              </div>

              {/* Payment details */}
              <div className="border-t border-neutral-100 pt-4 mt-4 space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-neutral-500">Total paid</span>
                  <span className="font-medium">$14.00</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-neutral-500">Payment method</span>
                  <span className="font-medium">💳 Visa</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-neutral-500">Payment ID</span>
                  <span className="font-mono text-xs">clm-cpayer_393JW...J938 📋</span>
                </div>
              </div>

              <button className="w-full mt-6 py-2.5 bg-[#6C47FF] text-white text-sm font-medium rounded-lg">
                Go to app
              </button>
            </motion.div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}

export default ClerkBilling;
