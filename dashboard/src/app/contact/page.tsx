'use client';

import { motion } from 'framer-motion';
import { Mail, MapPin, Clock, MessageSquare } from 'lucide-react';
import { ContactForm } from '@/components/forms/ContactForm';

export default function ContactPage() {
  return (
    <div className="min-h-screen bg-neutral-950">
      <div className="max-w-6xl mx-auto px-4 py-16">
        {/* Header */}
        <motion.div 
          initial={{ opacity: 0, y: 20 }} 
          animate={{ opacity: 1, y: 0 }}
          className="text-center mb-12"
        >
          <div className="flex items-center justify-center gap-2 text-emerald-400 text-sm font-mono mb-4">
            <MessageSquare size={14} />
            CONTACT US
          </div>
          <h1 className="font-outfit text-4xl md:text-5xl font-bold text-white mb-4">
            Get in Touch
          </h1>
          <p className="text-neutral-400 max-w-2xl mx-auto">
            Have questions about Zalt? Want to discuss enterprise pricing? 
            We&apos;d love to hear from you.
          </p>
        </motion.div>

        <div className="grid lg:grid-cols-2 gap-12">
          {/* Contact Form */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
          >
            <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
              <h2 className="text-xl font-bold text-white mb-6">Send us a message</h2>
              <ContactForm />
            </div>
          </motion.div>

          {/* Contact Info */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="space-y-6"
          >
            {/* Quick Contact */}
            <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
              <h2 className="text-xl font-bold text-white mb-4">Quick Contact</h2>
              <div className="space-y-4">
                <div className="flex items-start gap-3">
                  <Mail size={20} className="text-emerald-400 mt-0.5" />
                  <div>
                    <p className="text-white font-medium">Email</p>
                    <a href="mailto:hello@zalt.io" className="text-neutral-400 hover:text-emerald-400">
                      hello@zalt.io
                    </a>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <MapPin size={20} className="text-emerald-400 mt-0.5" />
                  <div>
                    <p className="text-white font-medium">Location</p>
                    <p className="text-neutral-400">Istanbul, Turkey</p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <Clock size={20} className="text-emerald-400 mt-0.5" />
                  <div>
                    <p className="text-white font-medium">Response Time</p>
                    <p className="text-neutral-400">Within 24 hours</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Sales */}
            <div className="bg-gradient-to-br from-emerald-500/10 to-emerald-500/5 border border-emerald-500/20 rounded-lg p-6">
              <h2 className="text-xl font-bold text-white mb-2">Enterprise Sales</h2>
              <p className="text-neutral-400 mb-4">
                Looking for custom pricing, SLAs, or dedicated support? 
                Our enterprise team is here to help.
              </p>
              <a 
                href="mailto:enterprise@zalt.io"
                className="inline-flex items-center gap-2 text-emerald-400 hover:text-emerald-300"
              >
                <Mail size={16} />
                enterprise@zalt.io
              </a>
            </div>

            {/* Support */}
            <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
              <h2 className="text-xl font-bold text-white mb-2">Technical Support</h2>
              <p className="text-neutral-400 mb-4">
                Already a customer? Get help from our support team.
              </p>
              <a 
                href="mailto:support@zalt.io"
                className="inline-flex items-center gap-2 text-emerald-400 hover:text-emerald-300"
              >
                <Mail size={16} />
                support@zalt.io
              </a>
            </div>

            {/* FAQ Link */}
            <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
              <h2 className="text-xl font-bold text-white mb-2">Common Questions</h2>
              <p className="text-neutral-400 mb-4">
                Check our documentation for answers to frequently asked questions.
              </p>
              <a 
                href="/docs"
                className="inline-flex items-center gap-2 text-emerald-400 hover:text-emerald-300"
              >
                View Documentation →
              </a>
            </div>
          </motion.div>
        </div>
      </div>
    </div>
  );
}
