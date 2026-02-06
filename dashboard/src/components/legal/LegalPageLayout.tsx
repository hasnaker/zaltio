'use client';

import { motion } from 'framer-motion';
import Link from 'next/link';
import { FileText, ChevronRight } from 'lucide-react';
import { ReactNode } from 'react';

interface TableOfContentsItem {
  id: string;
  title: string;
}

interface LegalPageLayoutProps {
  title: string;
  lastUpdated: string;
  tableOfContents: TableOfContentsItem[];
  children: ReactNode;
}

export function LegalPageLayout({ 
  title, 
  lastUpdated, 
  tableOfContents, 
  children 
}: LegalPageLayoutProps) {
  return (
    <div className="min-h-screen bg-neutral-950">
      <div className="max-w-4xl mx-auto px-4 py-16">
        {/* Header */}
        <motion.div 
          initial={{ opacity: 0, y: 20 }} 
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <div className="flex items-center gap-2 text-emerald-400 text-sm font-mono mb-4">
            <FileText size={14} />
            LEGAL
          </div>
          <h1 className="font-outfit text-3xl md:text-4xl font-bold text-white mb-2">
            {title}
          </h1>
          <p className="text-neutral-500 text-sm">
            Last updated: {lastUpdated}
          </p>
        </motion.div>

        <div className="grid lg:grid-cols-4 gap-8">
          {/* Table of Contents - Sidebar */}
          <motion.aside
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.1 }}
            className="lg:col-span-1"
          >
            <div className="sticky top-24 bg-neutral-900 border border-emerald-500/10 rounded-lg p-4">
              <h2 className="text-sm font-medium text-white mb-3">Contents</h2>
              <nav className="space-y-1">
                {tableOfContents.map((item, i) => (
                  <a
                    key={item.id}
                    href={`#${item.id}`}
                    className="flex items-center gap-2 text-sm text-neutral-400 hover:text-emerald-400 py-1 transition-colors"
                  >
                    <ChevronRight size={12} />
                    {item.title}
                  </a>
                ))}
              </nav>
            </div>

            {/* Other Legal Pages */}
            <div className="mt-4 bg-neutral-900 border border-emerald-500/10 rounded-lg p-4">
              <h2 className="text-sm font-medium text-white mb-3">Other Policies</h2>
              <nav className="space-y-1">
                <Link href="/privacy" className="block text-sm text-neutral-400 hover:text-emerald-400 py-1">
                  Privacy Policy
                </Link>
                <Link href="/terms" className="block text-sm text-neutral-400 hover:text-emerald-400 py-1">
                  Terms of Service
                </Link>
                <Link href="/security" className="block text-sm text-neutral-400 hover:text-emerald-400 py-1">
                  Security Policy
                </Link>
                <Link href="/dpa" className="block text-sm text-neutral-400 hover:text-emerald-400 py-1">
                  Data Processing Agreement
                </Link>
                <Link href="/cookies" className="block text-sm text-neutral-400 hover:text-emerald-400 py-1">
                  Cookie Policy
                </Link>
              </nav>
            </div>
          </motion.aside>

          {/* Content */}
          <motion.main
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="lg:col-span-3 prose prose-invert prose-emerald max-w-none"
          >
            <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6 md:p-8">
              {children}
            </div>
          </motion.main>
        </div>
      </div>
    </div>
  );
}

export default LegalPageLayout;
