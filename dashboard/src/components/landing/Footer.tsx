'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import Image from 'next/image';
import { motion } from 'framer-motion';
import { 
  Twitter, Github, Linkedin, Youtube, 
  Mail, ArrowRight, CheckCircle2, Shield
} from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Badge } from '@/components/ui/Badge';
import { cn } from '@/lib/utils';

interface FooterLink {
  label: string;
  href: string;
}

interface FooterColumn {
  title: string;
  links: FooterLink[];
}

const footerColumns: FooterColumn[] = [
  {
    title: 'Product',
    links: [
      { label: 'Features', href: '/features' },
      { label: 'Pricing', href: '/pricing' },
      { label: 'Changelog', href: '/changelog' },
      { label: 'Roadmap', href: '/roadmap' },
      { label: 'Status', href: 'https://status.zalt.io' },
    ],
  },
  {
    title: 'Resources',
    links: [
      { label: 'Documentation', href: '/docs' },
      { label: 'API Reference', href: '/docs/api' },
      { label: 'Guides', href: '/docs/guides' },
      { label: 'Blog', href: '/blog' },
      { label: 'Community', href: '/community' },
    ],
  },
  {
    title: 'Company',
    links: [
      { label: 'About', href: '/about' },
      { label: 'Careers', href: '/careers' },
      { label: 'Contact', href: '/contact' },
      { label: 'Partners', href: '/partners' },
      { label: 'Press Kit', href: '/press' },
    ],
  },
  {
    title: 'Legal',
    links: [
      { label: 'Privacy Policy', href: '/privacy' },
      { label: 'Terms of Service', href: '/terms' },
      { label: 'Cookie Policy', href: '/cookies' },
      { label: 'DPA', href: '/dpa' },
      { label: 'Security', href: '/security' },
    ],
  },
];

const socialLinks = [
  { icon: Twitter, href: 'https://twitter.com/zaltio', label: 'Twitter' },
  { icon: Github, href: 'https://github.com/zalt-io', label: 'GitHub' },
  { icon: Linkedin, href: 'https://linkedin.com/company/zaltio', label: 'LinkedIn' },
  { icon: Youtube, href: 'https://youtube.com/@zaltio', label: 'YouTube' },
];

const complianceBadges = ['SOC 2', 'HIPAA', 'GDPR', 'ISO 27001'];

// Newsletter form component
function NewsletterForm() {
  const [email, setEmail] = useState('');
  const [isSubmitted, setIsSubmitted] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 1000));
    setIsSubmitted(true);
    setIsLoading(false);
  };

  if (isSubmitted) {
    return (
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="flex items-center gap-3 text-success"
      >
        <CheckCircle2 size={20} />
        <span className="text-sm">Thanks for subscribing!</span>
      </motion.div>
    );
  }

  return (
    <form onSubmit={handleSubmit} className="flex gap-2">
      <Input
        type="email"
        placeholder="Enter your email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        required
        size="sm"
        className="bg-neutral-800 border-neutral-700 text-white placeholder:text-neutral-500 focus:border-primary"
      />
      <Button 
        type="submit" 
        variant="primary" 
        size="sm"
        isLoading={isLoading}
      >
        Subscribe
      </Button>
    </form>
  );
}

export function Footer() {
  return (
    <footer className="bg-neutral-950 text-white">
      {/* Main footer content */}
      <div className="max-w-7xl mx-auto px-6 py-16">
        <div className="grid lg:grid-cols-6 gap-12">
          {/* Brand column */}
          <div className="lg:col-span-2">
            <Link href="/" className="inline-block mb-6">
              <Image
                src="/zalt-full-logo.svg"
                alt="Zalt"
                width={100}
                height={32}
                className="h-8 w-auto brightness-0 invert"
              />
            </Link>
            
            <p className="text-neutral-400 text-sm leading-relaxed mb-6 max-w-xs">
              Enterprise-grade authentication for modern applications. 
              Secure, scalable, and developer-friendly.
            </p>

            {/* Newsletter */}
            <div className="mb-6">
              <p className="text-sm font-medium text-white mb-3">
                Subscribe to our newsletter
              </p>
              <NewsletterForm />
            </div>

            {/* Social links */}
            <div className="flex items-center gap-4">
              {socialLinks.map((social) => (
                <a
                  key={social.label}
                  href={social.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="w-10 h-10 rounded-lg bg-neutral-800 flex items-center justify-center text-neutral-400 hover:text-white hover:bg-neutral-700 transition-colors"
                  aria-label={social.label}
                >
                  <social.icon size={18} />
                </a>
              ))}
            </div>
          </div>

          {/* Link columns */}
          {footerColumns.map((column) => (
            <div key={column.title}>
              <h4 className="text-sm font-semibold text-white mb-4">
                {column.title}
              </h4>
              <ul className="space-y-3">
                {column.links.map((link) => (
                  <li key={link.label}>
                    <Link
                      href={link.href}
                      className="text-sm text-neutral-400 hover:text-white transition-colors"
                    >
                      {link.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>

      {/* Bottom bar */}
      <div className="border-t border-neutral-800">
        <div className="max-w-7xl mx-auto px-6 py-6">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            {/* Copyright */}
            <p className="text-sm text-neutral-500">
              © {new Date().getFullYear()} Zalt.io. All rights reserved.
            </p>

            {/* Compliance badges */}
            <div className="flex items-center gap-3">
              {complianceBadges.map((badge) => (
                <div
                  key={badge}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-neutral-800/50 text-neutral-400"
                >
                  <Shield size={12} />
                  <span className="text-xs font-medium">{badge}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
}

export default Footer;
