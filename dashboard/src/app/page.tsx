'use client';

import React, { useEffect } from 'react';
import { motion, useScroll, useSpring } from 'framer-motion';
import {
  ClerkNavbar,
  ClerkHero,
  ClerkComponents,
  ClerkDarkFeatures,
  ClerkMultiTenancy,
  ClerkBilling,
  ClerkFrameworks,
  ClerkTestimonials,
  ClerkFooter,
} from '@/components/landing';

/**
 * Zalt.io Landing Page
 * 
 * Clerk-Style Modern Design
 * Clean, minimal, professional aesthetics
 * Framer Motion animations throughout
 */
export default function LandingPage() {
  // Smooth scroll behavior
  useEffect(() => {
    document.documentElement.style.scrollBehavior = 'smooth';
    return () => {
      document.documentElement.style.scrollBehavior = 'auto';
    };
  }, []);

  // Scroll progress for indicator
  const { scrollYProgress } = useScroll();
  const smoothProgress = useSpring(scrollYProgress, {
    stiffness: 100,
    damping: 30,
    restDelta: 0.001,
  });

  return (
    <div className="min-h-screen bg-white text-neutral-900 overflow-x-hidden">
      {/* Scroll Progress Indicator */}
      <motion.div
        className="fixed top-0 left-0 right-0 h-0.5 bg-[#6C47FF] z-[60] origin-left"
        style={{ scaleX: smoothProgress }}
      />

      {/* Navigation */}
      <ClerkNavbar />

      {/* Main Content */}
      <main>
        {/* Hero Section */}
        <ClerkHero />

        {/* Components Section - SignUp/SignIn preview */}
        <ClerkComponents />

        {/* Dark Features Section - Authentication features */}
        <ClerkDarkFeatures />

        {/* Multi-tenancy Section */}
        <ClerkMultiTenancy />

        {/* Billing Section */}
        <ClerkBilling />

        {/* Frameworks & Integrations */}
        <ClerkFrameworks />

        {/* Testimonials */}
        <ClerkTestimonials />
      </main>

      {/* Footer */}
      <ClerkFooter />
    </div>
  );
}
