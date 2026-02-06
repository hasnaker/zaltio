'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Quote, ChevronLeft, ChevronRight, Star, Building2, Users, TrendingUp } from 'lucide-react';
import { scrollAnimations, springs } from '@/lib/motion';

// Testimonial data with metrics
const testimonials = [
  {
    id: 1,
    quote: "Zalt let us achieve HIPAA compliance in days, not months. The security architecture is exactly what healthcare needs - WebAuthn, audit logging, and data residency all built-in.",
    name: "Dr. Sarah Mitchell",
    role: "CTO",
    company: "Clinisyn",
    avatar: "SM",
    avatarColor: 'from-purple-500 to-pink-500',
    metrics: [
      { label: 'Time to compliance', value: '3 days' },
      { label: 'Users onboarded', value: '4,000+' },
      { label: 'Countries', value: '11' },
    ],
    rating: 5,
  },
  {
    id: 2,
    quote: "We evaluated Clerk, Auth0, and Zalt. The WebAuthn implementation, EU data residency, and enterprise SSO made Zalt the clear choice for our healthcare platform.",
    name: "Marcus Weber",
    role: "Head of Engineering",
    company: "HealthTech EU",
    avatar: "MW",
    avatarColor: 'from-blue-500 to-cyan-500',
    metrics: [
      { label: 'Auth latency', value: '<50ms' },
      { label: 'Uptime', value: '99.99%' },
      { label: 'Security incidents', value: '0' },
    ],
    rating: 5,
  },
  {
    id: 3,
    quote: "The SDK is beautifully designed. We integrated authentication across our entire platform in a single afternoon. The TypeScript types are perfect.",
    name: "Alex Chen",
    role: "Lead Developer",
    company: "MedFlow",
    avatar: "AC",
    avatarColor: 'from-green-500 to-emerald-500',
    metrics: [
      { label: 'Integration time', value: '4 hours' },
      { label: 'Lines of code', value: '<100' },
      { label: 'Developer satisfaction', value: '10/10' },
    ],
    rating: 5,
  },
  {
    id: 4,
    quote: "Switching from our legacy auth system to Zalt reduced our security overhead by 80%. The MFA options and session management are enterprise-grade.",
    name: "Jennifer Park",
    role: "Security Lead",
    company: "PsychCare",
    avatar: "JP",
    avatarColor: 'from-orange-500 to-red-500',
    metrics: [
      { label: 'Security overhead', value: '-80%' },
      { label: 'Failed login attempts blocked', value: '50K+' },
      { label: 'Compliance audits passed', value: '3' },
    ],
    rating: 5,
  },
];

// Auto-play interval in milliseconds
const AUTO_PLAY_INTERVAL = 6000;

interface TestimonialsSectionProps {
  className?: string;
}

export function TestimonialsSection({ className = '' }: TestimonialsSectionProps) {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [isAutoPlaying, setIsAutoPlaying] = useState(true);
  const [direction, setDirection] = useState(0);

  const currentTestimonial = testimonials[currentIndex];

  // Navigate to next testimonial
  const goToNext = useCallback(() => {
    setDirection(1);
    setCurrentIndex((prev) => (prev + 1) % testimonials.length);
  }, []);

  // Navigate to previous testimonial
  const goToPrev = useCallback(() => {
    setDirection(-1);
    setCurrentIndex((prev) => (prev - 1 + testimonials.length) % testimonials.length);
  }, []);

  // Go to specific testimonial
  const goToIndex = useCallback((index: number) => {
    setDirection(index > currentIndex ? 1 : -1);
    setCurrentIndex(index);
  }, [currentIndex]);

  // Auto-play effect
  useEffect(() => {
    if (!isAutoPlaying) return;

    const interval = setInterval(goToNext, AUTO_PLAY_INTERVAL);
    return () => clearInterval(interval);
  }, [isAutoPlaying, goToNext]);

  // Pause auto-play on hover
  const handleMouseEnter = () => setIsAutoPlaying(false);
  const handleMouseLeave = () => setIsAutoPlaying(true);

  // Animation variants
  const slideVariants = {
    enter: (direction: number) => ({
      x: direction > 0 ? 300 : -300,
      opacity: 0,
    }),
    center: {
      x: 0,
      opacity: 1,
    },
    exit: (direction: number) => ({
      x: direction < 0 ? 300 : -300,
      opacity: 0,
    }),
  };

  return (
    <section className={`py-24 md:py-32 px-6 bg-gradient-to-b from-neutral-900 to-neutral-950 relative overflow-hidden ${className}`}>
      {/* Background decorations */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,rgba(108,71,255,0.1),transparent_50%)]" />
      <div className="absolute top-1/2 left-0 w-96 h-96 bg-primary/5 rounded-full blur-3xl -translate-y-1/2" />
      <div className="absolute top-1/2 right-0 w-96 h-96 bg-accent/5 rounded-full blur-3xl -translate-y-1/2" />

      <div className="max-w-6xl mx-auto relative">
        {/* Section header */}
        <motion.div
          {...scrollAnimations.fadeUp}
          className="text-center mb-16"
        >
          <motion.div 
            className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-white/5 border border-white/10 mb-6"
            whileHover={{ scale: 1.02 }}
          >
            <Quote size={16} className="text-primary" />
            <span className="text-sm font-medium text-white/80">Customer Stories</span>
          </motion.div>
          
          <h2 className="text-4xl md:text-5xl font-bold text-white mb-4">
            Trusted by{' '}
            <span className="bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
              Security Leaders
            </span>
          </h2>
          
          <p className="text-lg text-neutral-400 max-w-2xl mx-auto">
            Healthcare organizations and enterprises trust Zalt with their most sensitive authentication needs.
          </p>
        </motion.div>

        {/* Testimonial carousel */}
        <div
          className="relative"
          onMouseEnter={handleMouseEnter}
          onMouseLeave={handleMouseLeave}
        >
          {/* Main testimonial card */}
          <div className="relative min-h-[400px] md:min-h-[350px]">
            <AnimatePresence mode="wait" custom={direction}>
              <motion.div
                key={currentTestimonial.id}
                custom={direction}
                variants={slideVariants}
                initial="enter"
                animate="center"
                exit="exit"
                transition={{ type: 'spring', stiffness: 300, damping: 30 }}
                className="absolute inset-0"
              >
                <div className="bg-white/5 backdrop-blur-sm border border-white/10 rounded-2xl p-8 md:p-10">
                  <div className="grid md:grid-cols-3 gap-8">
                    {/* Quote and author */}
                    <div className="md:col-span-2">
                      {/* Rating stars */}
                      <div className="flex items-center gap-1 mb-6">
                        {[...Array(currentTestimonial.rating)].map((_, i) => (
                          <Star key={i} size={18} className="fill-yellow-400 text-yellow-400" />
                        ))}
                      </div>

                      {/* Quote */}
                      <blockquote className="text-xl md:text-2xl text-white/90 leading-relaxed mb-8">
                        "{currentTestimonial.quote}"
                      </blockquote>

                      {/* Author */}
                      <div className="flex items-center gap-4">
                        <div className={`w-14 h-14 rounded-full bg-gradient-to-br ${currentTestimonial.avatarColor} 
                                        flex items-center justify-center text-white font-semibold text-lg shadow-lg`}>
                          {currentTestimonial.avatar}
                        </div>
                        <div>
                          <p className="text-white font-semibold text-lg">{currentTestimonial.name}</p>
                          <p className="text-neutral-400">
                            {currentTestimonial.role} at{' '}
                            <span className="text-primary">{currentTestimonial.company}</span>
                          </p>
                        </div>
                      </div>
                    </div>

                    {/* Metrics */}
                    <div className="space-y-4">
                      <p className="text-sm font-medium text-neutral-500 uppercase tracking-wider mb-4">
                        Key Results
                      </p>
                      {currentTestimonial.metrics.map((metric, i) => (
                        <motion.div
                          key={metric.label}
                          initial={{ opacity: 0, x: 20 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: i * 0.1 }}
                          className="bg-white/5 rounded-lg p-4 border border-white/5"
                        >
                          <div className="text-2xl font-bold bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
                            {metric.value}
                          </div>
                          <div className="text-sm text-neutral-400">{metric.label}</div>
                        </motion.div>
                      ))}
                    </div>
                  </div>
                </div>
              </motion.div>
            </AnimatePresence>
          </div>

          {/* Navigation controls */}
          <div className="flex items-center justify-between mt-8">
            {/* Dots indicator */}
            <div className="flex items-center gap-2">
              {testimonials.map((_, index) => (
                <button
                  key={index}
                  onClick={() => goToIndex(index)}
                  className={`w-2.5 h-2.5 rounded-full transition-all duration-300 ${
                    index === currentIndex
                      ? 'bg-primary w-8'
                      : 'bg-white/20 hover:bg-white/40'
                  }`}
                  aria-label={`Go to testimonial ${index + 1}`}
                />
              ))}
            </div>

            {/* Arrow buttons */}
            <div className="flex items-center gap-2">
              <motion.button
                onClick={goToPrev}
                className="w-10 h-10 rounded-full bg-white/5 border border-white/10 
                           flex items-center justify-center text-white/60 hover:text-white 
                           hover:bg-white/10 transition-all"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                aria-label="Previous testimonial"
              >
                <ChevronLeft size={20} />
              </motion.button>
              <motion.button
                onClick={goToNext}
                className="w-10 h-10 rounded-full bg-white/5 border border-white/10 
                           flex items-center justify-center text-white/60 hover:text-white 
                           hover:bg-white/10 transition-all"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                aria-label="Next testimonial"
              >
                <ChevronRight size={20} />
              </motion.button>
            </div>
          </div>
        </div>

        {/* Bottom stats */}
        <motion.div
          {...scrollAnimations.fadeUp}
          className="grid grid-cols-2 md:grid-cols-4 gap-6 mt-16 pt-16 border-t border-white/10"
        >
          {[
            { icon: Building2, value: '100+', label: 'Companies' },
            { icon: Users, value: '50,000+', label: 'Protected Users' },
            { icon: TrendingUp, value: '99.99%', label: 'Uptime' },
            { icon: Star, value: '4.9/5', label: 'Customer Rating' },
          ].map((stat, i) => (
            <motion.div
              key={stat.label}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.1 }}
              className="text-center"
            >
              <stat.icon className="w-6 h-6 text-primary mx-auto mb-3" />
              <div className="text-2xl md:text-3xl font-bold text-white mb-1">{stat.value}</div>
              <div className="text-sm text-neutral-500">{stat.label}</div>
            </motion.div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}

export default TestimonialsSection;
