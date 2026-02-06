'use client';

import React from 'react';
import { motion } from 'framer-motion';

const testimonials = [
  {
    quote: "Zalt has been instrumental in helping us scale our authentication infrastructure. The developer experience is unmatched.",
    author: "Sarah Chen",
    role: "CTO",
    company: "Clinisyn",
    logo: "🏥",
  },
  {
    quote: "We migrated from our custom auth solution to Zalt in just 2 days. The security features and compliance support saved us months of work.",
    author: "Michael Torres",
    role: "Lead Engineer",
    company: "Voczo",
    logo: "🎵",
  },
  {
    quote: "The multi-tenancy support is exactly what we needed for our B2B SaaS. Organizations, roles, and permissions just work.",
    author: "Emma Wilson",
    role: "Founder",
    company: "DataFlow",
    logo: "📊",
  },
];

const companyLogos = [
  { name: 'Vercel', logo: '▲' },
  { name: 'Stripe', logo: '💳' },
  { name: 'Linear', logo: '◇' },
  { name: 'Notion', logo: '📝' },
  { name: 'Figma', logo: '🎨' },
  { name: 'Discord', logo: '💬' },
];

export function ClerkTestimonials() {
  return (
    <section className="py-24 bg-white">
      <div className="max-w-7xl mx-auto px-6">
        {/* Section header */}
        <div className="text-center mb-16">
          <span className="text-[#6C47FF] text-sm font-medium">Testimonials</span>
          <h2 className="mt-2 text-4xl md:text-5xl font-bold text-neutral-900">
            Loved by developers worldwide
          </h2>
          <p className="mt-4 text-lg text-neutral-500 max-w-2xl mx-auto">
            Join thousands of companies that trust Zalt for their authentication needs.
          </p>
        </div>

        {/* Testimonial cards */}
        <div className="grid md:grid-cols-3 gap-6 mb-16">
          {testimonials.map((testimonial, i) => (
            <motion.div
              key={testimonial.author}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.1 }}
              className="bg-neutral-50 rounded-2xl p-6 border border-neutral-100"
            >
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 bg-neutral-200 rounded-full flex items-center justify-center text-xl">
                  {testimonial.logo}
                </div>
                <div>
                  <div className="font-medium text-neutral-900">{testimonial.author}</div>
                  <div className="text-sm text-neutral-500">{testimonial.role} at {testimonial.company}</div>
                </div>
              </div>
              <p className="text-neutral-600 leading-relaxed">"{testimonial.quote}"</p>
            </motion.div>
          ))}
        </div>

        {/* Company logos */}
        <div className="border-t border-neutral-100 pt-12">
          <p className="text-center text-sm text-neutral-400 mb-8">
            Trusted by teams at
          </p>
          <div className="flex flex-wrap justify-center items-center gap-12">
            {companyLogos.map((company, i) => (
              <motion.div
                key={company.name}
                initial={{ opacity: 0 }}
                whileInView={{ opacity: 1 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.05 }}
                className="flex items-center gap-2 text-neutral-400 hover:text-neutral-600 transition-colors"
              >
                <span className="text-2xl">{company.logo}</span>
                <span className="font-medium">{company.name}</span>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

export default ClerkTestimonials;
