'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import { Send, CheckCircle, AlertCircle, Loader2 } from 'lucide-react';

interface FormData {
  name: string;
  email: string;
  company: string;
  message: string;
}

interface FormErrors {
  name?: string;
  email?: string;
  company?: string;
  message?: string;
}

type FormStatus = 'idle' | 'submitting' | 'success' | 'error';

export function ContactForm() {
  const [formData, setFormData] = useState<FormData>({
    name: '',
    email: '',
    company: '',
    message: '',
  });
  const [errors, setErrors] = useState<FormErrors>({});
  const [status, setStatus] = useState<FormStatus>('idle');
  const [errorMessage, setErrorMessage] = useState('');

  const validateEmail = (email: string): boolean => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  const validateForm = (): boolean => {
    const newErrors: FormErrors = {};

    if (!formData.name.trim()) {
      newErrors.name = 'Name is required';
    }

    if (!formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!validateEmail(formData.email)) {
      newErrors.email = 'Please enter a valid email address';
    }

    if (!formData.company.trim()) {
      newErrors.company = 'Company is required';
    }

    if (!formData.message.trim()) {
      newErrors.message = 'Message is required';
    } else if (formData.message.trim().length < 10) {
      newErrors.message = 'Message must be at least 10 characters';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
  ) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    
    // Clear error when user starts typing
    if (errors[name as keyof FormErrors]) {
      setErrors(prev => ({ ...prev, [name]: undefined }));
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    setStatus('submitting');
    setErrorMessage('');

    try {
      const response = await fetch('/api/contact', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      });

      if (response.status === 429) {
        setStatus('error');
        setErrorMessage('Too many requests. Please try again later.');
        return;
      }

      if (!response.ok) {
        throw new Error('Failed to submit form');
      }

      setStatus('success');
      setFormData({ name: '', email: '', company: '', message: '' });
    } catch {
      setStatus('error');
      setErrorMessage('Something went wrong. Please try again.');
    }
  };

  if (status === 'success') {
    return (
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="bg-emerald-500/10 border border-emerald-500/30 rounded-lg p-8 text-center"
      >
        <CheckCircle size={48} className="text-emerald-400 mx-auto mb-4" />
        <h3 className="text-xl font-bold text-white mb-2">Message Sent!</h3>
        <p className="text-neutral-400">
          Thanks for reaching out. We&apos;ll get back to you within 24 hours.
        </p>
        <button
          onClick={() => setStatus('idle')}
          className="mt-4 text-emerald-400 hover:text-emerald-300"
        >
          Send another message
        </button>
      </motion.div>
    );
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {/* Name */}
      <div>
        <label htmlFor="name" className="block text-sm text-neutral-400 mb-1">
          Name *
        </label>
        <input
          type="text"
          id="name"
          name="name"
          value={formData.name}
          onChange={handleChange}
          className={`w-full px-4 py-2 bg-neutral-800 border rounded-lg text-white placeholder-neutral-500 focus:outline-none ${
            errors.name 
              ? 'border-red-500 focus:border-red-500' 
              : 'border-neutral-700 focus:border-emerald-500'
          }`}
          placeholder="Your name"
          aria-invalid={!!errors.name}
          aria-describedby={errors.name ? 'name-error' : undefined}
        />
        {errors.name && (
          <p id="name-error" className="mt-1 text-sm text-red-400">
            {errors.name}
          </p>
        )}
      </div>

      {/* Email */}
      <div>
        <label htmlFor="email" className="block text-sm text-neutral-400 mb-1">
          Email *
        </label>
        <input
          type="email"
          id="email"
          name="email"
          value={formData.email}
          onChange={handleChange}
          className={`w-full px-4 py-2 bg-neutral-800 border rounded-lg text-white placeholder-neutral-500 focus:outline-none ${
            errors.email 
              ? 'border-red-500 focus:border-red-500' 
              : 'border-neutral-700 focus:border-emerald-500'
          }`}
          placeholder="you@company.com"
          aria-invalid={!!errors.email}
          aria-describedby={errors.email ? 'email-error' : undefined}
        />
        {errors.email && (
          <p id="email-error" className="mt-1 text-sm text-red-400">
            {errors.email}
          </p>
        )}
      </div>

      {/* Company */}
      <div>
        <label htmlFor="company" className="block text-sm text-neutral-400 mb-1">
          Company *
        </label>
        <input
          type="text"
          id="company"
          name="company"
          value={formData.company}
          onChange={handleChange}
          className={`w-full px-4 py-2 bg-neutral-800 border rounded-lg text-white placeholder-neutral-500 focus:outline-none ${
            errors.company 
              ? 'border-red-500 focus:border-red-500' 
              : 'border-neutral-700 focus:border-emerald-500'
          }`}
          placeholder="Your company"
          aria-invalid={!!errors.company}
          aria-describedby={errors.company ? 'company-error' : undefined}
        />
        {errors.company && (
          <p id="company-error" className="mt-1 text-sm text-red-400">
            {errors.company}
          </p>
        )}
      </div>

      {/* Message */}
      <div>
        <label htmlFor="message" className="block text-sm text-neutral-400 mb-1">
          Message *
        </label>
        <textarea
          id="message"
          name="message"
          value={formData.message}
          onChange={handleChange}
          rows={4}
          className={`w-full px-4 py-2 bg-neutral-800 border rounded-lg text-white placeholder-neutral-500 focus:outline-none resize-none ${
            errors.message 
              ? 'border-red-500 focus:border-red-500' 
              : 'border-neutral-700 focus:border-emerald-500'
          }`}
          placeholder="How can we help you?"
          aria-invalid={!!errors.message}
          aria-describedby={errors.message ? 'message-error' : undefined}
        />
        {errors.message && (
          <p id="message-error" className="mt-1 text-sm text-red-400">
            {errors.message}
          </p>
        )}
      </div>

      {/* Error Message */}
      {status === 'error' && errorMessage && (
        <div className="flex items-center gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
          <AlertCircle size={18} className="text-red-400" />
          <p className="text-sm text-red-400">{errorMessage}</p>
        </div>
      )}

      {/* Submit Button */}
      <button
        type="submit"
        disabled={status === 'submitting'}
        className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-emerald-500 text-neutral-950 rounded-lg font-medium disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {status === 'submitting' ? (
          <>
            <Loader2 size={18} className="animate-spin" />
            Sending...
          </>
        ) : (
          <>
            <Send size={18} />
            Send Message
          </>
        )}
      </button>
    </form>
  );
}

export default ContactForm;
