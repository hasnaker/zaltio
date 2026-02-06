'use client';

import React, { forwardRef, HTMLAttributes, useRef, useState } from 'react';
import { motion, useMotionValue, useSpring, useTransform } from 'framer-motion';
import { cn } from '@/lib/utils';
import { springs } from '@/lib/motion';

export type CardVariant = 'default' | 'elevated' | 'gradient-border' | 'glass' | '3d-tilt';

export interface CardProps extends HTMLAttributes<HTMLDivElement> {
  variant?: CardVariant;
  padding?: 'none' | 'sm' | 'md' | 'lg';
  hoverable?: boolean;
  glowOnHover?: boolean;
  children: React.ReactNode;
}

const variantStyles: Record<CardVariant, string> = {
  default: `
    bg-white 
    border border-neutral-200
    rounded-xl
  `,
  elevated: `
    bg-white 
    rounded-xl
    shadow-md
  `,
  'gradient-border': `
    bg-white 
    rounded-xl
    relative
    before:absolute before:inset-0 before:rounded-xl before:p-[1px]
    before:bg-gradient-to-br before:from-primary before:to-accent
    before:-z-10
    before:content-['']
  `,
  glass: `
    bg-white/70 
    backdrop-blur-xl
    border border-white/50
    rounded-xl
  `,
  '3d-tilt': `
    bg-white 
    border border-neutral-200
    rounded-xl
    transform-gpu
    perspective-1000
  `,
};

const paddingStyles: Record<'none' | 'sm' | 'md' | 'lg', string> = {
  none: '',
  sm: 'p-4',
  md: 'p-6',
  lg: 'p-8',
};

// 3D Tilt Card Component
const TiltCard = forwardRef<HTMLDivElement, CardProps>(
  ({ children, padding = 'md', hoverable, glowOnHover, className }, ref) => {
    const cardRef = useRef<HTMLDivElement>(null);
    const [isHovered, setIsHovered] = useState(false);

    const x = useMotionValue(0);
    const y = useMotionValue(0);

    const mouseXSpring = useSpring(x, springs.smooth);
    const mouseYSpring = useSpring(y, springs.smooth);

    const rotateX = useTransform(mouseYSpring, [-0.5, 0.5], ['7.5deg', '-7.5deg']);
    const rotateY = useTransform(mouseXSpring, [-0.5, 0.5], ['-7.5deg', '7.5deg']);

    const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
      if (!cardRef.current) return;

      const rect = cardRef.current.getBoundingClientRect();
      const width = rect.width;
      const height = rect.height;
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;

      const xPct = mouseX / width - 0.5;
      const yPct = mouseY / height - 0.5;

      x.set(xPct);
      y.set(yPct);
    };

    const handleMouseLeave = () => {
      setIsHovered(false);
      x.set(0);
      y.set(0);
    };

    return (
      <motion.div
        ref={cardRef}
        className={cn(
          variantStyles['3d-tilt'],
          paddingStyles[padding],
          'transition-shadow duration-300',
          hoverable && 'hover:border-neutral-300',
          glowOnHover && 'hover:shadow-glow',
          className
        )}
        style={{
          rotateX,
          rotateY,
          transformStyle: 'preserve-3d',
        }}
        onMouseMove={handleMouseMove}
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={handleMouseLeave}
        whileHover={hoverable ? { 
          scale: 1.02,
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.15)',
        } : undefined}
        transition={springs.smooth}
      >
        <div style={{ transform: 'translateZ(20px)' }}>
          {children}
        </div>
      </motion.div>
    );
  }
);

TiltCard.displayName = 'TiltCard';

// Main Card Component
export const Card = forwardRef<HTMLDivElement, CardProps>(
  (
    {
      variant = 'default',
      padding = 'md',
      hoverable = false,
      glowOnHover = false,
      className,
      children,
      ...props
    },
    ref
  ) => {
    // Use TiltCard for 3d-tilt variant
    if (variant === '3d-tilt') {
      return (
        <TiltCard
          ref={ref}
          padding={padding}
          hoverable={hoverable}
          glowOnHover={glowOnHover}
          className={className}
        >
          {children}
        </TiltCard>
      );
    }

    const hoverStyles = hoverable
      ? 'hover:border-neutral-300 hover:shadow-lg hover:-translate-y-1 transition-all duration-300'
      : '';

    const glowStyles = glowOnHover
      ? 'hover:shadow-card-hover'
      : '';

    return (
      <motion.div
        ref={ref}
        className={cn(
          variantStyles[variant],
          paddingStyles[padding],
          hoverStyles,
          glowStyles,
          className
        )}
        whileHover={hoverable ? { y: -4 } : undefined}
        transition={springs.gentle}
      >
        {children}
      </motion.div>
    );
  }
);

Card.displayName = 'Card';

// Card Header
export interface CardHeaderProps extends HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
}

export const CardHeader = forwardRef<HTMLDivElement, CardHeaderProps>(
  ({ className, children, ...props }, ref) => (
    <div
      ref={ref}
      className={cn('flex flex-col space-y-1.5', className)}
      {...props}
    >
      {children}
    </div>
  )
);

CardHeader.displayName = 'CardHeader';

// Card Title
export interface CardTitleProps extends HTMLAttributes<HTMLHeadingElement> {
  children: React.ReactNode;
}

export const CardTitle = forwardRef<HTMLHeadingElement, CardTitleProps>(
  ({ className, children, ...props }, ref) => (
    <h3
      ref={ref}
      className={cn('text-lg font-semibold text-neutral-900', className)}
      {...props}
    >
      {children}
    </h3>
  )
);

CardTitle.displayName = 'CardTitle';

// Card Description
export interface CardDescriptionProps extends HTMLAttributes<HTMLParagraphElement> {
  children: React.ReactNode;
}

export const CardDescription = forwardRef<HTMLParagraphElement, CardDescriptionProps>(
  ({ className, children, ...props }, ref) => (
    <p
      ref={ref}
      className={cn('text-sm text-neutral-500', className)}
      {...props}
    >
      {children}
    </p>
  )
);

CardDescription.displayName = 'CardDescription';

// Card Content
export interface CardContentProps extends HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
}

export const CardContent = forwardRef<HTMLDivElement, CardContentProps>(
  ({ className, children, ...props }, ref) => (
    <div ref={ref} className={cn('pt-4', className)} {...props}>
      {children}
    </div>
  )
);

CardContent.displayName = 'CardContent';

// Card Footer
export interface CardFooterProps extends HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
}

export const CardFooter = forwardRef<HTMLDivElement, CardFooterProps>(
  ({ className, children, ...props }, ref) => (
    <div
      ref={ref}
      className={cn('flex items-center pt-4', className)}
      {...props}
    >
      {children}
    </div>
  )
);

CardFooter.displayName = 'CardFooter';

export default Card;
