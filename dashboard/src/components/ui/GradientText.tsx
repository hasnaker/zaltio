'use client';

import React, { forwardRef, HTMLAttributes } from 'react';
import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';

export type GradientPreset = 'primary' | 'secondary' | 'rainbow' | 'fire' | 'ocean' | 'sunset' | 'aurora';
export type TextElement = 'h1' | 'h2' | 'h3' | 'h4' | 'h5' | 'h6' | 'span' | 'p' | 'div';

export interface GradientTextProps extends HTMLAttributes<HTMLElement> {
  children: React.ReactNode;
  as?: TextElement;
  gradient?: GradientPreset;
  animate?: boolean;
  className?: string;
}

const gradientStyles: Record<GradientPreset, string> = {
  primary: 'from-primary to-accent',
  secondary: 'from-accent to-primary',
  rainbow: 'from-primary via-accent via-success via-warning to-error',
  fire: 'from-warning to-error',
  ocean: 'from-info to-accent',
  sunset: 'from-error via-warning to-primary',
  aurora: 'from-success via-accent to-primary',
};

const animatedGradientStyles: Record<GradientPreset, string> = {
  primary: 'bg-[linear-gradient(90deg,#6C47FF,#00D4FF,#6C47FF)] bg-[length:200%_100%]',
  secondary: 'bg-[linear-gradient(90deg,#00D4FF,#6C47FF,#00D4FF)] bg-[length:200%_100%]',
  rainbow: 'bg-[linear-gradient(90deg,#6C47FF,#00D4FF,#22C55E,#F59E0B,#EF4444,#6C47FF)] bg-[length:300%_100%]',
  fire: 'bg-[linear-gradient(90deg,#F59E0B,#EF4444,#F59E0B)] bg-[length:200%_100%]',
  ocean: 'bg-[linear-gradient(90deg,#3B82F6,#00D4FF,#3B82F6)] bg-[length:200%_100%]',
  sunset: 'bg-[linear-gradient(90deg,#EF4444,#F59E0B,#6C47FF,#EF4444)] bg-[length:300%_100%]',
  aurora: 'bg-[linear-gradient(90deg,#22C55E,#00D4FF,#6C47FF,#22C55E)] bg-[length:300%_100%]',
};

export const GradientText = forwardRef<HTMLElement, GradientTextProps>(
  (
    {
      children,
      as: Component = 'span',
      gradient = 'primary',
      animate = false,
      className,
      ...props
    },
    ref
  ) => {
    const baseStyles = 'bg-clip-text text-transparent';
    
    if (animate) {
      return (
        <motion.span
          ref={ref as React.Ref<HTMLSpanElement>}
          className={cn(
            baseStyles,
            animatedGradientStyles[gradient],
            className
          )}
          animate={{
            backgroundPosition: ['0% 50%', '100% 50%', '0% 50%'],
          }}
          transition={{
            duration: gradient === 'rainbow' || gradient === 'sunset' || gradient === 'aurora' ? 8 : 5,
            repeat: Infinity,
            ease: 'linear',
          }}
        >
          {children}
        </motion.span>
      );
    }

    // Non-animated version
    const Tag = Component;
    
    return (
      <Tag
        className={cn(
          baseStyles,
          'bg-gradient-to-r',
          gradientStyles[gradient],
          className
        )}
        {...props}
      >
        {children}
      </Tag>
    );
  }
);

GradientText.displayName = 'GradientText';

// Convenience components for headings
export const GradientH1 = forwardRef<HTMLHeadingElement, Omit<GradientTextProps, 'as'>>(
  (props, ref) => <GradientText ref={ref} as="h1" {...props} />
);
GradientH1.displayName = 'GradientH1';

export const GradientH2 = forwardRef<HTMLHeadingElement, Omit<GradientTextProps, 'as'>>(
  (props, ref) => <GradientText ref={ref} as="h2" {...props} />
);
GradientH2.displayName = 'GradientH2';

export const GradientH3 = forwardRef<HTMLHeadingElement, Omit<GradientTextProps, 'as'>>(
  (props, ref) => <GradientText ref={ref} as="h3" {...props} />
);
GradientH3.displayName = 'GradientH3';

export default GradientText;
