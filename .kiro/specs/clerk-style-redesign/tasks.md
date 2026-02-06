# Implementation Plan: Clerk-Style Redesign

## Overview

This implementation plan transforms Zalt.io's landing page and dashboard from the current cyberpunk/terminal theme to a modern, Apple-inspired design with cinematic animations. The implementation uses TypeScript, React, Next.js, Tailwind CSS, and Framer Motion.

## Tasks

- [x] 1. Set up design system foundation
  - [x] 1.1 Create clerk-theme.ts with all design tokens (colors, gradients, typography, spacing, shadows)
    - Define ClerkTheme interface with primary purple (#6C47FF), accent blue (#00D4FF), and neutral palette
    - Export theme object with all tokens
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_
  
  - [x] 1.2 Create motion.ts with Framer Motion presets
    - Implement cinematic animations (lockReveal, shieldMorph, particleExplosion)
    - Implement Steve Jobs style animations (dramaticReveal, textReveal, counterReveal)
    - Implement micro-interactions (magneticHover, card3DTilt, glowPulse)
    - Implement scroll animations (scrollReveal, staggerOnScroll, parallaxScroll)
    - _Requirements: 8.1, 8.2, 8.3, 8.4_
  
  - [x] 1.3 Update globals.css with new Tailwind configuration
    - Add custom colors from theme
    - Add gradient utilities
    - Add animation utilities
    - Configure Inter font family
    - _Requirements: 1.1, 1.2_
  
  - [x] 1.4 Update tailwind.config.js with theme extensions
    - Extend colors with primary, accent, neutral palettes
    - Add custom shadows (glow, cardHover)
    - Add custom animations
    - _Requirements: 1.1, 1.5_

- [x] 2. Implement core UI components
  - [x] 2.1 Create Button component with all variants
    - Implement primary, secondary, outline, ghost, gradient, glass variants
    - Add magnetic hover effect option
    - Add glow effect option
    - Add loading state with spinner
    - _Requirements: 10.1_
  
  - [x] 2.2 Write property test for Button variants
    - **Property 13: Button Variant Rendering**
    - **Validates: Requirements 10.1**
    - ✅ 15 tests passed (variant mapping, size scaling, loading/disabled states, accessibility)
  
  - [x] 2.3 Create Card component with 3D tilt effects
    - Implement default, elevated, gradient-border, glass, 3d-tilt variants
    - Add hover effects with Framer Motion
    - Add glow on hover option
    - _Requirements: 10.2_
  
  - [x] 2.4 Create GradientText component
    - Support multiple gradient presets (primary, secondary, rainbow, fire, ocean)
    - Add animated gradient option
    - Support different HTML elements (h1-h4, span, p)
    - _Requirements: 3.2_
  
  - [x] 2.5 Create Input component with focus and validation states
    - Implement focus ring with theme colors
    - Add error and success validation states
    - Add icon support (left/right)
    - _Requirements: 10.3_
  
  - [x] 2.6 Write property test for Input focus and validation
    - **Property 14: Input Focus and Validation States**
    - **Validates: Requirements 10.3**
    - ✅ 20 tests passed (size/state mapping, focus shadows, message priority, password toggle)
  
  - [x] 2.7 Create Badge component for status indicators
    - Implement color variants (success, warning, error, info, neutral)
    - Add dot indicator option
    - Add pulse animation option
    - _Requirements: 10.4_

- [x] 3. Checkpoint - Core UI components complete
  - ✅ All core UI tests pass (Button: 15, Input: 20)

- [x] 4. Implement advanced animation components
  - [x] 4.1 Create HeroLock 3D animation component
    - Implement SVG lock with 3D transforms
    - Add unlock sequence animation (shackle rise, glow pulse)
    - Add particle explosion on unlock
    - Add idle floating animation
    - _Requirements: 3.6, 8.1_
  
  - [x] 4.2 Create SecurityShield component
    - Implement shield SVG with morphing animation
    - Add threat level states (safe, monitoring, blocking, secured)
    - Add pulse and scan line effects
    - Add blocked count display
    - _Requirements: 4.2_
  
  - [x] 4.3 Create BiometricScanner component
    - Implement fingerprint, face, iris scanner types
    - Add scanning animation with progress
    - Add success/failed states with feedback
    - Add grid overlay option
    - _Requirements: 4.2_
  
  - [x] 4.4 Create EncryptionVisualizer component
    - Implement algorithm display (AES-256, RSA-4096, Argon2id)
    - Add data flow animation
    - Add encrypting/encrypted/decrypting states
    - _Requirements: 4.2_
  
  - [x] 4.5 Create ThreatMap component
    - Implement world map with threat connections
    - Add real-time threat animation
    - Add blocked/allowed indicators
    - Add severity color coding
    - _Requirements: 4.2_
  
  - [x] 4.6 Create StatsCounter component with count-up animation
    - Implement number animation from 0 to target
    - Support prefix/suffix
    - Add viewport trigger for animation start
    - _Requirements: 3.8_

- [x] 5. Implement landing page sections
  - [x] 5.1 Redesign Navbar component
    - White/transparent background with blur on scroll
    - Update navigation links styling
    - Add gradient hover effects
    - Implement responsive hamburger menu
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7_
  
  - [x] 5.2 Write property test for Navbar scroll behavior
    - **Property 3: Navbar Scroll Behavior**
    - **Validates: Requirements 2.1, 2.5**
    - ✅ 23 tests passed (scroll threshold, blur, dropdown, responsive)
  
  - [x] 5.3 Write property test for Navbar responsive behavior
    - **Property 4: Navbar Responsive Behavior**
    - **Validates: Requirements 2.6**
    - ✅ Included in Navbar.property.test.tsx
  
  - [x] 5.4 Redesign HeroSection component
    - Implement split-screen layout (content left, animation right)
    - Add gradient mesh background with animated blobs
    - Integrate HeroLock 3D animation
    - Add character-by-character headline reveal
    - Add gradient text for highlighted words
    - Add CTA buttons with magnetic hover
    - Add trust badges with stagger animation
    - Add StatsCounter component
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8_
  
  - [x] 5.5 Redesign FeaturesSection component
    - Implement grid layout with feature cards
    - Add gradient icon backgrounds
    - Add 3D tilt hover effects on cards
    - Add scroll-triggered stagger reveal
    - Display at least 6 features
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6_
  
  - [x] 5.6 Write property test for Features section content
    - **Property 5: Features Section Content Integrity**
    - **Validates: Requirements 4.2, 4.6**
    - ✅ 23 tests passed (feature count, structure, icons, gradients, stats)

- [x] 6. Checkpoint - Landing page sections in progress
  - ✅ All section tests pass (Navbar: 23, Features: 23)

- [x] 7. Continue landing page sections
  - [x] 7.1 Create SecurityTheater section
    - Integrate ThreatMap component
    - Integrate EncryptionVisualizer component
    - Integrate BiometricScanner component
    - Add section heading with gradient text
    - Add scroll-triggered animations
    - _Requirements: 4.1, 4.2_
  
  - [x] 7.2 Redesign CodeShowcase component
    - Implement tabbed interface for frameworks (React, Next.js, Node.js, Python)
    - Add syntax highlighting with soft color theme
    - Add typing effect animation
    - Add copy-to-clipboard functionality
    - Add line number display
    - Add highlight lines feature
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6_
  
  - [x] 7.3 Write property test for CodeShowcase tabs
    - **Property 6: Code Showcase Tab Functionality**
    - **Validates: Requirements 5.2, 5.5**
    - ✅ 32 tests passed (framework structure, code validity, tab switching, copy data, stats, accessibility)
  
  - [x] 7.4 Create SocialProof section
    - Display company logos with grayscale to color hover
    - Add stats with icons
    - Add scroll-triggered fade-in
    - _Requirements: 4.1_
  
  - [x] 7.5 Redesign PricingSection component
    - Implement pricing cards (Free, Pro, Enterprise)
    - Add gradient border for highlighted plan
    - Add monthly/annual toggle with discount indicator
    - Add feature list with checkmarks
    - Add sparkle effect for highlighted plan
    - Add hover scale and shadow effects
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6_
  
  - [x] 7.6 Write property test for Pricing section structure
    - **Property 7: Pricing Section Structure**
    - **Validates: Requirements 6.1, 6.2, 6.3, 6.6**
    - ✅ 29 tests passed (plan structure, features, toggle, discount)
  
  - [x] 7.7 Write property test for Pricing toggle
    - **Property 8: Pricing Toggle Functionality**
    - **Validates: Requirements 6.5**
    - ✅ Included in PricingSection.property.test.tsx
  
  - [x] 7.8 Redesign TestimonialsSection component
    - Implement carousel with auto-play
    - Add company logos and avatars
    - Add metrics display
    - Add smooth transition animations
    - _Requirements: 4.1_
  
  - [x] 7.9 Create FinalCTA section
    - Add compelling headline with gradient text
    - Add HeroLock animation (smaller version)
    - Add primary and secondary CTA buttons
    - Add background gradient effects
    - _Requirements: 3.4, 3.5_
  
  - [x] 7.10 Redesign Footer component
    - Dark background (#0F0F10) with white text
    - Add logo and company description
    - Organize links in columns (Product, Resources, Company, Legal)
    - Add social media icons with hover effects
    - Add newsletter signup with animation
    - Add compliance badges
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6_
  
  - [x] 7.11 Write property test for Footer links
    - **Property 9: Footer Link Organization**
    - **Validates: Requirements 7.3**
    - ✅ 29 tests passed (columns, links, social, compliance, newsletter)

- [x] 8. Checkpoint - Landing page complete
  - ✅ All tests pass: 314 total (21 test suites)
  - ✅ Build successful: 76 pages compiled

- [x] 9. Implement accessibility and motion preferences
  - [x] 9.1 Add reduced motion support
    - Detect prefers-reduced-motion media query
    - Create motion context provider
    - Disable/reduce animations when preference is set
    - _Requirements: 8.5_
  
  - [x] 9.2 Write property test for reduced motion
    - **Property 10: Reduced Motion Preference**
    - **Validates: Requirements 8.5**
    - ✅ 24 tests passed (variant structure, animation selection, opacity-only, no infinite)
  
  - [x] 9.3 Add focus management for accessibility
    - Ensure visible focus rings on all interactive elements
    - Implement keyboard navigation
    - Add skip links
    - _Requirements: 10.7_
  
  - [x] 9.4 Write property test for focus accessibility
    - **Property 15: Component Focus Accessibility**
    - **Validates: Requirements 10.7**
    - ✅ 37 tests passed (skip links, focusable selectors, focus trap, ARIA, keyboard nav)

- [x] 10. Redesign Dashboard
  - [x] 10.1 Create new Dashboard Sidebar component
    - Implement collapsible sidebar with icons and labels
    - Add active state indicators
    - Add hover effects
    - Implement responsive collapse for mobile
    - _Requirements: 9.1_
  
  - [x] 10.2 Create new Dashboard Header component
    - Add user profile dropdown
    - Add notification bell with badge
    - Add search input
    - Add breadcrumb navigation
    - _Requirements: 9.5_
  
  - [x] 10.3 Update Dashboard layout with new theme
    - Apply new color palette
    - Update card styles with soft shadows
    - Add smooth page transitions
    - _Requirements: 9.2, 9.3, 9.4_
    - ✅ Created DashboardCard, DashboardStatGrid, DashboardSection, DashboardTableCard components
    - ✅ Updated layout with ClerkSidebar, ClerkHeader, page transitions
    - ✅ Light theme with purple primary, soft shadows, gradient accents
  
  - [x] 10.4 Write property test for Dashboard theme consistency
    - **Property 11: Dashboard Theme Consistency**
    - **Validates: Requirements 9.3**
    - ✅ 45 tests passed (theme consistency, responsive layout)
  
  - [x] 10.5 Write property test for Dashboard responsive layout
    - **Property 12: Dashboard Responsive Layout**
    - **Validates: Requirements 9.6**
    - ✅ Included in ClerkDashboard.property.test.tsx

- [x] 11. Update main landing page
  - [x] 11.1 Update page.tsx with new section order
    - Navbar
    - HeroSection
    - SocialProof (company logos)
    - FeaturesSection
    - SecurityTheater
    - CodeShowcase
    - TestimonialsSection
    - PricingSection
    - FinalCTA
    - Footer
    - _Requirements: All landing page requirements_
  
  - [x] 11.2 Add page-level animations and transitions
    - Smooth scroll behavior
    - Section reveal animations
    - Parallax effects
    - _Requirements: 8.1, 8.6_
    - ✅ Scroll progress indicator, section reveal animations, parallax background

- [x] 12. Final checkpoint - All components complete
  - ✅ All tests pass: 513 total (27 test suites)
  - ✅ Build successful

- [x] 13. Theme configuration tests
  - [x] 13.1 Write property test for theme token consistency
    - **Property 1: Theme Configuration Consistency**
    - **Validates: Requirements 1.1, 1.3**
    - ✅ 37 tests passed (structure, colors, gradients, typography, spacing, shadows, CSS vars)
  
  - [x] 13.2 Write property test for theme mode switching
    - **Property 2: Theme Mode Switching**
    - **Validates: Requirements 1.6**
    - ✅ 24 tests passed (mode structure, color inversion, contrast compliance, accessibility)

## Notes

- All tasks including tests are required for comprehensive implementation
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties
- Unit tests validate specific examples and edge cases
- Implementation uses TypeScript, React, Next.js, Tailwind CSS, and Framer Motion
- All animations should respect prefers-reduced-motion preference
