/**
 * Zalt.io SEO Utility Library
 * 
 * Provides meta tag generation, Open Graph, Twitter Cards,
 * and JSON-LD structured data helpers.
 */

import { Metadata } from 'next';

// Site configuration
const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL || 'https://zalt.io';
const SITE_NAME = 'Zalt.io';
const DEFAULT_DESCRIPTION = 'Enterprise-grade authentication and user management. The premium Clerk alternative for modern applications.';
const DEFAULT_IMAGE = `${SITE_URL}/og-image.png`;
const TWITTER_HANDLE = '@zaltio';

// Type definitions
export interface SEOProps {
  title: string;
  description?: string;
  canonical?: string;
  noIndex?: boolean;
  openGraph?: OpenGraphData;
  twitter?: TwitterCardData;
  jsonLd?: StructuredData[];
}

export interface OpenGraphData {
  type?: 'website' | 'article' | 'product';
  title?: string;
  description?: string;
  image?: string;
  url?: string;
  siteName?: string;
  locale?: string;
  article?: {
    publishedTime?: string;
    modifiedTime?: string;
    author?: string;
    section?: string;
    tags?: string[];
  };
}

export interface TwitterCardData {
  card?: 'summary' | 'summary_large_image' | 'app' | 'player';
  site?: string;
  creator?: string;
  title?: string;
  description?: string;
  image?: string;
}

export interface StructuredData {
  '@context': string;
  '@type': string;
  [key: string]: unknown;
}

/**
 * Generate full page title with site name
 */
export function generateTitle(title: string, includeSiteName = true): string {
  if (!includeSiteName) return title;
  return `${title} | ${SITE_NAME}`;
}

/**
 * Generate canonical URL
 */
export function generateCanonicalUrl(path: string): string {
  const cleanPath = path.startsWith('/') ? path : `/${path}`;
  return `${SITE_URL}${cleanPath}`;
}

/**
 * Generate Open Graph meta tags
 */
export function generateOpenGraph(props: SEOProps): OpenGraphData {
  const og = props.openGraph || {};
  
  return {
    type: og.type || 'website',
    title: og.title || props.title,
    description: og.description || props.description || DEFAULT_DESCRIPTION,
    image: og.image || DEFAULT_IMAGE,
    url: og.url || props.canonical || SITE_URL,
    siteName: og.siteName || SITE_NAME,
    locale: og.locale || 'en_US',
    ...og,
  };
}

/**
 * Generate Twitter Card meta tags
 */
export function generateTwitterCard(props: SEOProps): TwitterCardData {
  const twitter = props.twitter || {};
  
  return {
    card: twitter.card || 'summary_large_image',
    site: twitter.site || TWITTER_HANDLE,
    creator: twitter.creator || TWITTER_HANDLE,
    title: twitter.title || props.title,
    description: twitter.description || props.description || DEFAULT_DESCRIPTION,
    image: twitter.image || DEFAULT_IMAGE,
  };
}

/**
 * Generate Organization structured data (JSON-LD)
 */
export function generateOrganizationSchema(): StructuredData {
  return {
    '@context': 'https://schema.org',
    '@type': 'Organization',
    name: SITE_NAME,
    url: SITE_URL,
    logo: `${SITE_URL}/logo.png`,
    description: DEFAULT_DESCRIPTION,
    sameAs: [
      'https://twitter.com/zaltio',
      'https://github.com/zalt-io',
      'https://linkedin.com/company/zalt-io',
    ],
    contactPoint: {
      '@type': 'ContactPoint',
      contactType: 'customer service',
      email: 'support@zalt.io',
      url: `${SITE_URL}/contact`,
    },
  };
}

/**
 * Generate SoftwareApplication structured data (JSON-LD)
 */
export function generateSoftwareSchema(): StructuredData {
  return {
    '@context': 'https://schema.org',
    '@type': 'SoftwareApplication',
    name: SITE_NAME,
    applicationCategory: 'DeveloperApplication',
    operatingSystem: 'Web',
    description: DEFAULT_DESCRIPTION,
    url: SITE_URL,
    offers: {
      '@type': 'Offer',
      price: '0',
      priceCurrency: 'USD',
      description: 'Free tier available',
    },
    aggregateRating: {
      '@type': 'AggregateRating',
      ratingValue: '4.9',
      ratingCount: '150',
      bestRating: '5',
      worstRating: '1',
    },
  };
}

/**
 * Generate WebPage structured data (JSON-LD)
 */
export function generateWebPageSchema(props: {
  title: string;
  description: string;
  url: string;
  datePublished?: string;
  dateModified?: string;
}): StructuredData {
  return {
    '@context': 'https://schema.org',
    '@type': 'WebPage',
    name: props.title,
    description: props.description,
    url: props.url,
    isPartOf: {
      '@type': 'WebSite',
      name: SITE_NAME,
      url: SITE_URL,
    },
    ...(props.datePublished && { datePublished: props.datePublished }),
    ...(props.dateModified && { dateModified: props.dateModified }),
  };
}

/**
 * Generate Article structured data (JSON-LD)
 */
export function generateArticleSchema(props: {
  title: string;
  description: string;
  url: string;
  image: string;
  datePublished: string;
  dateModified?: string;
  author: {
    name: string;
    url?: string;
  };
}): StructuredData {
  return {
    '@context': 'https://schema.org',
    '@type': 'Article',
    headline: props.title,
    description: props.description,
    url: props.url,
    image: props.image,
    datePublished: props.datePublished,
    dateModified: props.dateModified || props.datePublished,
    author: {
      '@type': 'Person',
      name: props.author.name,
      ...(props.author.url && { url: props.author.url }),
    },
    publisher: {
      '@type': 'Organization',
      name: SITE_NAME,
      logo: {
        '@type': 'ImageObject',
        url: `${SITE_URL}/logo.png`,
      },
    },
  };
}

/**
 * Generate FAQ structured data (JSON-LD)
 */
export function generateFAQSchema(
  faqs: Array<{ question: string; answer: string }>
): StructuredData {
  return {
    '@context': 'https://schema.org',
    '@type': 'FAQPage',
    mainEntity: faqs.map((faq) => ({
      '@type': 'Question',
      name: faq.question,
      acceptedAnswer: {
        '@type': 'Answer',
        text: faq.answer,
      },
    })),
  };
}

/**
 * Generate Product structured data for pricing pages (JSON-LD)
 */
export function generateProductSchema(props: {
  name: string;
  description: string;
  price: number | string;
  priceCurrency?: string;
}): StructuredData {
  return {
    '@context': 'https://schema.org',
    '@type': 'Product',
    name: props.name,
    description: props.description,
    brand: {
      '@type': 'Brand',
      name: SITE_NAME,
    },
    offers: {
      '@type': 'Offer',
      price: props.price,
      priceCurrency: props.priceCurrency || 'USD',
      availability: 'https://schema.org/InStock',
    },
  };
}

/**
 * Generate BreadcrumbList structured data (JSON-LD)
 */
export function generateBreadcrumbSchema(
  items: Array<{ name: string; url: string }>
): StructuredData {
  return {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: items.map((item, index) => ({
      '@type': 'ListItem',
      position: index + 1,
      name: item.name,
      item: item.url.startsWith('http') ? item.url : `${SITE_URL}${item.url}`,
    })),
  };
}

/**
 * Generate complete Next.js Metadata object
 */
export function generateMetadata(props: SEOProps): Metadata {
  const title = generateTitle(props.title);
  const description = props.description || DEFAULT_DESCRIPTION;
  const canonical = props.canonical ? generateCanonicalUrl(props.canonical) : undefined;
  const og = generateOpenGraph(props);
  const twitter = generateTwitterCard(props);

  return {
    title,
    description,
    ...(canonical && { alternates: { canonical } }),
    ...(props.noIndex && { robots: { index: false, follow: false } }),
    openGraph: {
      type: og.type as 'website' | 'article',
      title: og.title,
      description: og.description,
      url: og.url,
      siteName: og.siteName,
      locale: og.locale,
      images: og.image ? [{ url: og.image, width: 1200, height: 630 }] : undefined,
      ...(og.article && {
        publishedTime: og.article.publishedTime,
        modifiedTime: og.article.modifiedTime,
        authors: og.article.author ? [og.article.author] : undefined,
        section: og.article.section,
        tags: og.article.tags,
      }),
    },
    twitter: {
      card: twitter.card,
      site: twitter.site,
      creator: twitter.creator,
      title: twitter.title,
      description: twitter.description,
      images: twitter.image ? [twitter.image] : undefined,
    },
  };
}

/**
 * Generate JSON-LD script tag content
 */
export function generateJsonLd(data: StructuredData | StructuredData[]): string {
  const schemas = Array.isArray(data) ? data : [data];
  return JSON.stringify(schemas.length === 1 ? schemas[0] : schemas);
}

/**
 * Default page SEO configurations
 */
export const defaultPageSEO: Record<string, SEOProps> = {
  home: {
    title: 'Enterprise Authentication & User Management',
    description: 'Zalt.io provides enterprise-grade authentication, MFA, SSO, and user management. The premium Clerk alternative for modern applications.',
    canonical: '/',
  },
  pricing: {
    title: 'Pricing',
    description: 'Simple, transparent pricing for authentication and user management. Free tier available. Scale as you grow.',
    canonical: '/pricing',
  },
  docs: {
    title: 'Documentation',
    description: 'Comprehensive documentation for Zalt.io. Quickstart guides, API reference, SDK documentation, and more.',
    canonical: '/docs',
  },
  blog: {
    title: 'Blog',
    description: 'Technical articles, product updates, and best practices for authentication and security.',
    canonical: '/blog',
  },
  contact: {
    title: 'Contact Us',
    description: 'Get in touch with the Zalt.io team. We\'re here to help with your authentication needs.',
    canonical: '/contact',
  },
};

// Export all functions
export const seo = {
  generateTitle,
  generateCanonicalUrl,
  generateOpenGraph,
  generateTwitterCard,
  generateOrganizationSchema,
  generateSoftwareSchema,
  generateWebPageSchema,
  generateArticleSchema,
  generateFAQSchema,
  generateProductSchema,
  generateBreadcrumbSchema,
  generateMetadata,
  generateJsonLd,
  defaultPageSEO,
};

export default seo;
