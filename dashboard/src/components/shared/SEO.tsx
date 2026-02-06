'use client';

import Head from 'next/head';

interface SEOProps {
  title: string;
  description: string;
  canonical?: string;
  ogImage?: string;
  ogType?: 'website' | 'article';
  twitterCard?: 'summary' | 'summary_large_image';
  noIndex?: boolean;
  article?: {
    publishedTime?: string;
    modifiedTime?: string;
    author?: string;
    section?: string;
    tags?: string[];
  };
  jsonLd?: Record<string, unknown>;
}

export function SEO({
  title,
  description,
  canonical,
  ogImage = 'https://zalt.io/og-image.png',
  ogType = 'website',
  twitterCard = 'summary_large_image',
  noIndex = false,
  article,
  jsonLd,
}: SEOProps) {
  const fullTitle = title.includes('Zalt') ? title : `${title} | Zalt.io`;
  const siteUrl = 'https://zalt.io';
  const canonicalUrl = canonical ? `${siteUrl}${canonical}` : undefined;

  // Default JSON-LD for organization
  const defaultJsonLd = {
    '@context': 'https://schema.org',
    '@type': 'Organization',
    name: 'Zalt.io',
    url: siteUrl,
    logo: `${siteUrl}/zalt-logo.svg`,
    description: 'Enterprise-grade authentication as a service',
    sameAs: [
      'https://twitter.com/zaltio',
      'https://github.com/zaltio',
    ],
  };

  const structuredData = jsonLd || defaultJsonLd;

  return (
    <Head>
      {/* Basic Meta Tags */}
      <title>{fullTitle}</title>
      <meta name="description" content={description} />
      {canonicalUrl && <link rel="canonical" href={canonicalUrl} />}
      {noIndex && <meta name="robots" content="noindex, nofollow" />}

      {/* Open Graph */}
      <meta property="og:title" content={fullTitle} />
      <meta property="og:description" content={description} />
      <meta property="og:type" content={ogType} />
      <meta property="og:image" content={ogImage} />
      <meta property="og:site_name" content="Zalt.io" />
      {canonicalUrl && <meta property="og:url" content={canonicalUrl} />}

      {/* Article specific OG tags */}
      {article && (
        <>
          {article.publishedTime && (
            <meta property="article:published_time" content={article.publishedTime} />
          )}
          {article.modifiedTime && (
            <meta property="article:modified_time" content={article.modifiedTime} />
          )}
          {article.author && <meta property="article:author" content={article.author} />}
          {article.section && <meta property="article:section" content={article.section} />}
          {article.tags?.map((tag, i) => (
            <meta key={i} property="article:tag" content={tag} />
          ))}
        </>
      )}

      {/* Twitter Card */}
      <meta name="twitter:card" content={twitterCard} />
      <meta name="twitter:site" content="@zaltio" />
      <meta name="twitter:title" content={fullTitle} />
      <meta name="twitter:description" content={description} />
      <meta name="twitter:image" content={ogImage} />

      {/* JSON-LD Structured Data */}
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData) }}
      />
    </Head>
  );
}

// Helper function to generate meta tags (for use in metadata export)
export function generateMetadata({
  title,
  description,
  canonical,
  ogImage = 'https://zalt.io/og-image.png',
}: {
  title: string;
  description: string;
  canonical?: string;
  ogImage?: string;
}) {
  const fullTitle = title.includes('Zalt') ? title : `${title} | Zalt.io`;
  
  return {
    title: fullTitle,
    description,
    openGraph: {
      title: fullTitle,
      description,
      url: canonical ? `https://zalt.io${canonical}` : undefined,
      siteName: 'Zalt.io',
      images: [{ url: ogImage }],
      type: 'website',
    },
    twitter: {
      card: 'summary_large_image',
      title: fullTitle,
      description,
      images: [ogImage],
    },
  };
}

export default SEO;
