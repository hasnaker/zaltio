import { MetadataRoute } from 'next';

export default function sitemap(): MetadataRoute.Sitemap {
  const baseUrl = 'https://zalt.io';
  const currentDate = new Date().toISOString();

  // Static pages
  const staticPages = [
    { url: '', priority: 1.0, changeFrequency: 'weekly' as const },
    { url: '/docs', priority: 0.9, changeFrequency: 'weekly' as const },
    { url: '/docs/quickstart', priority: 0.9, changeFrequency: 'monthly' as const },
    { url: '/docs/sdk', priority: 0.8, changeFrequency: 'monthly' as const },
    { url: '/docs/playground', priority: 0.7, changeFrequency: 'monthly' as const },
    { url: '/docs/compare', priority: 0.8, changeFrequency: 'monthly' as const },
    { url: '/compare/clerk', priority: 0.8, changeFrequency: 'monthly' as const },
    { url: '/compare/auth0', priority: 0.8, changeFrequency: 'monthly' as const },
    { url: '/blog', priority: 0.8, changeFrequency: 'daily' as const },
    { url: '/changelog', priority: 0.7, changeFrequency: 'weekly' as const },
    { url: '/contact', priority: 0.6, changeFrequency: 'monthly' as const },
    { url: '/privacy', priority: 0.4, changeFrequency: 'yearly' as const },
    { url: '/terms', priority: 0.4, changeFrequency: 'yearly' as const },
    { url: '/security', priority: 0.5, changeFrequency: 'yearly' as const },
    { url: '/dpa', priority: 0.4, changeFrequency: 'yearly' as const },
    { url: '/cookies', priority: 0.3, changeFrequency: 'yearly' as const },
    { url: '/signup', priority: 0.9, changeFrequency: 'monthly' as const },
    { url: '/login', priority: 0.8, changeFrequency: 'monthly' as const },
  ];

  return staticPages.map((page) => ({
    url: `${baseUrl}${page.url}`,
    lastModified: currentDate,
    changeFrequency: page.changeFrequency,
    priority: page.priority,
  }));
}
