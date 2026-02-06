'use client';

import Link from 'next/link';
import { Calendar, Clock, User } from 'lucide-react';

export interface BlogPost {
  slug: string;
  title: string;
  excerpt: string;
  author: string;
  date: string;
  readingTime: number;
  category: string;
  tags: string[];
  featured?: boolean;
}

interface BlogCardProps {
  post: BlogPost;
  featured?: boolean;
}

export function BlogCard({ post, featured = false }: BlogCardProps) {
  const categoryColors: Record<string, string> = {
    'Engineering': 'bg-blue-500/20 text-blue-400',
    'Security': 'bg-red-500/20 text-red-400',
    'Product': 'bg-emerald-500/20 text-emerald-400',
    'Company': 'bg-purple-500/20 text-purple-400',
    'Tutorial': 'bg-amber-500/20 text-amber-400',
  };

  const colorClass = categoryColors[post.category] || 'bg-neutral-500/20 text-neutral-400';

  if (featured) {
    return (
      <Link href={`/blog/${post.slug}`} className="block group">
        <article className="bg-gradient-to-br from-emerald-500/10 to-emerald-500/5 border border-emerald-500/20 rounded-lg p-6 hover:border-emerald-500/40 transition-colors">
          <div className="flex items-center gap-2 mb-3">
            <span className={`px-2 py-1 rounded text-xs font-medium ${colorClass}`}>
              {post.category}
            </span>
            <span className="text-xs text-emerald-400 font-medium">Featured</span>
          </div>
          <h2 className="text-2xl font-bold text-white mb-3 group-hover:text-emerald-400 transition-colors">
            {post.title}
          </h2>
          <p className="text-neutral-400 mb-4 line-clamp-2">{post.excerpt}</p>
          <div className="flex items-center gap-4 text-sm text-neutral-500">
            <span className="flex items-center gap-1">
              <User size={14} />
              {post.author}
            </span>
            <span className="flex items-center gap-1">
              <Calendar size={14} />
              {post.date}
            </span>
            <span className="flex items-center gap-1">
              <Clock size={14} />
              {post.readingTime} min read
            </span>
          </div>
        </article>
      </Link>
    );
  }

  return (
    <Link href={`/blog/${post.slug}`} className="block group">
      <article className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-5 hover:border-emerald-500/30 transition-colors h-full">
        <div className="flex items-center gap-2 mb-3">
          <span className={`px-2 py-1 rounded text-xs font-medium ${colorClass}`}>
            {post.category}
          </span>
        </div>
        <h3 className="text-lg font-semibold text-white mb-2 group-hover:text-emerald-400 transition-colors line-clamp-2">
          {post.title}
        </h3>
        <p className="text-sm text-neutral-400 mb-4 line-clamp-2">{post.excerpt}</p>
        <div className="flex items-center gap-3 text-xs text-neutral-500">
          <span className="flex items-center gap-1">
            <Calendar size={12} />
            {post.date}
          </span>
          <span className="flex items-center gap-1">
            <Clock size={12} />
            {post.readingTime} min
          </span>
        </div>
      </article>
    </Link>
  );
}

export default BlogCard;
