'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import { Search, Tag, X } from 'lucide-react';
import { BlogCard, BlogPost } from './BlogCard';

interface BlogLayoutProps {
  posts: BlogPost[];
  categories: string[];
}

export function BlogLayout({ posts, categories }: BlogLayoutProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [selectedTags, setSelectedTags] = useState<string[]>([]);

  // Get all unique tags
  const allTags = Array.from(new Set(posts.flatMap(p => p.tags)));

  // Filter posts
  const filteredPosts = posts.filter(post => {
    const matchesSearch = searchQuery === '' || 
      post.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      post.excerpt.toLowerCase().includes(searchQuery.toLowerCase());
    
    const matchesCategory = !selectedCategory || post.category === selectedCategory;
    
    const matchesTags = selectedTags.length === 0 || 
      selectedTags.some(tag => post.tags.includes(tag));
    
    return matchesSearch && matchesCategory && matchesTags;
  });

  const featuredPost = filteredPosts.find(p => p.featured);
  const regularPosts = filteredPosts.filter(p => !p.featured);

  const toggleTag = (tag: string) => {
    setSelectedTags(prev => 
      prev.includes(tag) 
        ? prev.filter(t => t !== tag)
        : [...prev, tag]
    );
  };

  const clearFilters = () => {
    setSearchQuery('');
    setSelectedCategory(null);
    setSelectedTags([]);
  };

  const hasActiveFilters = searchQuery || selectedCategory || selectedTags.length > 0;

  return (
    <div className="min-h-screen bg-neutral-950">
      <div className="max-w-6xl mx-auto px-4 py-16">
        {/* Header */}
        <motion.div 
          initial={{ opacity: 0, y: 20 }} 
          animate={{ opacity: 1, y: 0 }}
          className="text-center mb-12"
        >
          <h1 className="font-outfit text-4xl md:text-5xl font-bold text-white mb-4">
            Zalt Blog
          </h1>
          <p className="text-neutral-400 max-w-2xl mx-auto">
            Engineering insights, security best practices, and product updates from the Zalt team.
          </p>
        </motion.div>

        {/* Search and Filters */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="mb-8 space-y-4"
        >
          {/* Search */}
          <div className="relative">
            <Search size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-neutral-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search articles..."
              className="w-full pl-12 pr-4 py-3 bg-neutral-900 border border-emerald-500/10 rounded-lg text-white placeholder-neutral-500 focus:border-emerald-500/30 focus:outline-none"
            />
          </div>

          {/* Categories */}
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => setSelectedCategory(null)}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                !selectedCategory 
                  ? 'bg-emerald-500 text-neutral-950' 
                  : 'bg-neutral-800 text-neutral-400 hover:bg-neutral-700'
              }`}
            >
              All
            </button>
            {categories.map(category => (
              <button
                key={category}
                onClick={() => setSelectedCategory(category)}
                className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                  selectedCategory === category 
                    ? 'bg-emerald-500 text-neutral-950' 
                    : 'bg-neutral-800 text-neutral-400 hover:bg-neutral-700'
                }`}
              >
                {category}
              </button>
            ))}
          </div>

          {/* Tags */}
          <div className="flex flex-wrap items-center gap-2">
            <Tag size={14} className="text-neutral-500" />
            {allTags.slice(0, 10).map(tag => (
              <button
                key={tag}
                onClick={() => toggleTag(tag)}
                className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
                  selectedTags.includes(tag)
                    ? 'bg-emerald-500/20 text-emerald-400'
                    : 'bg-neutral-800 text-neutral-500 hover:text-neutral-300'
                }`}
              >
                {tag}
              </button>
            ))}
          </div>

          {/* Clear Filters */}
          {hasActiveFilters && (
            <button
              onClick={clearFilters}
              className="flex items-center gap-1 text-sm text-neutral-500 hover:text-white"
            >
              <X size={14} />
              Clear filters
            </button>
          )}
        </motion.div>

        {/* Featured Post */}
        {featuredPost && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="mb-8"
          >
            <BlogCard post={featuredPost} featured />
          </motion.div>
        )}

        {/* Posts Grid */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="grid md:grid-cols-2 lg:grid-cols-3 gap-6"
        >
          {regularPosts.map((post, i) => (
            <motion.div
              key={post.slug}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 + i * 0.05 }}
            >
              <BlogCard post={post} />
            </motion.div>
          ))}
        </motion.div>

        {/* No Results */}
        {filteredPosts.length === 0 && (
          <div className="text-center py-12">
            <p className="text-neutral-500">No articles found matching your criteria.</p>
            <button
              onClick={clearFilters}
              className="mt-4 text-emerald-400 hover:text-emerald-300"
            >
              Clear filters
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

export default BlogLayout;
