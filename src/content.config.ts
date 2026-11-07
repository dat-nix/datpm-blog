import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';

const blog = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/blog' }),
  schema: z.object({
    title: z.string(),
    date: z.date(),
    category: z.string(),
    ctf: z.string().optional(),
    tags: z.array(z.string()).default([]),
    excerpt: z.string().default('A technical writeup from my CTF notes.'),
    draft: z.boolean().default(false),
  }),
});

export const collections = { blog };
