// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// Replace with the real repository URL before publishing (task W-03).
const REPO_URL = 'https://github.com/mrAbhishek1105/dpg';

export default defineConfig({
  site: 'https://example.invalid',
  integrations: [
    starlight({
      title: 'DPG',
      description:
        'DPG (Data Protection Gateway): a local-first open-source layer that masks secrets for AI coding agents and restores them only in your local files.',
      logo: { src: './src/assets/logo.svg', replacesTitle: false },
      social: [{ icon: 'github', label: 'GitHub', href: REPO_URL }],
      editLink: { baseUrl: `${REPO_URL}/edit/main/website/` },
      customCss: ['./src/styles/custom.css'],
      lastUpdated: false,
      sidebar: [
        {
          label: 'Project',
          items: [
            { label: 'Overview', link: '/' },
            { label: 'The problem', slug: 'problem' },
            { label: 'How DPG works', slug: 'how-it-works' },
            { label: 'Architecture', slug: 'architecture' },
            { label: 'Security & privacy', slug: 'security' },
            { label: 'Project status', slug: 'status' },
            { label: 'Roadmap', slug: 'roadmap' },
            { label: 'Community', slug: 'community' },
          ],
        },
        {
          label: 'Getting started',
          items: [
            { slug: 'docs/introduction' },
            { slug: 'docs/installation' },
            { slug: 'docs/quick-start' },
          ],
        },
        {
          label: 'Guides',
          items: [
            { slug: 'docs/configuration' },
            { slug: 'docs/claude-code' },
            { slug: 'docs/proxy' },
            { slug: 'docs/troubleshooting' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { slug: 'docs/cli' },
            { slug: 'docs/detection-rules' },
            { slug: 'docs/policy' },
            { slug: 'docs/placeholders' },
            { slug: 'docs/restoration' },
            { slug: 'docs/faq' },
          ],
        },
        {
          label: 'Contributing',
          items: [{ slug: 'docs/development' }, { slug: 'docs/contributing' }],
        },
      ],
    }),
  ],
});
