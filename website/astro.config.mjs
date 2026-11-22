// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { existsSync } from 'node:fs';

// docs/bindings.md is synced only when it exists in the repository.
const hasBindings = existsSync(new URL('../docs/bindings.md', import.meta.url));

export default defineConfig({
  site: 'https://kanywst.github.io',
  base: '/visado',
  trailingSlash: 'always',
  // Keep the whitespace between inline elements and text that ends a line.
  compressHTML: false,
  integrations: [
    starlight({
      title: 'visado',
      description:
        'An ext_authz service that verifies WIMSE workload credentials, asks an AuthZEN PDP and mints OAuth Transaction Tokens.',
      logo: {
        light: './src/assets/brand/lockup-light.svg',
        dark: './src/assets/brand/lockup-dark.svg',
        alt: 'visado',
        replacesTitle: true,
      },
      favicon: '/favicon.svg',
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/kanywst/visado' }],
      customCss: [
        '@fontsource-variable/instrument-sans/index.css',
        '@fontsource/ibm-plex-mono/400.css',
        '@fontsource/ibm-plex-mono/500.css',
        './src/styles/theme.css',
      ],
      components: {
        Footer: './src/components/Footer.astro',
        Hero: './src/components/Hero.astro',
        PageTitle: './src/components/PageTitle.astro',
        SocialIcons: './src/components/SocialIcons.astro',
      },
      credits: false,
      lastUpdated: false,
      sidebar: [
        { label: 'Overview', slug: 'overview' },
        { label: 'Getting started', slug: 'getting-started' },
        {
          label: 'Concepts',
          items: [
            { label: 'Scope', slug: 'concepts/scope' },
            { label: 'Design', slug: 'concepts/design' },
            ...(hasBindings ? [{ label: 'Bindings', slug: 'concepts/bindings' }] : []),
          ],
        },
        { label: 'Spec map', slug: 'spec-map' },
        {
          label: 'Security model',
          items: [
            { label: 'Threat model', slug: 'security/threats' },
            { label: 'Reporting a vulnerability', slug: 'security/policy' },
          ],
        },
        { label: 'Roadmap', slug: 'roadmap' },
        { label: 'Changelog', slug: 'changelog' },
        {
          label: 'Contributing',
          items: [
            { label: 'How to contribute', slug: 'contributing' },
            { label: 'Code of Conduct', slug: 'code-of-conduct' },
          ],
        },
        {
          label: 'Research notes',
          collapsed: true,
          items: [
            { label: 'Index', slug: 'research' },
            { label: 'Market', slug: 'research/market' },
            { label: 'Specs', slug: 'research/specs' },
            { label: 'Delegation chains', slug: 'research/delegation-chains' },
            { label: 'Landscape', slug: 'research/landscape' },
            { label: 'IdPs and SPIRE', slug: 'research/idp-and-spire' },
            { label: 'Observability, UI, launch', slug: 'research/observability-ui-launch' },
          ],
        },
      ],
    }),
  ],
});
