// @ts-check
// Note: type annotations allow type checking and IDEs autocompletion

const {themes} = require('prism-react-renderer');
const lightTheme = themes.github;
const darkTheme = themes.dracula;

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Arti',
  tagline: '',
  //favicon: '',

  // Set the production url of your site here
  url: 'https://tpo.pages.torproject.net',

  // Set the /<baseUrl>/ pathname under which your site is served
  baseUrl: '/',
  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',

  // Even if you don't use internalization, you can use this field to set useful
  // metadata like html lang. For example, if your site is Chinese, you may want
  // to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  markdown: {
    mermaid: true,
  },
  themes: ['@docusaurus/theme-mermaid'],

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          routeBasePath: '/',
          sidebarPath: require.resolve('./sidebars.js'),
          breadcrumbs: true,
          showLastUpdateTime: true,
        },
        blog:false, // Remove this to use the blog.
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      // Replace with your project's social card
      // image: 'img/docusaurus-social-card.jpg',
      navbar: {
        title: '',
        logo: {
          alt: '',
          src: 'https://tpo.pages.torproject.net/core/arti/old/arti_logo.png',
        },
        items: [
          {
            href: '/about',
            label: 'About Arti',
            position: 'left',
          },
          {
            href: 'https://blog.torproject.org/',
            label: 'Blog',
            position: 'left',
          },
          {
            href: '/FAQs',
            label: 'FAQs',
            position: 'left',
          },
          {
            href: 'https://gitlab.torproject.org/tpo/core/arti',
            label: 'GitLab',
            position: 'right',
          },
        ],
      },
      footer: {
        style: 'light',
        copyright: `Copyright © ${new Date().getFullYear()} Arti, TorProject.org.`,
        //copyright: 'Trademark, copyright notices, and rules for use by third parties can be found in our https://www.torproject.org/about/trademark/.'
      },
 
      
      prism: {
        theme: lightTheme,
        darkTheme: darkTheme,
      },
    }),
};

module.exports = config;
