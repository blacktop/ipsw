// @ts-check
// `@type` JSDoc annotations allow editor autocompletion and type checking
// (when paired with `@ts-check`).
// There are various equivalent ways to declare your Docusaurus config.
// See: https://docusaurus.io/docs/api/docusaurus-config

const path = require("path");
import {themes as prismThemes} from "prism-react-renderer";
const lightCodeTheme = prismThemes.vsDark;
const darkCodeTheme = prismThemes.palenight;

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: "ipsw",
  tagline: "iOS/macOS Research Swiss Army Knife",
  url: "https://blacktop.github.io",
  baseUrl: "/ipsw",
  onBrokenLinks: "throw",
  onBrokenMarkdownLinks: "warn",
  favicon: "img/logo/ipsw.ico",

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: "blacktop", // Usually your GitHub org/user name.
  projectName: "ipsw", // Usually your repo name.

  // Even if you don't use internalization, you can use this field to set useful
  // metadata like html lang. For example, if your site is Chinese, you may want
  // to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: "en",
    locales: ["en"],
  },
  markdown: {
    mermaid: true,
  },
  themes: ["@docusaurus/theme-mermaid"],
  presets: [
    [
      "classic",
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: require.resolve("./sidebars.js"),
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl: "https://github.com/blacktop/ipsw/tree/master/www/",
        },
        gtag: {
          trackingID: "G-6PLDXGZBEK",
          anonymizeIP: false,
        },
        // blog: {
        //   showReadingTime: true,
        //   // Please change this to your repo.
        //   // Remove this to remove the "edit this page" links.
        //   editUrl:
        //     "https://github.com/facebook/docusaurus/tree/main/packages/create-docusaurus/templates/shared/",
        // },
        theme: {
          customCss: [
            require.resolve("./src/css/custom.css"),
            require.resolve("prism-themes/themes/prism-nord.css"),
          ],
        },
      }),
    ],
    [
      "redocusaurus",
      /** @type {import('redocusaurus').PresetEntry} */
      ({
        // Plugin Options for loading OpenAPI files
        specs: [
          {
            spec: "api/swagger.json",
            route: "/api",
            layout: {
              title: "ipsw API",
              noFooter: true,
            },
          },
        ],
        // Theme Options for modifying how redoc renders them
        theme: {
          // Change with your site colors
          primaryColor: "#503B9F",
        },
      }),
    ],
  ],
  // plugins: [require.resolve("@cmfcmf/docusaurus-search-local")],
  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      docs: {
        sidebar: {
          hideable: true,
          autoCollapseCategories: true,
        },
      },
      colorMode: {
        defaultMode: "dark",
        disableSwitch: false,
        respectPrefersColorScheme: true,
      },
      announcementBar: {
        content: `⭐️ If you like ipsw, give it a star on <a target="_blank" rel="noopener noreferrer" href="https://github.com/blacktop/ipsw">GitHub</a>`,
        backgroundColor: "#2b3137",
        textColor: "#ffffff", //
      },
      prism: {
        theme: lightCodeTheme,
        darkTheme: darkCodeTheme,
        themes: [path.resolve(__dirname, "/src/themes/prism-nord")],
        additionalLanguages: ["armasm", "llvm", "bash"],
      },
      // algolia: {
      //   appId: "XN7OVST81R",
      //   apiKey: "493729d49a9639b14fe433a033ef5992",
      //   indexName: "ipsw",
      // },
      navbar: {
        hideOnScroll: true,
        title: "ipsw",
        logo: {
          alt: "ipsw logo",
          src: "img/logo/ipsw.svg",
          // srcDark: "img/icon-dark.svg",
          width: 32,
          height: 32,
        },
        items: [
          {
            type: "doc",
            position: "left",
            docId: "introduction",
            label: "Docs",
          },
          {
            type: "docSidebar",
            position: "left",
            sidebarId: "cli",
            label: "CLI",
          },
          {
            label: "API",
            to: "/api",
            position: "left",
            sidebarId: "api",
          },
          // Right
          {
            href: "https://github.com/blacktop/ipsw",
            position: "right",
            className: "header-icon-link header-github-link",
          },
          {
            href: "https://twitter.com/blacktop__",
            position: "right",
            className: "header-icon-link header-twitter-link",
          },
          {
            href: "https://mastodon.social/@blacktop",
            position: "right",
            className: "header-icon-link header-mastodon-link",
          },
        ],
      },
      footer: {
        style: "dark",
        links: [
          {
            title: "Docs",
            items: [
              {
                label: "Guides",
                to: "/docs/category/guides",
              },
              {
                label: "CLI",
                to: "/docs/cli/ipsw",
              },
            ],
          },
          {
            title: "Community",
            items: [
              {
                label: "Twitter",
                href: "https://twitter.com/blacktop__",
              },
              {
                label: "Mastodon",
                href: "https://mastodon.social/@blacktop",
              },
            ],
          },
          {
            title: "More",
            items: [
              {
                label: "Blog",
                href: "https://blog.blacktop.io",
              },
              {
                label: "GitHub",
                href: "https://github.com/blacktop/ipsw",
              },
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} ipsw. Built with Go and ❤️`,
      },
    }),
};

module.exports = config;
