// @ts-nocheck
// Note: type annotations allow type checking and IDEs autocompletion

const path = require("path");
const lightCodeTheme = require("prism-react-renderer/themes/vsDark");
const darkCodeTheme = require("prism-react-renderer/themes/palenight");

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: "ipsw",
  tagline: "iOS/macOS Research Swiss Army Knife",
  url: "https://blacktop.github.io",
  baseUrl: "/",
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
  ],

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
        additionalLanguages: ["armasm"],
      },
      zoom: {
        selector: ".markdown img:not(.not-zoom)",
        background: {
          light: "rgb(255, 255, 255)",
          dark: "rgb(50, 50, 50)",
        },
        // medium-zoom configuration options
        // Refer to https://github.com/francoischalifour/medium-zoom#options
        config: {},
      },
      // algolia: {
      //   appId: 'X1Z85QJPUV',
      //   apiKey: 'bf7211c161e8205da2f933a02534105a',
      //   indexName: 'docusaurus-2',
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
          // Right
          // {
          //   type: "localeDropdown",
          //   position: "right",
          //   dropdownItemsAfter: [
          //     {
          //       type: "html",
          //       value: '<hr style="margin: 0.3rem 0;">',
          //     },
          //     {
          //       href: "https://github.com/facebook/docusaurus/issues/3526",
          //       label: "Help Us Translate",
          //     },
          //   ],
          // },
          // {
          //   type: "docsVersionDropdown",
          //   position: "right",
          //   dropdownActiveClassDisabled: true,
          // },
          {
            href: "https://github.com/blacktop/ipsw",
            position: "right",
            className: "header-icon-link header-github-link",
          },
          {
            href: "https://discord.gg/xx2y9yrcgs",
            position: "right",
            className: "header-icon-link header-discord-link",
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
          {
            position: "right",
            type: "html",
            value: "<span></span>",
            className: "navbar-items-separator",
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
                label: "Discord",
                href: "https://discordapp.com/invite/docusaurus",
              },
              {
                label: "Twitter",
                href: "https://twitter.com/docusaurus",
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
                href: "https://github.com/facebook/docusaurus",
              },
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} ipsw. Built with Go and ❤️`,
      },
    }),

  plugins: ["docusaurus-plugin-image-zoom"],
};

module.exports = config;
