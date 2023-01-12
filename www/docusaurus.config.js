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
      algolia: {
        appId: "KYIBYORJ9P",
        apiKey: "3affebe656f9ea5ea2f830e2747f5afc",
        indexName: "ipsw",
        contextualSearch: true,
        custom_settings: {
          attributesForFaceting: [
            "language",
            "version",
            "type",
            "docusaurus_tag",
          ],
        },
      },
      gtag: {
        trackingID: "G-6PLDXGZBEK",
        anonymizeIP: false,
      },
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
                href: "https://discord.gg/xx2y9yrcgs",
              },
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
