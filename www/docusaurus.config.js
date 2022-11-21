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
  favicon: "img/favicon.png",

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
          editUrl:
            "https://github.com/facebook/docusaurus/tree/main/packages/create-docusaurus/templates/shared/",
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
      navbar: {
        title: "ipsw",
        logo: {
          alt: "ipsw logo",
          src: "img/icon.svg",
        },
        items: [
          {
            to: "docs/getting-started/overview/",
            label: "Docs",
            position: "left",
          },
          {
            to: "docs",
            label: "Tutorial",
            position: "left",
            activeBaseRegex: "/^/docs(/)?$/",
          },
          // {to: "/blog", label: "Blog", position: "left"},
          {
            href: "https://github.com/blacktop/ipsw",
            position: "right",
            className: "header-github-link",
            "aria-label": "GitHub repository",
          },
          {
            href: "https://discord.gg/xx2y9yrcgs",
            position: "right",
            className: "header-discord-link",
            "aria-label": "GitHub repository",
          },

          {
            type: "docsVersionDropdown",
            position: "right",
            dropdownActiveClassDisabled: true,
          },
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
                label: "Tutorial",
                to: "/docs/intro",
              },
            ],
          },
          {
            title: "Community",
            items: [
              {
                label: "Stack Overflow",
                href: "https://stackoverflow.com/questions/tagged/docusaurus",
              },
              {
                label: "Discord",
                href: "https://discordapp.com/invite/docusaurus",
              },
              {
                label: "Twitter",
                href: "https://twitter.com/docusaurus",
              },
              {
                html: `
                    <a href="https://www.netlify.com" target="_blank" rel="noreferrer noopener" aria-label="Deploys by Netlify">
                      <img src="https://www.netlify.com/img/global/badges/netlify-color-accent.svg" alt="Deploys by Netlify" width="114" height="51" />
                    </a>
                  `,
              },
            ],
          },
          {
            title: "More",
            items: [
              {
                label: "Blog",
                to: "/blog",
              },
              {
                label: "GitHub",
                href: "https://github.com/facebook/docusaurus",
              },
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} ipsw. Built with Go.`,
      },
      prism: {
        theme: lightCodeTheme,
        darkTheme: darkCodeTheme,
        // themes: [path.resolve(__dirname, "/src/themes/prism-nord")],
        additionalLanguages: ["armasm"],
      },
      // colorMode: {
      //   defaultMode: "light",
      //   disableSwitch: true,
      //   respectPrefersColorScheme: true,
      // },
    }),
};

module.exports = config;
