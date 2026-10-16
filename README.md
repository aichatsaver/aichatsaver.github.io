# AI Chat Saver website

Jekyll site served by GitHub Pages at https://aichatsaver.github.io/ (no Actions needed).

- Edit product values in `_data/site.yml` (product name, tagline, support email, prices, Pro status, store links, feature lists).
- Edit policy text in `pages/privacy.md`, `pages/terms.md`, `pages/refund.md`.
- Translations: `_data/i18n/<code>.yml` (10 languages); the pages read these at build time.
- A private admin panel (password protected, not linked from the site) can edit all of this; it saves through the GitHub API.
- Prices: write `TBD` (or leave empty) to show "Coming soon".
