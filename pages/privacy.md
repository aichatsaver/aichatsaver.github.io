---
title: Privacy Policy
description: How the AI Chat Saver browser extension handles your data. Your chats stay on your device.
permalink: /privacy.html
---
{% assign s = site.data.site %}
This Privacy Policy explains how the **{{ s.product_name }}** browser extension (the "Extension") and this website handle information. "{{ s.product_name }}", "we" and "us" mean the business that publishes the Extension.

> **In short:** the Extension reads your AI chats through your own browser and saves them only on your own computer. We do not receive your chats, we run no analytics, and we never sell data.

## 1. What the Extension does with your data

The Extension saves conversations from AI services you use (ChatGPT, Claude, Gemini, Google AI Mode, Google AI Studio, Gemini Notebook, Qwen, DeepSeek, Kimi, Z.ai, Grok, Copilot including GitHub Copilot, Meta AI, MiniMax, Manus, Perplexity, Doubao and Tencent Yuanbao).

- **Where chats are read from.** Chats are read only from AI sites you are already signed in to in your browser. The Extension uses your existing session on that site, in your browser, the same way the site's own page does. It never asks for, sees or stores your passwords for those sites.
- **Where chats are written to.** Chats, and the images, files and other media in them, are written only to:
  - your own **Downloads folder** (in `Downloads/AI Chat Saver/`), or a **folder you choose to connect**; and
  - your **browser's local storage** on your device (extension storage and IndexedDB), so that search and the Command Center work.
- **What is saved.** Messages, attachments and generated media, thinking or reasoning, tool calls and code output, sources and citations, artifacts, and some account extras the AI site shows you (for example project instructions, memories or custom instructions), depending on the AI and your settings.
- **Settings** (including highlights, notes, tags and an optional PIN lock) are kept in local browser storage on your device. They are not synced to your browser account.

**None of this content is sent to us.** We have no server that receives your chats, and we cannot see them.

## 2. Network requests the Extension makes

The Extension only connects to:

1. **The AI services themselves** and the addresses they use to store your chat media (for example their file and image hosts), to read your chats and download their attachments. For Google AI Mode it also reads your Google My Activity list of AI Mode chats; for Google AI Studio it reads (never changes) the AI Studio prompt files stored in your own Google Drive.
2. **Google's public favicon service** (`www.google.com/s2/favicons`), in some views and exported pages, to show the small icon of a website cited as a source. This request includes that website's domain name, not your chat.
3. **Public code libraries** (`esm.sh`, `unpkg.com`, `cdn.tailwindcss.com`), only when you open a live preview of a code artifact (for example a React or Mermaid artifact). These requests download the library code; your chat is not sent. The preview runs in an isolated sandbox page.

Like any web request, these services receive standard technical information such as your IP address and browser type, under their own privacy policies.

The Extension contains **no analytics, no advertising, no tracking and no telemetry**.

## 3. Browser permissions and why they are needed

| Permission | Why it is needed |
|---|---|
| Access to the AI sites and their media hosts | To read your chats from the sites you are signed in to and save the images and files in them. Media can live on many different hosts, so access to web pages in general is requested; the Extension only uses it to download media belonging to your chats. |
| `downloads`, `downloads.ui` | To write your saved chats into your Downloads folder, and to keep the browser's download bar quiet and remove the Extension's own entries from the download list (the files stay on disk). |
| `storage`, `unlimitedStorage` | To keep your vault, settings, highlights and notes in local browser storage on your device. |
| `scripting` | To read chats in the AI site's own page when the site has no other way to list them. |
| `offscreen` | To build exports such as PDF and Word files on your device. |
| `alarms` | To run scheduled Updates at the interval you choose. |
| `notifications` | To tell you when an Update finishes or an AI site changed and needs attention. |

## 4. Pro, payments and licensing

When Pro becomes available, purchases, subscriptions, licence keys and refunds will be handled by **Freemius, Inc.** as reseller and merchant of record. If you buy Pro, Freemius processes your **email address, licence key and payment data** (and related billing details such as country for tax) under its own privacy policy: <https://freemius.com/privacy/>. We do not see or store your full card details. Licence checks will send your licence key and the information needed to validate it to Freemius; they never include your chats.

## 5. Sharing and selling

We do not sell, rent or trade any data. We do not share your chats with anyone, because we never receive them. The only third party involved in a purchase is Freemius, as described above.

## 6. This website

This website is hosted on GitHub Pages. It uses no cookies, no analytics and no tracking scripts of our own. GitHub may log standard technical information (such as IP addresses) to run and secure the service, under the GitHub Privacy Statement: <https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement>.

## 7. Data retention and deletion

Because your data is stored only on your device, you control how long it is kept:

- **Delete the saved files:** delete the `AI Chat Saver` folder in your Downloads folder (or the folder you connected).
- **Delete the in-browser vault:** use **Settings → Clear vault** in the Command Center, or **uninstall the Extension**. Uninstalling removes the Extension's local browser storage. Files already written to your folder are not deleted by uninstalling; delete the folder to remove them.
- **Pro purchase data** is kept by Freemius as required for billing, tax and legal reasons. To ask for it to be deleted, contact Freemius or us at {{ s.support_email }}.

## 8. Children

The Extension and this website are not directed at children under 13 (or the minimum age required in your country), and we do not knowingly collect personal information from children.

## 9. Security

Your chats never leave your device through us. Keep your computer and browser profile protected, since anyone with access to them can open your saved files. The optional PIN lock hides the Command Center but does not encrypt the files in your folder.

## 10. Changes to this policy

If we change this policy we will update this page and the "Last updated" date above. If a change affects how the Extension handles your data, we will say so in the Extension's release notes before the change takes effect.

## 11. Contact

Questions about privacy: **{{ s.support_email }}**.
