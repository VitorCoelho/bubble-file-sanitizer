# Bubble Export Sanitizer

Strip API keys, credentials and personal data from a Bubble.io `.bubble` app export — entirely in your browser, offline, with an audit trail of every change.

Bubble's **Settings → General → Export application** gives you a JSON file of your whole app. It is great for backups, code migration, AI-assisted documentation or sharing with a contractor — and it contains every API Connector key, Stripe secret, database connection string and hard-coded email address in your app. This tool lets you share the file without sharing those.

## Use it

- **Hosted:** open `index.html` from GitHub Pages (or any static host).
- **Local, single file:** download `dist/bubble-sanitizer.html` and open it from disk. It has the engine inlined and needs nothing else.

Drop the `.bubble` file, pick the rules, click **Sanitize**, read the report, download `yourapp.sanitized.bubble`.

## Guarantees

- **No network.** The page ships a `Content-Security-Policy` with `default-src 'none'; connect-src 'none'`. The browser refuses any request the code might try. Check DevTools → Network, or use it in airplane mode.
- **No storage.** Nothing is written to localStorage, cookies, IndexedDB or disk until you click Download. "Clear memory" drops the file.
- **No dependencies, no build step.** One engine file (`src/sanitizer.js`) and one page. Read them.
- **Structure preserved.** Only string values are rewritten. Keys, numbers, booleans, nulls, order and nesting are untouched, so the file keeps its shape and internal references.
- **Bubble ids are protected.** Thing/element ids (`1700000000000x100000000000000001`), editor ids (`bTGYf`), plugin element and API call ids, dates and colors are never redacted, whatever rule fires.
- **Second-pass check.** The output is scanned again and must come back clean, or the download is disabled.
- **Audit report without secrets.** Every change is listed with JSON path, key and rule. Previews show two characters on each end plus the length; the original value is kept nowhere.

## What gets redacted

| Rule | What |
|---|---|
| `key-name` | String values under keys like `api_key`, `secret`, `token`, `password`, `private_key`, `client_secret`, `auth_token`, `connection_string`, `account_sid`, `access_key`… (also `{"api_key": {"value": …}}` shapes). Harmless lookalikes such as `token_type`, `auth_type`, `scope` are allow-listed. |
| `private-flag` | Any `value` inside an object marked `"private": true` — this is how the API Connector stores private headers and parameters. |
| Known formats | Stripe `sk_`/`rk_`/`whsec_` (and optionally `pk_`), AWS access keys, Google API keys, Twilio SIDs (optional) , Mailgun, SendGrid, Klaviyo private keys, Slack, GitHub and OpenAI tokens, JWTs, `Bearer …`/`Basic …` headers, PEM private keys, credentials inside URLs (`user:pass@host`), `password=` in connection strings, `key=value` secrets inside text and query strings. |
| `secure-settings` | Every value under `settings.secure` — the server-only half of Bubble's settings, where plugin keys live under opaque names like `1400000000000x…_ADu` (a Twilio auth token), next to API Connector passwords, Data API tokens and the app's private JWK. Labels (`key`, `name`, `url`, `method`), Bubble ids and trivial values (`True`, `1`, `api`) are kept. |
| `plugin-setting` | `settings.client_safe."<pluginid>_<key>"` — plugin settings the browser sees (publishable keys, app ids). |
| `sample-value` | API Connector `types` hold the **real response of the last initialization** (customer names, ids, addresses). String samples become `"string value"`; numbers/booleans stay for type inference. |
| `stripe-object-id` | Stripe customer-level ids (`cus_`, `sub_`, `si_`, `pm_`, `in_`, `ch_`, `pi_`, `promo_`…). Catalog ids (`prod_`, `price_`, `plan_`) are kept. |
| `sql-rows` | `INSERT … VALUES (…)` literal rows inside SQL Database Connector queries (pasted dumps). Parameterised `VALUES (?,?,?)` are untouched. |
| `comment` | Editor comments on elements, types and workflows → `[comment removed]`. |
| `param-value` | API Connector non-private parameters keep the test value typed at initialization (a phone number, a `cus_` id, a name). Config-like values (`usd`, `always_invoice`, `2`, return URLs, `prod_`/`price_` ids) are kept. |
| `tracking-id` | GTM / GA4 / UA / Ads ids, Meta pixel id, Clarity, Impact and Hyros ids inside the custom header scripts. Public, but they identify the account. |
| `custom-word` | Words you type in "Also redact these words" — people's names, internal hostnames — whole-word, case-insensitive, everywhere. |
| `email` / `phone` / `ip` | Replaced by `user1@example.com`, `+10000000001`, `0.0.0.1` — the same original always maps to the same placeholder in a run. You can keep emails on chosen domains. |
| `high-entropy` (opt-in) | Random-looking strings nothing else matched. By default they are only **listed for review**, because this rule can hit legitimate values. |

Each secret becomes `[REDACTED:<rule>:<10-hex>]`. The suffix is a salted hash of the original: identical secrets share a placeholder inside one run (so cross-references still line up), the salt is random per run (so placeholders can't be compared across runs or files), and nothing about the value can be recovered from it.

## What it cannot do

It does not know your business. Person names inside copy, street addresses, internal hostnames, or values that are secret only to you will not be detected. Read the review list and skim the output before publishing it anywhere.

Report a miss by opening an issue with the **JSON path and the key name only** — never the value.

## Development

```
node test/run.js   # engine test-suite (no dependencies)
node build.js      # writes dist/bubble-sanitizer.html (single file)
```

The engine is a UMD module: `window.BubbleSanitizer` in the browser, `require('./src/sanitizer.js')` in Node.

```js
const S = require('./src/sanitizer.js');
const { data, report, review, counts, total } = S.sanitize(jsonText, { emails: true, redactEntropy: false });
const out = S.stringify(data, jsonText);   // keeps compact/pretty style of the input
S.verify(out).clean;                        // true when a second pass finds nothing
```

## License

MIT. Not affiliated with Bubble Group, Inc.
