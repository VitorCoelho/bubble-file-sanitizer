/*
 * bubble-sanitizer — strips API keys, credentials and personal data from a
 * Bubble.io ".bubble" app export, entirely in memory.
 *
 * Works in the browser (window.BubbleSanitizer) and in Node (module.exports).
 * No dependencies. No network. No storage.
 *
 * Design:
 *  - Only STRING VALUES are ever rewritten. Object keys, numbers, booleans,
 *    nulls and the overall structure are never touched, so the file keeps its
 *    shape and every reference between nodes keeps working.
 *  - Bubble object ids (e.g. "1700000000000x100000000000000001") and short
 *    editor ids are protected: a protected value is never redacted by any rule.
 *  - Every rewrite is recorded with its JSON path and the rule that fired, so
 *    the user can audit exactly what changed (without ever seeing the secret).
 *  - Replacements are deterministic within one run (same secret → same
 *    placeholder) using a random per-run salt, so cross-references survive but
 *    nothing about the original value can be recovered from the output.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.BubbleSanitizer = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ---------------------------------------------------------------------------
  // Protected values: never redact these, whatever any rule says.
  // ---------------------------------------------------------------------------
  const BUBBLE_ID = /^\d{13}x\d{12,24}$/;                 // thing / element ids
  const BUBBLE_SHORT_ID = /^[a-z]?[A-Z]{2,3}[A-Za-z]{0,3}[0-9]?$/; // editor ids: "bQZPk", "AAa", "bQRsT0", "cXa"
  const BUBBLE_TYPED_ID = /^(?:[A-Za-z0-9_]{1,40}-)?\d{13}x\d{12,24}(?:[.\-_]\d{13}x\d{12,24})*$/; // plugin-element & api-call ids
  const PLUGIN_KEY = /^\d{13}x\d{12,24}-[A-Za-z]{2,8}$/;  // "1600000000000x100000000000000003-AAC"
  const ISO_DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$/;
  const HEX_COLOR = /^#[0-9a-fA-F]{3,8}$/;
  const URL_ONLY = /^https?:\/\/[^\s?#]+$/i;              // plain URL with no query/fragment

  // Placeholders produced by this tool. Protected so a second run is a no-op.
  const PLACEHOLDER_RE = /^\[REDACTED:[a-z0-9\-]+:[0-9a-f]{10}\]$/;
  const PII_PLACEHOLDER_RE = /^(user\d+@example\.com|\+1000000\d{4}|0\.0\.0\.\d+)$/;

  function isProtectedValue(s) {
    return BUBBLE_ID.test(s) || BUBBLE_SHORT_ID.test(s) || BUBBLE_TYPED_ID.test(s) ||
      PLUGIN_KEY.test(s) || ISO_DATE.test(s) || HEX_COLOR.test(s) ||
      PLACEHOLDER_RE.test(s) || PII_PLACEHOLDER_RE.test(s);
  }

  // ---------------------------------------------------------------------------
  // Rule 1 — key names that hold credentials. Applies to the key the string
  // sits under, and to its parent key for shapes like {"api_key": {"value": …}}.
  // ---------------------------------------------------------------------------
  const SECRET_KEY_RE = new RegExp([
    'api[_\\-\\s]?key', 'apikey', 'secret', 'token', 'passw(or)?d', 'passphrase',
    'private[_\\-\\s]?key', 'client[_\\-\\s]?secret', 'signing[_\\-\\s]?key', 'auth(orization)?$',
    'bearer', 'credential', 'connection[_\\-\\s]?string', '^dsn$', 'access[_\\-\\s]?key',
    'secret[_\\-\\s]?key', 'webhook[_\\-\\s]?secret', 'sk_(live|test)', 'auth[_\\-\\s]?token',
    'account[_\\-\\s]?sid', 'app[_\\-\\s]?secret', 'encryption[_\\-\\s]?key', 'master[_\\-\\s]?key',
    'service[_\\-\\s]?account', 'refresh[_\\-\\s]?token', 'session[_\\-\\s]?key',
    'license[_\\-\\s]?key', 'x-api-key', 'shared[_\\-\\s]?secret'
  ].join('|'), 'i');

  // Keys that look sensitive but are routinely public/non-secret in Bubble files.
  const SECRET_KEY_ALLOW_RE = /^(token_type|auth_type|authentication_type|secret_name|api_key_name|key_name|use_authentication|is_secret|private|tokenize|token_len(gth)?|password_min_length|password_rules|api_key_header_name|auth_mode|auth_method|password_field|secret_field|has_password|password_required|requires_auth|is_authenticated|authorize_url|authorization_url|token_url|oauth_version|oauth_scope|scope|auth_required|password_confirmation_field)$/i;

  // ---------------------------------------------------------------------------
  // Rule 2 — well-known secret formats, matched inside any string value.
  // Each entry: id, regex (global), what to replace (whole match or group 1).
  // ---------------------------------------------------------------------------
  const FORMAT_RULES = [
    { id: 'stripe-secret',     re: /\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{10,}\b/g },
    { id: 'stripe-webhook',    re: /\bwhsec_[0-9A-Za-z]{10,}\b/g },
    { id: 'stripe-publishable',re: /\bpk_(?:live|test)_[0-9A-Za-z]{10,}\b/g, optional: 'publishable' },
    { id: 'aws-access-key',    re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
    { id: 'google-api-key',    re: /\bAIza[0-9A-Za-z_\-]{35}\b/g },
    { id: 'twilio-sid',        re: /\b(?:AC|SK|VA|VE|MG|IS|SM|MM)[0-9a-f]{32}\b/g, optional: 'sids' },
    { id: 'mailgun-key',       re: /\bkey-[0-9a-f]{32}\b/g },
    { id: 'sendgrid-key',      re: /\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b/g },
    { id: 'klaviyo-private',   re: /\bpk_[0-9a-f]{34}\b/g },
    { id: 'slack-token',       re: /\bxox[abprs]-[0-9A-Za-z\-]{10,}\b/g },
    { id: 'github-token',      re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
    { id: 'openai-key',        re: /\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{20,}\b/g },
    { id: 'jwt',               re: /\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b/g },
    { id: 'bearer-header',     re: /\b(Bearer\s+)([A-Za-z0-9._\-+/=]{16,})/g, group: 2 },
    { id: 'basic-auth-header', re: /\b(Basic\s+)([A-Za-z0-9+/=]{16,})/g, group: 2 },
    { id: 'pem-private-key',   re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
    { id: 'url-credentials',   re: /\b([a-z][a-z0-9+.\-]*:\/\/[^\s:@/]+:)([^\s@/]+)(@)/gi, group: 2 },
    // "password=…" in connection strings. Skips SQL/ORM parameter markers (?, :name, @p, $1, <tag>).
    { id: 'conn-string-pwd',   re: /\b((?:password|pwd|passwd)\s*=\s*)(?![?:@$<])([^;\s"'<>]{4,})/gi, group: 2 },
    // Stripe customer-level object ids (identify real customers / payments). Catalog ids (prod_, price_, plan_) are kept.
    { id: 'stripe-object-id',  re: /\b(?:cus|sub|si|pm|in|ch|pi|py|re|promo|cs|seti|txn|evt|card|ba|src|tok|ic|il|dp|acct)_[0-9A-Za-z]{8,}\b/g, optional: 'stripeIds' },
    { id: 'kv-secret-in-text', re: /\b((?:api[_\-]?key|apikey|secret|token|password|access[_\-]?token|auth[_\-]?token)\s*[:=]\s*["']?)([A-Za-z0-9_\-+/=.]{12,})/gi, group: 2 },
    // Analytics / pixel ids embedded in header scripts. Public, but they identify the account.
    { id: 'tracking-id',       re: /\b(?:GTM-[A-Z0-9]{6,10}|G-(?=[A-Z0-9]*\d)[A-Z0-9]{8,12}|UA-\d{4,10}-\d{1,3}|AW-\d{8,12}|DC-\d{6,12})\b/g, optional: 'trackingIds' },
    { id: 'tracking-id',       re: /(fbq\(\s*['"](?:init|trackSingle|trackSingleCustom)['"]\s*,\s*['"])(\d{12,18})/g, group: 2, optional: 'trackingIds' },
    { id: 'tracking-id',       re: /(facebook\.com\/tr\/?\?id=)(\d{12,18})/g, group: 2, optional: 'trackingIds' },
    { id: 'tracking-id',       re: /(["']clarity["']\s*,\s*["']script["']\s*,\s*["'])([a-z0-9]{6,16})/g, group: 2, optional: 'trackingIds' },
    { id: 'tracking-id',       re: /(<meta\s+name=["'][\w\-]*verification["']\s+content=["'])([^"']{6,})/gi, group: 2, optional: 'trackingIds' },
    { id: 'tracking-id',       re: /([?&](?:ph|pixel_id|pid|account|aid|cid|client_id)=)([A-Za-z0-9_\-]{10,})/gi, group: 2, optional: 'trackingIds' },
    { id: 'stripe-connect-id', re: /\bca_[0-9A-Za-z]{20,}\b/g, optional: 'stripeIds' },
    // Stripe Payment Links / customer portal / hosted invoice codes: they open the account's own checkout pages.
    { id: 'stripe-link',       re: /((?:buy|billing|checkout|donate|invoice|pay)\.stripe\.com\/(?:p\/login\/|b\/|c\/pay\/|i\/)?)((?:test_)?[A-Za-z0-9]{10,})/g, group: 2, optional: 'stripeIds' },
    { id: 'stripe-link',       re: /^test_[A-Za-z0-9]{14,40}$/g, optional: 'stripeIds' },
    // Authenticator (TOTP) secrets: a whole value of 16+ base32 characters with at least one digit.
    { id: 'totp-secret',       re: /^(?=[A-Z2-7]*[2-7])(?=[A-Z2-7]*[A-Z])[A-Z2-7]{16,64}={0,6}$/g },
    { id: 'url-query-secret',  re: /([?&](?:api[_\-]?key|apikey|key|token|secret|signature|sig|auth|password|access_token|client_secret|private_key)=)([^&#\s"']+)/gi, group: 2 }
  ];

  // ---------------------------------------------------------------------------
  // Rule 3 — personal data (optional, on by default).
  // ---------------------------------------------------------------------------
  const EMAIL_RE = /[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g;
  // E.164 or common formatted numbers with 8–15 digits; avoids plain integers.
  const PHONE_RE = /(?<![\w.\-])(?:\+\d[\d\s().\-]{6,18}\d|\(\d{2,4}\)\s?\d[\d\s.\-]{5,12}\d|\d{2,4}[\s.\-]\d{3,4}[\s.\-]\d{3,5})(?![\w\-])/g;
  const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;

  // Bubble API Connector marks private params/headers with {"private": true}.
  // Shapes vary across versions, so we check a few sibling-key spellings.
  const PRIVATE_FLAG_KEYS = ['private', 'is_private', 'isPrivate', 'secret', 'is_secret'];
  const VALUE_KEYS = ['value', 'val', 'default', 'default_value', 'defaultValue'];

  // High-entropy scan (review-only unless the user opts in to redact).
  function shannon(s) {
    const f = Object.create(null);
    for (const c of s) f[c] = (f[c] || 0) + 1;
    let h = 0; const n = s.length;
    for (const k in f) { const p = f[k] / n; h -= p * Math.log2(p); }
    return h;
  }
  function looksHighEntropy(s) {
    if (s.length < 24 || s.length > 512) return false;
    if (/\s/.test(s)) return false;
    if (!/^[A-Za-z0-9_\-+/=.:]+$/.test(s)) return false;
    if (!/[A-Za-z]/.test(s) || !/\d/.test(s)) return false;
    if (URL_ONLY.test(s) || /^(https?:)?\/\/[^\s?#]+$/i.test(s)) return false;   // plain / protocol-relative URLs
    if (/\d{13}x\d{12,}/.test(s)) return false;                                 // contains a Bubble id
    if (/^[A-Za-z][A-Za-z0-9_\-]*$/.test(s) && ((s.match(/\d/g) || []).length < s.length * 0.15 || /_$|__/.test(s))) return false; // identifiers / style ids
    if (/^[a-z_]+(?:\.[A-Za-z0-9_\-]+)+$/.test(s)) return false;                 // dotted internal paths (styles.X, api.apiconnector2.Y)
    return shannon(s) >= 3.9;
  }

  // ---------------------------------------------------------------------------
  // Salted, non-reversible placeholder. Same input → same placeholder per run.
  // FNV-1a 52-bit over (salt + value); plenty for correlation, useless for recovery.
  // ---------------------------------------------------------------------------
  function makeHasher(salt) {
    return function (s) {
      let h1 = 0x811c9dc5 ^ salt.length, h2 = 0x01000193;
      const str = salt + '\u0000' + s;
      for (let i = 0; i < str.length; i++) {
        const c = str.charCodeAt(i);
        h1 = Math.imul(h1 ^ c, 16777619) >>> 0;
        h2 = Math.imul(h2 ^ c, 2246822519) >>> 0;
      }
      return (h1.toString(16).padStart(8, '0') + h2.toString(16).padStart(8, '0')).slice(0, 10);
    };
  }
  function randomSalt() {
    try {
      const g = (typeof crypto !== 'undefined' && crypto.getRandomValues) ? crypto :
        (typeof require === 'function' ? require('crypto').webcrypto : null);
      if (g) { const a = new Uint32Array(4); g.getRandomValues(a); return Array.from(a, x => x.toString(16)).join(''); }
    } catch (e) { /* fall through */ }
    return String(Date.now()) + Math.random().toString(16).slice(2);
  }

  // Iterative deep clone of plain JSON data (no recursion, no stack limits).
  function deepClone(src) {
    if (src === null || typeof src !== 'object') return src;
    const rootOut = Array.isArray(src) ? [] : {};
    const stack = [[src, rootOut]];
    while (stack.length) {
      const [from, to] = stack.pop();
      const keys = Array.isArray(from) ? from.map((_, i) => i) : Object.keys(from);
      for (const k of keys) {
        const v = from[k];
        if (v && typeof v === 'object') { const c = Array.isArray(v) ? [] : {}; to[k] = c; stack.push([v, c]); }
        else to[k] = v;
      }
    }
    return rootOut;
  }

  function preview(s) {
    // Non-recoverable hint for the audit table: shape only.
    const len = s.length;
    if (len <= 4) return '•'.repeat(len);
    const head = s.slice(0, 2), tail = s.slice(-2);
    return head + '•'.repeat(Math.min(len - 4, 12)) + tail + ' (' + len + ' chars)';
  }

  // ---------------------------------------------------------------------------
  // Core
  // ---------------------------------------------------------------------------
  const DEFAULT_OPTIONS = {
    keyNames: true,          // rule 1
    formats: true,           // rule 2
    privateFlags: true,      // API Connector {private:true} values
    publishable: true,       // Stripe pk_live/pk_test (public, but usually not wanted in a repo)
    sids: true,              // Twilio SIDs (identify the account, not secret by themselves)
    emails: true,            // rule 3
    phones: true,
    ips: true,
    keepEmailDomains: [],    // e.g. ["example.com"] — emails on these domains are kept
    entropyScan: true,       // list high-entropy strings for manual review
    redactEntropy: false,    // …and redact them too (aggressive)
    // Bubble-structure rules (where the export is known to keep sensitive things)
    secureSettings: true,    // settings.secure: every value is a credential → redact all
    pluginKeys: true,        // settings.client_safe "<pluginid>_<key>" plugin settings
    sampleValues: true,      // API Connector initialized sample responses (real customer data)
    sqlRows: true,           // SQL Database Connector: INSERT … VALUES (...) literal rows
    comments: true,          // editor comments (names, internal notes)
    stripeIds: true,         // Stripe customer-level ids (cus_, sub_, pm_, in_, ch_ …)
    paramValues: true,       // API Connector non-private parameter test values (client_safe)
    trackingIds: true,       // GTM / GA / pixel ids in header scripts
    customWords: [],         // extra words to redact everywhere (names, hostnames…), case-insensitive
    maxReportEntries: 5000
  };

  // Values that are plainly not secrets even inside settings.secure.
  const TRIVIAL_RE = /^(true|false|yes|no|null|undefined|none|\d{1,6}|[a-z]{1,3})$/i;
  const PLUGIN_SETTING_KEY = /^\d{13}x\d{12,24}_/;
  const SQL_INSERT_RE = /(INSERT\s+(?:IGNORE\s+)?INTO\s+[`"'\w.\[\]]+\s*(?:\([^)]*\))?\s*VALUES\s*)([\s\S]*?)(;|$)/gi;

  function sanitize(input, options) {
    const opts = Object.assign({}, DEFAULT_OPTIONS, options || {});
    const salt = randomSalt();
    const hash = makeHasher(salt);
    const report = [];
    const review = [];
    const counts = Object.create(null);
    const pii = { emails: new Map(), phones: new Map(), ips: new Map() };
    const keepDomains = (opts.keepEmailDomains || []).map(d => String(d).trim().toLowerCase()).filter(Boolean);
    const customWords = (opts.customWords || []).map(w => String(w).trim()).filter(w => w.length >= 2);
    const customRe = customWords.length ? new RegExp('(?<![A-Za-z0-9])(?:' + customWords.map(w => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|') + ')(?![A-Za-z0-9])', 'gi') : null;

    let data;
    if (typeof input === 'string') {
      const text = input.charCodeAt(0) === 0xFEFF ? input.slice(1) : input;
      data = JSON.parse(text);
    } else {
      data = deepClone(input); // never mutate the caller's object
    }

    function record(path, key, rule, original, replacement) {
      counts[rule] = (counts[rule] || 0) + 1;
      if (report.length < opts.maxReportEntries) {
        report.push({ path, key, rule, preview: preview(original), replacement });
      }
    }
    function placeholder(rule, original) {
      return '[REDACTED:' + rule + ':' + hash(original) + ']';
    }
    function piiPlaceholder(kind, original) {
      const map = pii[kind];
      const norm = kind === 'emails' ? original.toLowerCase() : original.replace(/[^\d+]/g, '');
      if (!map.has(norm)) map.set(norm, map.size + 1);
      const n = map.get(norm);
      if (kind === 'emails') return 'user' + n + '@example.com';
      if (kind === 'phones') return '+1000000' + String(n).padStart(4, '0');
      return '0.0.0.' + n;
    }

    // Replace a whole string value.
    function redactWhole(s, rule, path, key) {
      const r = placeholder(rule, s);
      record(path, key, rule, s, r);
      return r;
    }

    // Apply in-string pattern rules; returns the new string.
    function redactPatterns(s, path, key) {
      let out = s;
      if (opts.formats) {
        for (const fr of FORMAT_RULES) {
          if (fr.optional && !opts[fr.optional]) continue;
          fr.re.lastIndex = 0;
          if (!fr.re.test(out)) continue;
          fr.re.lastIndex = 0;
          out = out.replace(fr.re, function () {
            const m = arguments[0];
            if (fr.group) {
              const groups = Array.prototype.slice.call(arguments, 1, -2);
              const secret = groups[fr.group - 1];
              if (isProtectedValue(secret)) return m;
              const r = placeholder(fr.id, secret);
              record(path, key, fr.id, secret, r);
              return m.replace(secret, r);
            }
            if (isProtectedValue(m)) return m;
            const r = placeholder(fr.id, m);
            record(path, key, fr.id, m, r);
            return r;
          });
        }
      }
      if (opts.emails) {
        EMAIL_RE.lastIndex = 0;
        out = out.replace(EMAIL_RE, function (m) {
          const dom = m.split('@')[1].toLowerCase();
          if (keepDomains.some(d => dom === d || dom.endsWith('.' + d))) return m;
          if (/@example\.(com|org|net)$/i.test(m)) return m;
          const r = piiPlaceholder('emails', m);
          record(path, key, 'email', m, r);
          return r;
        });
      }
      if (opts.phones && /^\+?\d{11,15}$/.test(out) && !/^1[4-9]\d{11}$/.test(out) && !/change|version|count|time|date|stamp|size|amount|price/i.test(String(key))) {
        // A whole value of 11-15 bare digits is a phone number in E.164 without the "+" (e.g. a Twilio "From").
        // 13-digit values starting 14-19 are millisecond timestamps and are kept.
        const r = piiPlaceholder('phones', out);
        record(path, key, 'phone', out, r);
        return r;
      }
      if (opts.phones) {
        PHONE_RE.lastIndex = 0;
        out = out.replace(PHONE_RE, function (m) {
          if (isProtectedValue(m)) return m;
          const digits = m.replace(/\D/g, '');
          const min = m.trim().startsWith('+') ? 8 : 10;
          if (digits.length < min || digits.length > 15) return m;
          const r = piiPlaceholder('phones', m);
          record(path, key, 'phone', m, r);
          return r;
        });
      }
      if (opts.ips) {
        IPV4_RE.lastIndex = 0;
        out = out.replace(IPV4_RE, function (m) {
          if (isProtectedValue(m)) return m;
          if (/^(0\.0\.0\.0|127\.0\.0\.1|255\.255\.255\.255|0\.0\.0\.\d+)$/.test(m)) return m;
          if (m.split('.').every(p => p.length <= 1)) return m; // "1.2.3.4" version-like
          const r = piiPlaceholder('ips', m);
          record(path, key, 'ip', m, r);
          return r;
        });
      }
      if (customRe) {
        customRe.lastIndex = 0;
        out = out.replace(customRe, function (m) {
          const r = placeholder('custom-word', m.toLowerCase());
          record(path, key, 'custom-word', m, r);
          return r;
        });
      }
      return out;
    }

    function keyIsSecret(k) {
      if (typeof k !== 'string') return false;
      if (SECRET_KEY_ALLOW_RE.test(k)) return false;
      return SECRET_KEY_RE.test(k);
    }

    // Does this object carry an API-Connector style private flag?
    function hasPrivateFlag(obj) {
      for (const f of PRIVATE_FLAG_KEYS) if (obj[f] === true || obj[f] === 'true') return true;
      return false;
    }

    // -----------------------------------------------------------------------
    // Bubble-structure pass: places where the export is known to hold secrets
    // or real data, handled before the generic walk.
    // -----------------------------------------------------------------------
    const settings = data && data.settings && typeof data.settings === 'object' ? data.settings : null;

    // settings.secure — the server-only half of the settings: plugin keys under
    // opaque names like "1400000000000x100000000000000007_ADu", API Connector
    // passwords, Data API tokens, JWKs… Everything here is a credential.
    if (opts.secureSettings && settings && settings.secure && typeof settings.secure === 'object') {
      const st = [{ node: settings.secure, path: '$.settings.secure' }];
      while (st.length) {
        const { node, path } = st.pop();
        const isArr = Array.isArray(node);
        const keys = isArr ? node.map((_, i) => i) : Object.keys(node);
        for (const k of keys) {
          const v = node[k];
          const p = isArr ? path + '[' + k + ']' : path + '.' + k;
          if (v && typeof v === 'object') { st.push({ node: v, path: p }); continue; }
          if (typeof v !== 'string' || v === '') continue;
          if (isProtectedValue(v)) continue;
          if (TRIVIAL_RE.test(v) && !/user|login|pass|secret|token|key|account|campaign|tracker|client/i.test(String(k))) continue;
          if (String(k) === 'key' || String(k) === 'name' || String(k) === 'url' || String(k) === 'method') continue; // labels, not values
          if (URL_ONLY.test(v)) continue;
          node[k] = redactWhole(v, 'secure-settings', p, String(k));
        }
      }
    }

    const cs = settings && settings.client_safe && typeof settings.client_safe === 'object' ? settings.client_safe : null;

    // settings.client_safe."<pluginid>_<key>" — plugin settings exposed to the
    // browser (public keys, app ids). Not secret by definition, but they
    // identify the account; redact anything that is not trivial.
    if (opts.pluginKeys && cs) {
      for (const k of Object.keys(cs)) {
        const v = cs[k];
        if (!PLUGIN_SETTING_KEY.test(k) || typeof v !== 'string' || v === '') continue;
        if (isProtectedValue(v) || TRIVIAL_RE.test(v) || URL_ONLY.test(v)) continue;
        cs[k] = redactWhole(v, 'plugin-setting', '$.settings.client_safe.' + k, k);
      }
    }

    // API Connector initialized responses: calls[*].types is a JSON string whose
    // "sample_value" fields hold the real response of the last initialization
    // (customer names, ids, addresses…). Replace string samples with Bubble's
    // own generic placeholder; numbers/booleans are kept for type inference.
    if (opts.sampleValues && cs && cs.apiconnector2 && typeof cs.apiconnector2 === 'object') {
      for (const colId of Object.keys(cs.apiconnector2)) {
        const col = cs.apiconnector2[colId];
        if (!col || typeof col !== 'object' || !col.calls || typeof col.calls !== 'object') continue;
        for (const callId of Object.keys(col.calls)) {
          const call = col.calls[callId];
          if (!call || typeof call !== 'object' || typeof call.types !== 'string') continue;
          let types;
          try { types = JSON.parse(call.types); } catch (e) { continue; }
          let changed = 0;
          for (const t of Object.values(types)) {
            if (!t || typeof t !== 'object' || !t.fields || typeof t.fields !== 'object') continue;
            for (const f of Object.values(t.fields)) {
              if (!f || typeof f !== 'object') continue;
              const sv = f.sample_value;
              if (typeof sv === 'string' && sv !== '' && sv !== 'string value' && !isProtectedValue(sv) && !TRIVIAL_RE.test(sv)) {
                f.sample_value = 'string value'; changed++;
              }
            }
          }
          if (changed) {
            counts['sample-value'] = (counts['sample-value'] || 0) + changed;
            if (report.length < opts.maxReportEntries) {
              report.push({ path: '$.settings.client_safe.apiconnector2.' + colId + '.calls.' + callId + '.types', key: 'sample_value', rule: 'sample-value', preview: changed + ' sample value(s)', replacement: 'string value' });
            }
            call.types = JSON.stringify(types);
          }
        }
      }
    }

    // API Connector non-private parameters keep the test value the developer
    // typed when initializing the call (a real phone number, a customer id…).
    // Config-like values (usd, always_invoice, 1, URLs, catalog ids) are kept.
    if (opts.paramValues && cs && cs.apiconnector2 && typeof cs.apiconnector2 === 'object') {
      const CONFIGISH = /^(?:(?![\d\-\[\]]*$)[a-z0-9_\-\[\]]{1,40}|\d{1,7}(?:\.\d+)?|true|false|yes|no|prod_[A-Za-z0-9]+|price_[A-Za-z0-9]+|plan_[A-Za-z0-9]+|[a-z]{1,12})$/;
      for (const colId of Object.keys(cs.apiconnector2)) {
        const col = cs.apiconnector2[colId];
        if (!col || typeof col !== 'object' || !col.calls || typeof col.calls !== 'object') continue;
        for (const callId of Object.keys(col.calls)) {
          const call = col.calls[callId];
          if (!call || typeof call !== 'object') continue;
          for (const bucket of ['params', 'body_params', 'url_params', 'headers']) {
            const list = call[bucket];
            if (!list || typeof list !== 'object') continue;
            for (const pid of Object.keys(list)) {
              const prm = list[pid];
              if (!prm || typeof prm !== 'object' || typeof prm.value !== 'string' || prm.value === '') continue;
              const v = prm.value;
              if (isProtectedValue(v) || CONFIGISH.test(v) || URL_ONLY.test(v)) continue;
              if (/^https?:\/\/[^\s"']+$/i.test(v) && !/[?&](?:key|token|secret|sig|signature|auth)=/i.test(v)) continue; // return/success URLs
              prm.value = redactWhole(v, 'param-value', '$.settings.client_safe.apiconnector2.' + colId + '.calls.' + callId + '.' + bucket + '.' + pid + '.value', String(prm.key || pid));
            }
          }
        }
      }
    }

    // SQL Database Connector queries: a pasted dump can carry literal rows.
    // Parameterised inserts (VALUES (?,?,?)) are untouched.
    if (opts.sqlRows && cs && typeof cs.dbconnector_queries === 'string') {
      let q; try { q = JSON.parse(cs.dbconnector_queries); } catch (e) { q = null; }
      if (q && typeof q === 'object') {
        let changed = 0;
        for (const id of Object.keys(q)) {
          const item = q[id];
          if (!item || typeof item !== 'object' || typeof item.text !== 'string') continue;
          SQL_INSERT_RE.lastIndex = 0;
          const nt = item.text.replace(SQL_INSERT_RE, function (m, head, body, tail) {
            if (!/['"]|\d/.test(body)) return m;            // only markers like ?,?,? → leave alone
            changed++;
            return head + "(/* rows removed by sanitizer */)" + tail;
          });
          // params carry a test_value per placeholder: an array of objects, or that array serialized
          // as JSON or as a Python-style repr.
          if (item.params && typeof item.params === 'object') {
            let c3 = 0;
            for (const prm of Object.values(item.params)) {
              if (!prm || typeof prm !== 'object' || typeof prm.test_value !== 'string') continue;
              const val = prm.test_value;
              if (val === '' || val === 'string value' || TRIVIAL_RE.test(val) || isProtectedValue(val)) continue;
              prm.test_value = 'string value'; c3++;
            }
            if (c3) { changed += c3; if (report.length < opts.maxReportEntries) report.push({ path: '$.settings.client_safe.dbconnector_queries.' + id + '.params', key: 'test_value', rule: 'sql-rows', preview: c3 + ' test value(s)', replacement: 'string value' }); }
          }
          if (typeof item.params === 'string') {
            let c2 = 0;
            const np = item.params.replace(/(["']test_value["']\s*:\s*)(["'])((?:(?!\2).)*)\2/g, function (m, head, q, val) {
              if (val === '' || val === 'string value' || TRIVIAL_RE.test(val) || isProtectedValue(val)) return m;
              c2++; return head + q + 'string value' + q;
            });
            if (c2) { item.params = np; changed += c2; if (report.length < opts.maxReportEntries) report.push({ path: '$.settings.client_safe.dbconnector_queries.' + id + '.params', key: 'test_value', rule: 'sql-rows', preview: c2 + ' test value(s)', replacement: 'string value' }); }
          }
          if (nt !== item.text) {
            item.text = nt;
            if (report.length < opts.maxReportEntries) report.push({ path: '$.settings.client_safe.dbconnector_queries.' + id + '.text', key: String(item.name || id), rule: 'sql-rows', preview: 'INSERT … VALUES (…) literal rows', replacement: '(/* rows removed by sanitizer */)' });
          }
        }
        if (changed) { counts['sql-rows'] = (counts['sql-rows'] || 0) + changed; cs.dbconnector_queries = JSON.stringify(q); }
      }
    }

    // Editor comments: free text with people's names and internal notes.
    if (opts.comments && data && data.comments && typeof data.comments === 'object') {
      const st = [{ node: data.comments, path: '$.comments' }];
      let changed = 0;
      while (st.length) {
        const { node, path } = st.pop();
        for (const k of Object.keys(node)) {
          const v = node[k];
          if (v && typeof v === 'object') st.push({ node: v, path: path + '.' + k });
          else if (k === 'content' && typeof v === 'string' && v !== '' && v !== '[comment removed]') { node[k] = '[comment removed]'; changed++; }
        }
      }
      if (changed) {
        counts['comment'] = (counts['comment'] || 0) + changed;
        if (report.length < opts.maxReportEntries) report.push({ path: '$.comments', key: 'content', rule: 'comment', preview: changed + ' comment(s)', replacement: '[comment removed]' });
      }
    }

    // Iterative walk (no recursion → no stack overflow on deep exports).
    const stack = [{ node: data, path: '$', key: null, parentKey: null, parentPrivate: false }];
    while (stack.length) {
      const { node, path, key, parentKey, parentPrivate } = stack.pop();
      if (node === null || typeof node !== 'object') continue;
      const isArr = Array.isArray(node);
      const priv = !isArr && opts.privateFlags && hasPrivateFlag(node);
      const keys = isArr ? node.map((_, i) => i) : Object.keys(node);
      for (const k of keys) {
        const v = node[k];
        const childPath = isArr ? path + '[' + k + ']' : path + '.' + k;
        if (v && typeof v === 'object') {
          stack.push({ node: v, path: childPath, key: isArr ? key : k, parentKey: isArr ? parentKey : key, parentPrivate: priv });
          continue;
        }
        if (typeof v !== 'string' || v === '') continue;
        if (isProtectedValue(v)) continue;

        let nv = v;
        const effKey = isArr ? key : k;           // key the string is semantically under
        const effParent = isArr ? parentKey : key;

        // Rule: API Connector private value.
        if (opts.privateFlags && (priv || parentPrivate) && VALUE_KEYS.includes(String(k))) {
          nv = redactWhole(v, 'private-flag', childPath, String(k));
        }
        // Rule: secret-looking key name (own key, or parent key for {key:{value}} shapes).
        else if (opts.keyNames && (keyIsSecret(effKey) || (VALUE_KEYS.includes(String(k)) && keyIsSecret(effParent)))) {
          if (!URL_ONLY.test(v) || /secret|key|token|password/i.test(v)) {
            nv = redactWhole(v, 'key-name', childPath, String(effKey));
          }
        }
        if (nv === v) nv = redactPatterns(v, childPath, String(effKey));

        if (nv === v && opts.entropyScan && looksHighEntropy(v)) {
          if (opts.redactEntropy) {
            nv = redactWhole(v, 'high-entropy', childPath, String(effKey));
          } else if (review.length < opts.maxReportEntries) {
            review.push({ path: childPath, key: String(effKey), preview: preview(v) });
          }
        }
        if (nv !== v) node[k] = nv;
      }
    }

    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    return { data, report, review, counts, total, options: opts };
  }

  // Serialize preserving the input's formatting style (compact vs pretty).
  function stringify(data, originalText) {
    const pretty = typeof originalText === 'string' && /^\s*[{[]\s*\n/.test(originalText);
    return pretty ? JSON.stringify(data, null, 2) : JSON.stringify(data);
  }

  // Second pass: assert nothing from the report's originals survived.
  // We do not keep originals, so instead we re-run the detector on the output
  // and expect zero new findings (idempotence check).
  function verify(outputText, options) {
    const r = sanitize(outputText, Object.assign({}, options, { entropyScan: false }));
    return { clean: r.total === 0, findings: r.report };
  }

  return { sanitize, stringify, verify, isProtectedValue, DEFAULT_OPTIONS, FORMAT_RULES, SECRET_KEY_RE, version: '1.0.0' };
});
