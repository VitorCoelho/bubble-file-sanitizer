#!/usr/bin/env node
/* Test suite for bubble-sanitizer. Run: node test/run.js */
'use strict';
const assert = require('assert');
const path = require('path');
const S = require(path.join(__dirname, '..', 'src', 'sanitizer.js'));

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log('  ✓ ' + name); }
  catch (e) { failed++; console.log('  ✗ ' + name + '\n      ' + (e && e.message)); }
}

// ---------------------------------------------------------------------------
// Fixture: a synthetic, Bubble-shaped export with secrets in every place we
// know of, plus plenty of values that MUST survive untouched.
// ---------------------------------------------------------------------------
// Synthetic secrets, assembled at runtime so no literal in this file matches a
// real-world key format (GitHub push protection and other scanners would flag
// them). They still match our rules once concatenated.
const J = function () { return Array.prototype.join.call(arguments, ''); };
const SECRETS = {
  stripeLive: J('sk_', 'live_', '51FAKE00000000009ZabcDEFghIJklMNopQRstUVwxYZ0123456789'),
  stripeTest: J('sk_', 'test_', '51FAKE0000000000TESTabcDEFghIJklMNopQRstUVwxYZ01234567'),
  stripePub:  J('pk_', 'live_', '51FAKE0000000000PUBabcDEFghIJklMNopQRstUVwxYZ012345678'),
  whsec:      J('whsec_', '9f8e7d6c5b4a39281716151413121110abcdef'),
  twilioSid:  J('AC', '00000000111111112222222233333333'),
  twilioTok:  J('3f2a1b0c9d8e7f6a', '5b4c3d2e1f0a9b8c'),
  verifySid:  J('VA', '0123456789abcdef0123456789abcdef'),
  mailgun:    J('key-', '0123456789abcdef0123456789abcdef'),
  google:     J('AIza', 'SyD-1234567890abcdefghijklmnopqrstuv'),
  aws:        J('AKIA', 'IOSFODNN7EXAMPLE'),
  klaviyo:    J('pk_', '0123456789abcdef0123456789abcdef01'),
  jwt:        J('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', '.', 'eyJzdWIiOiIxMjM0NTY3ODkwIn0', '.', 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'),
  basic:      'QUMwMDAwMDAwMDExMTExMTExMjIyMjIyMjIzMzMzMzMzMzozZjJhMWIwYzlkOGU3ZjZhNWI0YzNkMmUxZjBhOWI4Yw==',
  dbUrl:      J('mysql://admin:', 'Sup3rS3cret!', '@db.internal.example:3306/app'),
  connStr:    J('Server=db.internal;Database=app;User Id=sa;', 'Password=', 'P@ssw0rd123;'),
  pem:        J('-----BEGIN RSA PRIVATE KEY-----', '\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn\n', '-----END RSA PRIVATE KEY-----'),
  dataApi:    J('c0ffee00c0ffee00', 'c0ffee00c0ffee00'),
  email1:     'jane.doe@company-domain.com',
  email2:     'Someone.Else@Gmail.com',
  phone1:     '+15145550142',
  phone2:     '(514) 555-0142',
  ip:         '203.0.113.42',
  openai:     J('sk-', 'proj-', 'abcdefghijklmnopqrstuvwxyz0123456789ABCD'),
  subId:      J('sub_', '1FAKE000000000000TESTsub0'),
  custId:     J('cus_', 'FAKE0000TEST01'),
  pluginTok:  J('0a1b2c3d4e5f6071', '8291a3b4c5d6e7f0'),
  pluginSec:  J('Qw3Rt7Yu1Io5Pa9S', 'Dd2Ff6Gg0Hh4Jj8K'),
  sqlName:    'Alice Example',
  sampleName: 'ACME TEST CUSTOMER',
  comment:    'Internal note mentioning a colleague by name'
};

const KEEP = {
  thingId: '1700000000000x100000000000000001',
  elemId: 'bQZPk',
  pluginElem: '1600000000000x100000000000000003-AAC',
  apiCallType: 'apiconnector2-1700000000000x100000000000000001.1700000000001x100000000000000002',
  date: '2026-11-18T16:52:44.702Z',
  color: 'rgba(10,20,30,1)',
  hex: '#3366CC',
  url: 'https://verify.twilio.com/v2/Services/[svc-id]/Verifications',
  version: '1.8.2',
  style: '100px 200px 300px',
  priceId: 'prod_FAKE00TESTprod',
  fieldName: 'phone_code_text',
  tokenType: 'Bearer',
  authType: 'private_key_in_header',
  exampleMail: 'noreply@example.com',
  text: 'Enter the 6-digit code we texted you',
  appName: 'sampleapp'
};

function fixture() {
  return {
    settings: {
      client_safe: {
        appname: KEEP.appName,
        domain: 'app.example.com',
        stripe_pk: SECRETS.stripePub,
        authentication: { email: { use_email: true } },
        apiconnector2: {
        stripe: { calls: { s1: { name: 'Get customer', url: 'https://api.stripe.com/v1/customers',
          types: JSON.stringify({ 't1': { caption: 'Get customer', fields: { _api_c2_id: { ret_btype: 'text', sample_value: SECRETS.custId, path: ['id'] }, _api_c2_name: { ret_btype: 'text', sample_value: SECRETS.sampleName, path: ['name'] }, _api_c2_n: { ret_btype: 'number', sample_value: 42, path: ['n'] } } } }),
          params: { q1: { key: 'subscription', value: SECRETS.subId, private: false } } } } },
        },
        dbconnector_queries: JSON.stringify({ q1: { name: 'seed_data', text: "INSERT INTO `people` VALUES (1,'"+SECRETS.sqlName+"','x@y.com','fr'),(2,'Other','a@b.co','de');\nINSERT INTO notes (title, owner) VALUES (?, ?);" }, q2: { name: 'login-check', text: 'SELECT id FROM accounts WHERE email = ? AND pass_hash = ?;' } }),
        '1600000000001x100000000000000006_header_AHJ': 'Xq7Lp2Wm9Z',
        '1700000000002x100000000000000004_appid': 'api'
      },
      stripe_sk_live: SECRETS.stripeLive,
      stripe_sk_test: SECRETS.stripeTest,
      api_tokens: [{ name: 'Backend token', token: SECRETS.dataApi, created: KEEP.date }],
      sendgrid: { api_key: SECRETS.google, from: SECRETS.email1 },
      sql: { connection_string: SECRETS.connStr, alt: SECRETS.dbUrl },
      plugins: {
        '1700000000002x100000000000000004': { api_key: SECRETS.mailgun, domain: 'mg.example.com' },
        twilio: { account_sid: SECRETS.twilioSid, auth_token: SECRETS.twilioTok }
      },
      google: { private_key: SECRETS.pem, client_email: 'svc@project.iam.gserviceaccount.com' },
      secure: {
        username: 'svc', password: 'svcpass1', cXa: KEEP.thingId, cXb: '1', oauth_login_page: 'bQXRm',
        '1400000000000x100000000000000007_ADt': SECRETS.twilioSid,
        '1400000000000x100000000000000007_ADu': SECRETS.pluginTok,
        '1400000000000x100000000000000007_AEM': SECRETS.pluginSec,
        apiconnector2: { bQXRv: { username: 'api', password: 'mgpass', calls: { c1: { url_params: { p1: { key: 'account-sid-param', value: SECRETS.twilioSid } } } } } },
        general_keys: { has_valid_algolia: 'False' }
      },
    },
    apiconnector2: {
      collections: {

        [KEEP.thingId]: {
          name: 'SMS provider',
          auth_type: KEEP.authType,
          shared_headers: [
            { key: 'Authorization', value: 'Basic ' + SECRETS.basic, private: true },
            { key: 'Content-Type', value: 'application/x-www-form-urlencoded', private: false }
          ],
          shared_parameters: [{ key: 'svc-id', value: SECRETS.verifySid, private: true }],
          calls: [{
            id: '1700000000001x100000000000000002',
            name: 'Send code',
            url: KEEP.url,
            method: 'POST',
            parameters: [
              { key: 'To', value: SECRETS.phone1, private: false },
              { key: 'Channel', value: 'sms', private: false }
            ],
            initialized_response: '{"to":"' + SECRETS.phone1 + '","sid":"VE0123456789abcdef0123456789abcdef","status":"pending"}',
            token_type: KEEP.tokenType
          }]
        },
        '1700000000003x100000000000000005': {
          name: 'Email provider',
          shared_headers: [{ key: 'Authorization', value: 'Klaviyo-API-Key ' + SECRETS.klaviyo, private: true }],
          calls: [{ name: 'Update contact', url: 'https://a.klaviyo.com/api/profiles/?api_key=' + SECRETS.klaviyo + '&v=1' }]
        },
        'openai': { shared_headers: [{ key: 'Authorization', value: 'Bearer ' + SECRETS.openai, private: true }] }
      }
    },
    pages: {
      [KEEP.elemId]: {
        type: 'Page', name: 'index', id: KEEP.elemId,
        elements: {
          [KEEP.pluginElem]: { type: KEEP.pluginElem, properties: { color: KEEP.color, bg: KEEP.hex, text: KEEP.text, width: KEEP.style } },
          contact: { properties: { text: 'Call us at ' + SECRETS.phone2 + ' or ' + SECRETS.email2, placeholder: KEEP.exampleMail } },
          jwtdemo: { properties: { default: SECRETS.jwt } }
        },
        workflows: { 'bQRsT0': { properties: { element_id: 'bQKBy' }, type: 'ButtonClicked', id: 'bQKCP',
          actions: [{ type: KEEP.apiCallType, properties: { 'Code': '123456', server_ip: SECRETS.ip } }] } }
      }
    },
    user_types: {
      user: { fields: { [KEEP.fieldName]: { type: 'text', display: 'phone code' }, 'price_field': { type: 'text', default_value: KEEP.priceId } } },
      user_details: { fields: { 'subscription_field': { type: 'text', sample: KEEP.priceId } } }
    },
    meta: { exported: KEEP.date, version: KEEP.version, aws_access_key_id: SECRETS.aws },
    comments: { user: { type: 'CustomType', content: SECRETS.comment, comments: { r1: { type: 'PrivacyRole', content: 'another note', parent: 'user' } } } }
  };
}

console.log('bubble-sanitizer tests\n');

const original = fixture();
const originalText = JSON.stringify(original);
const res = S.sanitize(originalText);
const outText = S.stringify(res.data, originalText);

test('parses and returns a result object', () => {
  assert.ok(res.data && typeof res.data === 'object');
  assert.ok(Array.isArray(res.report));
  assert.ok(res.total > 0);
});

test('no secret value survives in the output', () => {
  for (const [name, val] of Object.entries(SECRETS)) {
    const needle = name === 'pem' ? 'MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn' : val;
    assert.ok(!outText.includes(needle), 'secret still present: ' + name);
  }
});

test('secret fragments do not survive (case-insensitive, partial)', () => {
  const frags = ['Sup3rS3cret', 'P@ssw0rd123', '3f2a1b0c9d8e7f6a', 'c0ffee00c0ffee00', 'jane.doe', 'Someone.Else', '555-0142', '5145550142', '203.0.113'];
  for (const f of frags) assert.ok(!outText.toLowerCase().includes(f.toLowerCase()), 'fragment still present: ' + f);
});

test('every protected / non-secret value is untouched', () => {
  for (const [name, val] of Object.entries(KEEP)) assert.ok(outText.includes(val), 'value lost: ' + name);
});

test('object keys and structure are preserved exactly', () => {
  function shape(o) {
    if (Array.isArray(o)) return o.map(shape);
    if (o && typeof o === 'object') { const r = {}; for (const k of Object.keys(o)) r[k] = shape(o[k]); return r; }
    return typeof o;
  }
  assert.deepStrictEqual(shape(res.data), shape(original));
});

test('numbers, booleans and nulls are never changed', () => {
  const inp = { a: 1700000000000, b: true, c: null, d: [1, 2.5, false], secret: 42, token: true };
  const r = S.sanitize(JSON.stringify(inp));
  assert.deepStrictEqual(r.data, inp);
  assert.strictEqual(r.total, 0);
});

test('input object is not mutated', () => {
  const o = fixture();
  const before = JSON.stringify(o);
  S.sanitize(o);
  assert.strictEqual(JSON.stringify(o), before);
});

test('same secret maps to the same placeholder within a run', () => {
  const inp = { a: { api_key: SECRETS.mailgun }, b: { text: 'key is ' + SECRETS.mailgun } };
  const r = S.sanitize(JSON.stringify(inp));
  const p = r.data.a.api_key;
  assert.ok(/^\[REDACTED:/.test(p));
  assert.strictEqual(r.data.b.text, 'key is ' + p.replace('key-name', 'mailgun-key'));
});

test('placeholders differ between runs (random salt)', () => {
  const inp = { api_key: SECRETS.mailgun };
  const a = S.sanitize(JSON.stringify(inp)).data.api_key;
  const b = S.sanitize(JSON.stringify(inp)).data.api_key;
  assert.notStrictEqual(a, b);
});

test('email / phone / ip placeholders are consistent and anonymous', () => {
  const inp = { a: SECRETS.email1, b: SECRETS.email1.toUpperCase(), c: SECRETS.phone1, d: SECRETS.phone1, e: SECRETS.ip };
  const r = S.sanitize(JSON.stringify(inp));
  assert.strictEqual(r.data.a, 'user1@example.com');
  assert.strictEqual(r.data.b, 'user1@example.com');
  assert.strictEqual(r.data.c, '+10000000001');
  assert.strictEqual(r.data.d, '+10000000001');
  assert.strictEqual(r.data.e, '0.0.0.1');
});

test('keepEmailDomains keeps allow-listed domains only', () => {
  const inp = { a: 'ops@mycompany.com', b: 'me@sub.mycompany.com', c: 'x@other.com' };
  const r = S.sanitize(JSON.stringify(inp), { keepEmailDomains: ['mycompany.com'] });
  assert.strictEqual(r.data.a, 'ops@mycompany.com');
  assert.strictEqual(r.data.b, 'me@sub.mycompany.com');
  assert.strictEqual(r.data.c, 'user1@example.com');
});

test('report never contains the secret itself', () => {
  const dump = JSON.stringify(res.report) + JSON.stringify(res.review);
  for (const [name, val] of Object.entries(SECRETS)) {
    const needle = name === 'pem' ? 'MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn' : val;
    assert.ok(!dump.includes(needle), 'report leaks: ' + name);
  }
});

test('report entries carry path, key, rule and a shape-only preview', () => {
  const e = res.report.find(x => x.rule === 'stripe-secret' || (x.rule === 'key-name' && /stripe_sk/.test(x.key)));
  assert.ok(e, 'no stripe entry');
  assert.ok(e.path.startsWith('$.'));
  assert.ok(/•/.test(e.preview));
});

test('API Connector private:true values are redacted even under innocent key names', () => {
  const inp = { parameters: [{ key: 'X-Custom', value: 'plainlookingvalue', private: true }, { key: 'Y', value: 'keepme', private: false }] };
  const r = S.sanitize(JSON.stringify(inp));
  assert.ok(/^\[REDACTED:private-flag:/.test(r.data.parameters[0].value));
  assert.strictEqual(r.data.parameters[1].value, 'keepme');
});

test('{secret_key: {value: …}} nested shape is caught', () => {
  const inp = { api_key: { value: 'abc123def456', label: 'API key' } };
  const r = S.sanitize(JSON.stringify(inp));
  assert.ok(/^\[REDACTED:/.test(r.data.api_key.value));
  assert.strictEqual(r.data.api_key.label, 'API key');
});

test('allow-listed key names are not treated as secrets', () => {
  const inp = { token_type: 'Bearer', auth_type: 'oauth2', api_key_name: 'X-Api-Key', scope: 'read write', private: 'yes' };
  const r = S.sanitize(JSON.stringify(inp));
  assert.deepStrictEqual(r.data, inp);
});

test('Bubble ids are protected even under secret key names', () => {
  const inp = { token: KEEP.thingId, secret: KEEP.elemId, password: KEEP.pluginElem };
  const r = S.sanitize(JSON.stringify(inp));
  assert.deepStrictEqual(r.data, inp);
});

test('sanitizing is idempotent (second pass changes nothing)', () => {
  const second = S.sanitize(outText);
  assert.strictEqual(second.total, 0, 'second pass found ' + second.total + ' more: ' + JSON.stringify(second.report.slice(0, 3)));
  assert.strictEqual(S.stringify(second.data, outText), outText);
});

test('verify() reports the output as clean', () => {
  const v = S.verify(outText);
  assert.strictEqual(v.clean, true, JSON.stringify(v.findings.slice(0, 3)));
});

test('verify() flags an unsanitized file', () => {
  assert.strictEqual(S.verify(originalText).clean, false);
});

test('entropy scan lists high-entropy strings for review (but does not redact by default)', () => {
  const blob = J('Zk9x2Qp7Lm4Rt8', 'Wv1Yb6Nc3Hs5Jd0Fg');
  const r = S.sanitize(JSON.stringify({ note: blob }));
  assert.strictEqual(r.data.note, blob);
  assert.ok(r.review.some(x => x.path === '$.note'));
  const r2 = S.sanitize(JSON.stringify({ note: blob }), { redactEntropy: true });
  assert.ok(/^\[REDACTED:high-entropy:/.test(r2.data.note));
});

test('entropy scan ignores Bubble ids, URLs and data URIs', () => {
  const r = S.sanitize(JSON.stringify({ a: KEEP.thingId, b: KEEP.apiCallType, c: 'https://x.example/a/b/c', d: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ' }));
  assert.strictEqual(r.review.length, 0);
});

test('handles UTF-8 BOM and pretty-printed input, preserving style', () => {
  const pretty = '﻿' + JSON.stringify({ api_key: 'abcd1234efgh', ok: 1 }, null, 2);
  const r = S.sanitize(pretty);
  const out = S.stringify(r.data, pretty.slice(1));
  assert.ok(out.includes('\n  "ok": 1'));
});

test('optional rules can be switched off', () => {
  const inp = { text: 'mail me at ' + SECRETS.email2 + ' / ' + SECRETS.phone1, pk: SECRETS.stripePub, sid: SECRETS.twilioSid };
  const r = S.sanitize(JSON.stringify(inp), { emails: false, phones: false, publishable: false, sids: false });
  assert.strictEqual(r.data.text, inp.text);
  assert.strictEqual(r.data.pk, inp.pk);
  assert.strictEqual(r.data.sid, inp.sid);
});

test('does not mangle ordinary text, dates, CSS and expressions', () => {
  const inp = {
    t1: 'Your subscription renews on 2026-12-25.', t2: 'Order #1024 of 2000 shipped', t3: 'margin: 10px 20px 30px',
    t4: 'Search for Users:count', t5: '2026-11-18T16:52:44.702Z', t6: 'v1.2.3', t7: 'Step 2 of 4', t8: '12.5%'
  };
  const r = S.sanitize(JSON.stringify(inp));
  assert.deepStrictEqual(r.data, inp);
  assert.strictEqual(r.total, 0);
});

test('deeply nested input does not overflow the stack', () => {
  let o = { api_key: 'deepsecret123456' };
  for (let i = 0; i < 20000; i++) o = { child: o };
  const r = S.sanitize(o);
  assert.strictEqual(r.total, 1);
});


test('settings.secure: everything is redacted, including plugin keys under opaque names', () => {
  const sec = res.data.settings.secure;
  assert.ok(/^\[REDACTED:secure-settings:/.test(sec['1400000000000x100000000000000007_ADu']));
  assert.ok(/^\[REDACTED:secure-settings:/.test(sec['1400000000000x100000000000000007_AEM']));
  assert.ok(/^\[REDACTED:/.test(sec.password));
  assert.ok(/^\[REDACTED:/.test(sec.apiconnector2.bQXRv.password));
  assert.ok(/^\[REDACTED:/.test(sec.apiconnector2.bQXRv.calls.c1.url_params.p1.value));
  assert.strictEqual(sec.apiconnector2.bQXRv.calls.c1.url_params.p1.key, 'account-sid-param'); // labels kept
  assert.strictEqual(sec.cXa, KEEP.thingId);
  assert.strictEqual(sec.cXb, '1');
  assert.strictEqual(sec.oauth_login_page, 'bQXRm');
  assert.strictEqual(sec.general_keys.has_valid_algolia, 'False');
});

test('client_safe plugin settings are redacted unless trivial', () => {
  const cs = res.data.settings.client_safe;
  assert.ok(/^\[REDACTED:plugin-setting:/.test(cs['1600000000001x100000000000000006_header_AHJ']));
  assert.strictEqual(cs['1700000000002x100000000000000004_appid'], 'api');
});

test('API Connector sample values are replaced with "string value", numbers kept', () => {
  const call = res.data.settings.client_safe.apiconnector2.stripe.calls.s1;
  const t = JSON.parse(call.types).t1.fields;
  assert.strictEqual(t._api_c2_id.sample_value, 'string value');
  assert.strictEqual(t._api_c2_name.sample_value, 'string value');
  assert.strictEqual(t._api_c2_n.sample_value, 42);
  assert.deepStrictEqual(t._api_c2_id.path, ['id']);
  assert.ok(res.counts['sample-value'] >= 2);
});

test('Stripe customer-level ids are redacted, catalog ids kept', () => {
  const call = res.data.settings.client_safe.apiconnector2.stripe.calls.s1;
  assert.ok(/^\[REDACTED:(stripe-object-id|param-value):/.test(call.params.q1.value));
  const r2 = S.sanitize(JSON.stringify({ note: 'customer ' + SECRETS.custId + ' on ' + KEEP.priceId }));
  assert.ok(/^customer \[REDACTED:stripe-object-id:[0-9a-f]+\] on prod_FAKE00TESTprod$/.test(r2.data.note));
  assert.ok(outText.includes(KEEP.priceId));
});

test('SQL literal rows are removed, parameterised statements untouched', () => {
  const q = JSON.parse(res.data.settings.client_safe.dbconnector_queries);
  assert.ok(q.q1.text.includes('INSERT INTO `people` VALUES (/* rows removed by sanitizer */);'));
  assert.ok(q.q1.text.includes('INSERT INTO notes (title, owner) VALUES (?, ?);'));
  assert.strictEqual(q.q2.text, 'SELECT id FROM accounts WHERE email = ? AND pass_hash = ?;');
});

test('connection-string password rule skips SQL parameter markers', () => {
  const r = S.sanitize(JSON.stringify({ a: 'password = ?', b: 'pwd=:pwd', c: 'Password=@p1', d: 'password=realpass;' }));
  assert.strictEqual(r.data.a, 'password = ?');
  assert.strictEqual(r.data.b, 'pwd=:pwd');
  assert.strictEqual(r.data.c, 'Password=@p1');
  assert.ok(/^password=\[REDACTED:conn-string-pwd:[0-9a-f]+\];$/.test(r.data.d));
});

test('editor comments are blanked', () => {
  assert.strictEqual(res.data.comments.user.content, '[comment removed]');
  assert.strictEqual(res.data.comments.user.comments.r1.content, '[comment removed]');
  assert.strictEqual(res.data.comments.user.comments.r1.parent, 'user');
});

test('short passwords are not mistaken for Bubble editor ids', () => {
  const r = S.sanitize(JSON.stringify({ password: 'hunter2', token: 'abcdefg', id: 'bQZPk', id2: 'bQRsT0', id3: 'AAa' }));
  assert.ok(/^\[REDACTED:/.test(r.data.password));
  assert.ok(/^\[REDACTED:/.test(r.data.token));
  assert.strictEqual(r.data.id, 'bQZPk'); assert.strictEqual(r.data.id2, 'bQRsT0'); assert.strictEqual(r.data.id3, 'AAa');
});

test('structure rules can be switched off', () => {
  const r = S.sanitize(originalText, { secureSettings: false, pluginKeys: false, sampleValues: false, sqlRows: false, comments: false, stripeIds: false, formats: false, keyNames: false, sids: false });
  assert.strictEqual(r.data.comments.user.content, SECRETS.comment);
  assert.strictEqual(r.data.settings.client_safe['1600000000001x100000000000000006_header_AHJ'], 'Xq7Lp2Wm9Z');
});


test('API Connector param test values: real data redacted, config-like values kept', () => {
  const inp = { settings: { client_safe: { apiconnector2: { c: { calls: { k: { params: {
    a: { key: 'customer', value: J('cus_', 'FAKE0000TEST02'), private: false },
    b: { key: 'proration_behavior', value: 'always_invoice', private: false },
    c: { key: 'quantity', value: '2', private: false },
    d: { key: 'success_url', value: 'https://portal.example.com/checkout?step=3&flow_type=gift', private: false },
    e: { key: 'To', value: '5500000000000', private: false },
    f: { key: 'name', value: 'Alice', private: false },
    g: { key: 'applies_to[products][0]', value: 'prod_FAKE00TESTprd2', private: false }
  } } } } } } } };
  const r = S.sanitize(JSON.stringify(inp));
  const p = r.data.settings.client_safe.apiconnector2.c.calls.k.params;
  assert.ok(/^\[REDACTED:param-value:/.test(p.a.value));
  assert.strictEqual(p.b.value, 'always_invoice');
  assert.strictEqual(p.c.value, '2');
  assert.strictEqual(p.d.value, 'https://portal.example.com/checkout?step=3&flow_type=gift');
  assert.ok(/^\[REDACTED:param-value:/.test(p.e.value));
  assert.ok(/^\[REDACTED:param-value:/.test(p.f.value));
  assert.strictEqual(p.g.value, 'prod_FAKE00TESTprd2');
});

test('SQL query param test values are replaced (JSON and Python-repr forms)', () => {
  const inp = { settings: { client_safe: { dbconnector_queries: JSON.stringify({
    q1: { name: 'x', text: 'SELECT 1', params: "[{'name': 'contact_name', 'type': 'text', 'test_value': 'Alice Example'}, {'name': 'n', 'type': 'number', 'test_value': '7'}]" },
    q2: { name: 'y', text: 'SELECT 1', params: '[{"name":"email","type":"text","test_value":"someone@corp.io"}]' }
  }) } } };
  const r = S.sanitize(JSON.stringify(inp));
  const q = JSON.parse(r.data.settings.client_safe.dbconnector_queries);
  assert.ok(q.q1.params.includes("'test_value': 'string value'"));
  assert.ok(q.q1.params.includes("'test_value': '7'"));
  assert.ok(q.q2.params.includes('"test_value":"string value"'));
  assert.ok(!JSON.stringify(r.data).includes('Alice Example'));
});

test('tracking ids in header scripts are redacted', () => {
  const inp = { settings: { client_safe: { custom_header_meta_tag_content: "<meta name=\"site-verification\" content=\"abcdefgh0123verify\"><script>gtag('config','G-ABCD1234EF');</script><script>x('GTM-ABCD1234')</script><script>s.src='https://pixel.example.net/track.js?pixel_id=0123456789abcdef0123456789abcdef&tag=!clicked'</script><script>fbq('init', '1234567890123456');</script><script>(window, document, \"clarity\", \"script\", \"abcd1234ef\");</script>" } } };
  const r = S.sanitize(JSON.stringify(inp));
  const h = r.data.settings.client_safe.custom_header_meta_tag_content;
  for (const t of ['G-ABCD1234EF', 'GTM-ABCD1234', '0123456789abcdef0123456789abcdef', '1234567890123456', 'abcd1234ef', 'abcdefgh0123']) assert.ok(!h.includes(t), 'left: ' + t);
  assert.ok(h.includes("fbq('init', '[REDACTED:tracking-id:"));
  assert.ok(h.includes('&tag=!clicked'));
  const r2 = S.sanitize(JSON.stringify({ t: 'G-SHOCK watch, AW-2 model' }));
  assert.strictEqual(r2.data.t, 'G-SHOCK watch, AW-2 model');
});

test('custom words are redacted everywhere, whole-word, case-insensitive', () => {
  const r = S.sanitize(JSON.stringify({ a: 'Alice Example <x>', b: 'alice fixing 6 users', c: 'Alicante is a city', d: 'BOB requested it' }), { customWords: ['Alice', 'Bob'], emails: false });
  assert.ok(/^\[REDACTED:custom-word:[0-9a-f]+\] Example <x>$/.test(r.data.a));
  assert.ok(/^\[REDACTED:custom-word:[0-9a-f]+\] fixing 6 users$/.test(r.data.b));
  assert.strictEqual(r.data.a.split(' ')[0], r.data.b.split(' ')[0]); // same placeholder regardless of case
  assert.strictEqual(r.data.c, 'Alicante is a city');
  assert.ok(/^\[REDACTED:custom-word:/.test(r.data.d));
});

test('bare-digit phone numbers, authenticator secrets, Stripe links and pixel ids are redacted', () => {
  const inp = {
    from: '15145550142', from_uk: '447700900123', ts: '1700000000123', last_change: '10000000042', small: '12345678',
    totp: J('JBSWY3DPEHPK3PXP', 'JBSWY3DPEHPK3PXP'), word: 'CONFIRMATIONCODES',
    link: 'https://buy.stripe.com/' + J('test_', 'aBc123dEf456gHi789'), bare: J('test_', 'aBc123dEf456gHi789jK'), portal: 'https://billing.stripe.com/p/login/' + J('test_', 'zz11yy22xx33ww'),
    px: '<img src="https://www.facebook.com/tr?id=' + J('123456', '789012345') + '&ev=PageView">'
  };
  const r = S.sanitize(JSON.stringify(inp)).data;
  assert.ok(/^\+1000000\d{4}$/.test(r.from), r.from);
  assert.ok(/^\+1000000\d{4}$/.test(r.from_uk), r.from_uk);
  assert.strictEqual(r.ts, '1700000000123');
  assert.strictEqual(r.last_change, '10000000042');
  assert.strictEqual(r.small, '12345678');
  assert.ok(/^\[REDACTED:totp-secret:/.test(r.totp));
  assert.strictEqual(r.word, 'CONFIRMATIONCODES');
  assert.ok(/^https:\/\/buy\.stripe\.com\/\[REDACTED:stripe-link:/.test(r.link));
  assert.ok(/^\[REDACTED:stripe-link:/.test(r.bare));
  assert.ok(/\/p\/login\/\[REDACTED:stripe-link:/.test(r.portal));
  assert.ok(/tr\?id=\[REDACTED:tracking-id:[0-9a-f]+\]&ev=PageView/.test(r.px), r.px);
});

test('SQL query params given as an array of objects are replaced too', () => {
  const inp = { settings: { client_safe: { dbconnector_queries: JSON.stringify({
    q1: { name: 'x', text: 'SELECT 1', params: [{ name: 'contact_name', type: 'text', test_value: 'Alice Example' }, { name: 'n', type: 'number', test_value: '7' }] }
  }) } } };
  const q = JSON.parse(S.sanitize(JSON.stringify(inp)).data.settings.client_safe.dbconnector_queries);
  assert.strictEqual(q.q1.params[0].test_value, 'string value');
  assert.strictEqual(q.q1.params[1].test_value, '7');
});

test('settings.secure: short credential values are redacted even when they look trivial', () => {
  const r = S.sanitize(JSON.stringify({ settings: { secure: { username: 'svc', flag: 'yes', apiconnector2: { c: { calls: { k: { body_params: { p: { key: 'campaign', value: '12345' } } } } } } } } }));
  const sec = r.data.settings.secure;
  assert.ok(/^\[REDACTED:secure-settings:/.test(sec.username));
  assert.strictEqual(sec.flag, 'yes');
});

console.log('\n' + passed + ' passed, ' + failed + ' failed');
process.exit(failed ? 1 : 0);
