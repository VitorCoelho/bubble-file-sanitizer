#!/usr/bin/env node
/* Builds dist/bubble-sanitizer.html: the page with the engine inlined, so it
 * can be opened directly from disk (file://) with no server and no extra files.
 * Run: node build.js
 */
'use strict';
const fs = require('fs');
const path = require('path');
const root = __dirname;
const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
const js = fs.readFileSync(path.join(root, 'src', 'sanitizer.js'), 'utf8');
const tag = '<script src="src/sanitizer.js"></script>';
if (!html.includes(tag)) throw new Error('script tag not found in index.html');
const inlined = '<script>\n' + js.replace(/<\/script/gi, '<\\/script') + '\n</script>';
const out = html.replace(tag, () => inlined); // function form: no "$&" substitution surprises
fs.mkdirSync(path.join(root, 'dist'), { recursive: true });
fs.writeFileSync(path.join(root, 'dist', 'bubble-sanitizer.html'), out);
console.log('dist/bubble-sanitizer.html written (' + out.length + ' bytes)');
