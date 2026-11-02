// WAVE-style checks. Evaluated in the page by scan.py (Playwright); returns {category: {ruleId: [instances]}}.
// Rule IDs, categories and WCAG mapping come from references/wave-rule-catalog.json.
(() => {
  const CAT = {};
  const cat = (n) => CAT[n] || (CAT[n] = {});
  const add = (type, id, el, extra) => {
    const c = cat(type);
    (c[id] = c[id] || []).push({
      sel: el ? sel(el) : null,
      html: el && el.outerHTML ? el.outerHTML.replace(/\s+/g, ' ').slice(0, 140) : null,
      ...(extra || {}),
    });
  };
  function sel(el) {
    if (!el || el.nodeType !== 1) return '';
    if (el.id) return el.tagName.toLowerCase() + '#' + el.id;
    let p = [], n = el;
    while (n && n.nodeType === 1 && p.length < 4 && n.tagName !== 'BODY') {
      let i = 1, s = n; while ((s = s.previousElementSibling)) if (s.tagName === n.tagName) i++;
      p.unshift(n.tagName.toLowerCase() + ':nth-of-type(' + i + ')'); n = n.parentElement;
    }
    return p.join(' > ');
  }
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const txt = (el) => (el.textContent || '').replace(/\s+/g, ' ').trim();
  const idText = (ids) => ids.split(/\s+/).map(i => document.getElementById(i)).filter(Boolean).map(txt).join(' ').trim();

  // accessible-name approximation
  function name(el) {
    if (el.hasAttribute('aria-labelledby')) { const t = idText(el.getAttribute('aria-labelledby')); if (t) return t; }
    const al = (el.getAttribute('aria-label') || '').trim(); if (al) return al;
    let t = '';
    (function walk(n) {
      for (const c of n.childNodes) {
        if (c.nodeType === 3) t += c.textContent;
        else if (c.nodeType === 1) {
          if (c.tagName === 'IMG') t += ' ' + (c.getAttribute('alt') || '') + ' ';
          else if (c.tagName === 'INPUT' && c.type === 'image') t += ' ' + (c.getAttribute('alt') || '');
          else walk(c);
        }
      }
    })(el);
    return t.replace(/\s+/g, ' ').trim();
  }

  // ---------- page level
  const title = (document.title || '').trim();
  if (!title || /^(untitled|home|page|document|new page)$/i.test(title)) add('error', 'title_invalid', document.head, { note: 'title="' + title + '"' });
  const lang = document.documentElement.getAttribute('lang');
  if (!lang) add('error', 'language_missing', document.documentElement);
  else if (!/^[a-z]{2,3}(-[a-z0-9]{2,8})*$/i.test(lang)) add('error', 'language_missing', document.documentElement, { note: 'invalid lang=' + lang });
  else add('feature', 'lang', document.documentElement);
  $$('[lang]:not(html)').forEach(e => add('feature', 'lang', e));
  $$('meta[http-equiv="refresh" i]').forEach(e => add('error', 'meta_refresh', e));
  $$('blink').forEach(e => add('error', 'blink', e));
  $$('marquee').forEach(e => add('error', 'marquee', e));
  $$('noscript').forEach(e => add('alert', 'noscript', e));

  // ---------- images
  const imgs = $$('img');
  const mapNames = new Set($$('img[usemap]').map(i => i.getAttribute('usemap').replace('#', '')));
  const SUSP = /^(image|photo|picture|graphic|spacer|icon|logo|img|pic|blank|space|bullet)$|\.(jpe?g|png|gif|svg|bmp)$|^(image|picture|photo|graphic) of\b|^(img|dsc|image)[_-]?\d+/i;
  imgs.forEach((im, i) => {
    const hasAlt = im.hasAttribute('alt'); const alt = (im.getAttribute('alt') || '').trim();
    const a = im.closest('a[href]'); const hasMap = im.hasAttribute('usemap');
    const ariaN = (im.getAttribute('aria-label') || '').trim() || (im.hasAttribute('aria-labelledby') ? idText(im.getAttribute('aria-labelledby')) : '');
    if (hasMap) { hasAlt ? add('feature', 'alt_map', im) : add('error', 'alt_map_missing', im); }
    const rc = im.getBoundingClientRect();
    const spacer = rc.width > 0 && rc.height > 0 && Math.min(rc.width, rc.height) <= 3; // 1px layout images
    if (!hasAlt && !ariaN) {
      if (a && !txt(a)) add('error', 'alt_link_missing', im);
      else if (spacer) add('error', 'alt_spacer_missing', im);
      else add('error', 'alt_missing', im);
      if (im.hasAttribute('title')) add('alert', 'image_title', im);
    } else if (hasAlt && alt === '' && !ariaN) {
      // empty alt on an image that is the only content of a link leaves the link unnamed
      if (a && !txt(a)) add('error', 'alt_link_missing', im);
      else add('feature', spacer ? 'alt_spacer' : 'alt_null', im);
    } else {
      let flagged = false;
      const flag = (id, x) => { flagged = true; add('alert', id, im, x); };
      if (SUSP.test(alt)) flag('alt_suspicious', { alt });
      if (alt.length > 100) flag('alt_long', { alt: alt.slice(0, 60) + '...' });
      const near = [a ? txt(a).replace(alt, '') : '', im.nextSibling && im.nextSibling.textContent || '', im.previousSibling && im.previousSibling.textContent || ''].map(s => s.trim().toLowerCase());
      if (alt && (a ? txt(a).toLowerCase() === alt.toLowerCase() : near.some(s => s === alt.toLowerCase()))) flag('alt_redundant', { alt });
      // duplicate: the very next node (ignoring whitespace) is an image with the same alt
      let nx = im.nextSibling; while (nx && nx.nodeType === 3 && !nx.textContent.trim()) nx = nx.nextSibling;
      if (alt && nx && nx.nodeType === 1 && nx.tagName === 'IMG' && (nx.getAttribute('alt') || '').trim() === alt) flag('alt_duplicate', { alt });
      if (im.hasAttribute('title') && im.getAttribute('title').trim().toLowerCase() === alt.toLowerCase()) add('alert', 'title_redundant', im);
      // WAVE lists an image under Features only when it raised no alert
      if (!flagged) add('feature', a ? 'alt_link' : 'alt', im, { alt });
    }
    if (im.hasAttribute('longdesc')) { add('alert', 'longdesc', im); if (!/^(https?:|\/|\.|[\w-]+\.\w+|#)/.test(im.getAttribute('longdesc'))) add('error', 'longdesc_invalid', im); }
  });
  $$('input[type=image]').forEach(e => (e.getAttribute('alt') || e.getAttribute('aria-label')) ? add('feature', 'alt_input', e) : add('error', 'alt_input_missing', e));
  $$('area').forEach(e => (e.getAttribute('alt') || '').trim() ? add('feature', 'alt_area', e) : add('error', 'alt_area_missing', e));
  $$('figure').forEach(e => add('feature', 'figure', e));

  // ---------- forms
  const ctrls = $$('input:not([type=hidden]):not([type=submit]):not([type=button]):not([type=reset]):not([type=image]), select, textarea');
  ctrls.forEach(c => {
    const labels = c.id ? $$('label[for="' + CSS.escape(c.id) + '"]') : [];
    const wrap = c.closest('label');
    const all = [...labels, ...(wrap && !labels.includes(wrap) ? [wrap] : [])];
    const aria = (c.getAttribute('aria-label') || '').trim() || (c.hasAttribute('aria-labelledby') ? idText(c.getAttribute('aria-labelledby')) : '');
    if (all.length > 1) add('error', 'label_multiple', c);
    if (all.length) {
      if (all.every(l => !txt(l) && !l.querySelector('img[alt]:not([alt=""])'))) add('error', 'label_empty', c);
      else add('feature', 'label', c);
    } else if (aria) add('feature', 'label', c);
    else if (c.getAttribute('title')) add('alert', 'label_title', c);
    else add(c.tagName === 'SELECT' ? 'alert' : 'error', c.tagName === 'SELECT' ? 'select_missing_label' : 'label_missing', c);
  });
  $$('label[for]').forEach(l => { const t = document.getElementById(l.getAttribute('for')); if (!t || !t.matches('input,select,textarea,button,meter,output,progress')) add('alert', 'label_orphaned', l); });
  const groups = {};
  $$('input[type=radio],input[type=checkbox]').forEach(i => { if (i.name) (groups[i.type + ':' + i.name] = groups[i.type + ':' + i.name] || []).push(i); });
  Object.values(groups).forEach(g => { if (g.length > 1 && !g[0].closest('fieldset')) add('alert', 'fieldset_missing', g[0]); });
  $$('fieldset').forEach(f => { add('feature', 'fieldset', f); if (!f.querySelector(':scope > legend')) add('alert', 'legend_missing', f); });
  $$('select[onchange]').forEach(e => /location|href|window\.open/i.test(e.getAttribute('onchange')) && add('alert', 'javascript_jumpmenu', e));

  // ---------- links / buttons
  const SUSL = /^(click here|here|more|read more|link|this|click|more\.\.\.|learn more|continue|details|info)$/i;
  const links = $$('a[href]');
  const redundantSeen = new Set();
  links.forEach((a, i) => {
    const n = name(a);
    // a link containing an image with missing/empty alt is reported once, as alt_link_missing
    if (!n && !a.querySelector('img')) add('error', 'link_empty', a);
    else if (SUSL.test(n)) add('alert', 'link_suspicious', a, { text: n });
    const nx = links[i + 1];
    // consecutive links to the same URL: both are flagged. Links already flagged as suspicious text are skipped (calibrated on one page).
    if (nx && nx.getAttribute('href') === a.getAttribute('href') && !SUSL.test(n) && !SUSL.test(name(nx))) {
      [a, nx].forEach(x => { if (!redundantSeen.has(x)) { redundantSeen.add(x); add('alert', 'link_redundant', x); } });
    }
    const h = a.getAttribute('href') || '';
    if (/\.docx?($|\?)/i.test(h)) add('alert', 'link_word', a);
    else if (/\.xlsx?($|\?)/i.test(h)) add('alert', 'link_excel', a);
    else if (/\.pptx?($|\?)/i.test(h)) add('alert', 'link_powerpoint', a);
    else if (/\.pdf($|\?)/i.test(h)) add('alert', 'link_pdf', a);
    else if (/\.(zip|rtf|odt|txt|csv)($|\?)/i.test(h)) add('alert', 'link_document', a);
    if (/youtube\.com|youtu\.be/.test(h)) add('alert', 'youtube_video', a);
    if (/\.(mp3|mp4|wav|mov|avi|wmv|mpg|swf)($|\?)/i.test(h)) add('alert', 'audio_video', a);
    if (h.startsWith('#') && h.length > 1) {
      const id = decodeURIComponent(h.slice(1));
      const t = document.getElementById(id) || document.getElementsByName(id)[0];
      if (!t) add('alert', 'link_internal_broken', a, { target: h });
    }
  });
  // skip link: same-page link within first few links
  links.slice(0, 5).filter(a => (a.getAttribute('href') || '').startsWith('#') && a.getAttribute('href').length > 1 && /skip|jump|main|content/i.test(txt(a))).forEach(a => {
    add('feature', 'link_skip', a);
    const id = a.getAttribute('href').slice(1); const t = document.getElementById(id) || document.getElementsByName(id)[0];
    t ? add('feature', 'link_skip_target', t) : add('error', 'link_skip_broken', a);
  });
  $$('button, input[type=button], input[type=submit], input[type=reset]').forEach(b => {
    const n = b.tagName === 'BUTTON' ? name(b) : (b.getAttribute('value') || b.getAttribute('aria-label') || '').trim() || (b.type === 'submit' || b.type === 'reset' ? 'x' : '');
    if (!n) add('error', 'button_empty', b);
  });

  // ---------- headings / landmarks / lists / tables
  const heads = $$('h1,h2,h3,h4,h5,h6,[role=heading]');
  let prev = 0;
  heads.forEach(h => {
    const lv = h.getAttribute('aria-level') ? +h.getAttribute('aria-level') : (/^H\d$/.test(h.tagName) ? +h.tagName[1] : 2);
    add('structure', 'h' + lv, h);
    if (!txt(h) && !h.querySelector('img[alt]:not([alt=""])')) add('error', 'heading_empty', h);
    if (prev && lv > prev + 1) add('alert', 'heading_skipped', h, { from: 'h' + prev, to: 'h' + lv });
    prev = lv;
  });
  if (!heads.length) add('alert', 'heading_missing', document.body);
  else if (!heads.some(h => h.tagName === 'H1' || h.getAttribute('aria-level') === '1')) add('alert', 'h1_missing', document.body);
  const LM = [['header', 'header,[role=banner]'], ['nav', 'nav,[role=navigation]'], ['search', '[role=search]'], ['main', 'main,[role=main]'], ['aside', 'aside,[role=complementary]'], ['footer', 'footer,[role=contentinfo]'], ['region', '[role=region]']];
  let lmCount = 0;
  LM.forEach(([id, s]) => $$(s).forEach(e => { add('structure', id, e); lmCount++; }));
  if (!lmCount) add('alert', 'region_missing', document.body);
  $$('ol').forEach(e => add('structure', 'ol', e)); $$('ul').forEach(e => add('structure', 'ul', e)); $$('dl').forEach(e => add('structure', 'dl', e));
  $$('iframe').forEach(e => add('structure', 'iframe', e));
  $$('table').forEach(t => {
    const isLayout = t.getAttribute('role') === 'presentation' || (!t.querySelector('th') && !t.querySelector('caption') && !t.hasAttribute('summary'));
    if (isLayout) add('alert', 'table_layout', t);
    else {
      add('structure', 'table_data', t);
      if (t.querySelector('caption')) add('structure', 'table_caption', t);
    }
    $$('th', t).forEach(th => {
      add('structure', 'th', th);
      if (th.getAttribute('scope') === 'col') add('structure', 'th_col', th);
      if (th.getAttribute('scope') === 'row') add('structure', 'th_row', th);
      if (!txt(th) && !th.querySelector('img[alt]:not([alt=""])')) add('error', 'th_empty', th);
    });
  });
  // possible list: consecutive text lines starting with bullets, or br-separated
  $$('p,div,td').forEach(e => { const t = e.innerText || ''; if (e.children.length < 40 && /(^|\n)\s*([-*•·]|\d+[.)])\s+\S[^\n]*\n\s*([-*•·]|\d+[.)])\s+\S/.test(t) && !e.querySelector('ul,ol')) add('alert', 'list_possible', e); });
  // possible heading: short bold/large text blocks in p/div/span not heading
  $$('p,div,span,b,strong,font').forEach(e => {
    if (e.closest('h1,h2,h3,h4,h5,h6,a,button,label,th,li,nav')) return;
    const t = txt(e); if (!t || t.length > 60 || e.children.length > 1) return;
    const own = [...e.childNodes].some(n => n.nodeType === 3 && n.textContent.trim());
    if (!own) return;
    const cs = getComputedStyle(e); const fs = parseFloat(cs.fontSize);
    if ((fs >= 24 && (e.tagName === 'P' || e.tagName === 'DIV')) || (cs.fontWeight >= 700 || cs.fontWeight === 'bold') && fs >= 16 && (e.tagName === 'P' || e.tagName === 'DIV' || e.tagName === 'B' || e.tagName === 'STRONG') && (e.tagName === 'B' || e.tagName === 'STRONG' ? e.parentElement && txt(e.parentElement) === t : true)) add('alert', 'heading_possible', e, { text: t });
  });

  // ---------- keyboard / misc attributes
  $$('[accesskey]').forEach(e => add('alert', 'accesskey', e));
  $$('[tabindex]').forEach(e => { const v = +e.getAttribute('tabindex'); v > 0 ? add('alert', 'tabindex', e) : add('aria', 'aria_tabindex', e); });
  const EV = ['onmouseover', 'onmouseout', 'onmousedown', 'onmouseup', 'ondblclick', 'onmousemove'];
  $$('*').forEach(e => { if (EV.some(a => e.hasAttribute(a))) add('alert', 'event_handler', e); });
  $$('video,audio').forEach(e => add('alert', 'html5_video_audio', e));
  $$('iframe[src*=youtube],iframe[src*=youtu\\.be]').forEach(e => add('alert', 'youtube_video', e));
  $$('object,embed').forEach(e => /flash|swf/i.test(e.outerHTML) ? add('alert', 'flash', e) : add('alert', 'plugin', e));
  $$('applet').forEach(e => add('alert', 'applet', e));
  $$('[title]').forEach(e => { const t = e.getAttribute('title').trim().toLowerCase(); if (t && e.tagName !== 'IMG' && (txt(e).toLowerCase() === t)) add('alert', 'title_redundant', e); });

  // ---------- ARIA presence + broken refs
  const ariaEls = $$('*').filter(e => [...e.attributes].some(a => a.name === 'role' || a.name.startsWith('aria-')));
  ariaEls.forEach(e => {
    add('aria', 'aria', e);
    if (e.hasAttribute('aria-label') || e.hasAttribute('aria-labelledby')) add('aria', 'aria_label', e);
    if (e.hasAttribute('aria-describedby')) add('aria', 'aria_describedby', e);
    if (e.hasAttribute('aria-expanded')) add('aria', 'aria_expanded', e);
    if (e.hasAttribute('aria-haspopup')) add('aria', 'aria_haspopup', e);
    if (e.getAttribute('aria-hidden') === 'true') add('aria', 'aria_hidden', e);
    if (e.getAttribute('role') === 'button') add('aria', 'aria_button', e);
    if (/^(alert|status|log)$/.test(e.getAttribute('role') || '') || e.hasAttribute('aria-live')) add('aria', 'aria_live_region', e);
    if (/^(menu|menubar)$/.test(e.getAttribute('role') || '')) { add('aria', 'aria_menu', e); if (!e.querySelector('[role^=menuitem]')) add('error', 'aria_menu_broken', e); }
    ['aria-labelledby', 'aria-describedby'].forEach(at => { if (e.hasAttribute(at)) { const ids = e.getAttribute(at).split(/\s+/).filter(Boolean); if (ids.length && !ids.some(i => document.getElementById(i))) add('error', 'aria_reference_broken', e, { attr: at }); } });
  });

  // ---------- text style alerts + contrast
  const parse = (c) => { const m = c.match(/rgba?\(([^)]+)\)/); if (!m) return null; const p = m[1].split(/[,\s/]+/).filter(Boolean).map(Number); return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 }; };
  const over = (f, b) => ({ r: f.r * f.a + b.r * (1 - f.a), g: f.g * f.a + b.g * (1 - f.a), b: f.b * f.a + b.b * (1 - f.a), a: 1 });
  const lum = (c) => { const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
  const ratio = (a, b) => { const l1 = lum(a), l2 = lum(b); return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05); };
  function effBg(el) {
    const stack = []; let n = el, undetermined = false;
    while (n && n.nodeType === 1) {
      const cs = getComputedStyle(n);
      if (cs.backgroundImage && cs.backgroundImage !== 'none') { undetermined = true; break; }
      const bg = parse(cs.backgroundColor);
      if (bg && bg.a > 0) { stack.push(bg); if (bg.a >= 1) break; }
      n = n.parentElement;
    }
    let base = { r: 255, g: 255, b: 255, a: 1 };
    for (let i = stack.length - 1; i >= 0; i--) base = over(stack[i], base);
    return { c: base, undetermined };
  }
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const seen = new Set(); let nContrastChecked = 0, nUndetermined = 0;
  while (walker.nextNode()) {
    const tn = walker.currentNode; if (!tn.textContent.trim()) continue;
    const el = tn.parentElement; if (!el || seen.has(el) || el.closest('script,style,noscript,option')) continue; seen.add(el);
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden') continue;
    const fs = parseFloat(cs.fontSize);
    if (fs < 10) add('alert', 'text_small', el, { size: fs + 'px' });
    if (cs.textAlign === 'justify' && tn.textContent.length > 200) add('alert', 'text_justified', el);
    if (cs.textDecorationLine.includes('underline') && cs.textDecorationStyle !== 'dotted' && !el.closest('a')) add('alert', 'underline', el);
    let op = 1, n = el; while (n && n.nodeType === 1) { op *= parseFloat(getComputedStyle(n).opacity); n = n.parentElement; }
    const { c: bg, undetermined } = effBg(el);
    if (undetermined) { nUndetermined++; continue; }
    let fg = parse(cs.color); if (!fg) continue; fg = { ...fg, a: fg.a * op };
    const f = over(fg, bg); const r = ratio(f, bg);
    const large = fs >= 24 || (fs >= 18.66 && (+cs.fontWeight >= 700));
    const min = large ? 3 : 4.5; nContrastChecked++;
    if (r < min) add('contrast', 'contrast', el, { ratio: +r.toFixed(2), min, fg: cs.color, bg: `rgb(${Math.round(bg.r)},${Math.round(bg.g)},${Math.round(bg.b)})`, size: fs + 'px', text: txt(el).slice(0, 40) });
  }
  // rule IDs this script can emit; scan.py reports the remainder of the catalog as "not implemented"
  const IMPLEMENTED = ['alt_missing', 'alt_link_missing', 'alt_spacer_missing', 'alt_input_missing', 'alt_area_missing', 'alt_map_missing', 'longdesc_invalid',
    'label_missing', 'label_empty', 'label_multiple', 'aria_reference_broken', 'aria_menu_broken', 'title_invalid', 'language_missing', 'meta_refresh',
    'heading_empty', 'button_empty', 'link_empty', 'link_skip_broken', 'th_empty', 'blink', 'marquee', 'contrast',
    'alt_suspicious', 'alt_redundant', 'alt_duplicate', 'alt_long', 'longdesc', 'image_title', 'label_orphaned', 'label_title', 'select_missing_label',
    'fieldset_missing', 'legend_missing', 'heading_missing', 'h1_missing', 'region_missing', 'heading_skipped', 'heading_possible', 'table_layout',
    'list_possible', 'link_internal_broken', 'link_suspicious', 'link_redundant', 'link_word', 'link_excel', 'link_powerpoint', 'link_pdf', 'link_document',
    'audio_video', 'html5_video_audio', 'youtube_video', 'flash', 'applet', 'plugin', 'noscript', 'event_handler', 'javascript_jumpmenu', 'accesskey',
    'tabindex', 'text_small', 'text_justified', 'underline', 'title_redundant',
    'alt', 'alt_null', 'alt_spacer', 'alt_link', 'alt_input', 'alt_map', 'alt_area', 'figure', 'label', 'fieldset', 'link_skip', 'link_skip_target', 'lang',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ol', 'ul', 'dl', 'header', 'nav', 'search', 'main', 'aside', 'footer', 'region', 'table_data', 'table_caption', 'th',
    'th_col', 'th_row', 'iframe',
    'aria', 'aria_label', 'aria_describedby', 'aria_live_region', 'aria_menu', 'aria_button', 'aria_expanded', 'aria_haspopup', 'aria_tabindex', 'aria_hidden'];
  CAT._meta = { implemented: IMPLEMENTED, title, url: location.href, checkedForContrast: nContrastChecked, contrastUndeterminedBgImage: nUndetermined, elements: document.querySelectorAll('*').length };
  return CAT;
})()
