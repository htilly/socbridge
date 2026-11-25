'use strict';
(function () {
  // ---- tiny DOM helpers (textContent only; never innerHTML with data) ----
  function h(tag, attrs) {
    var el = document.createElement(tag);
    var kids = Array.prototype.slice.call(arguments, 2);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v === undefined || v === null || v === false) return;
        if (k === 'class') el.className = v;
        else if (k.slice(0, 2) === 'on') el.addEventListener(k.slice(2), v);
        else if (k === 'value') el.value = v;
        else if (k === 'checked') el.checked = !!v;
        else if (k === 'style') Object.assign(el.style, v); // CSSOM, allowed by the CSP (style attributes are not)
        else el.setAttribute(k, v === true ? '' : String(v));
      });
    }
    kids.flat(Infinity).forEach(function (c) {
      if (c === null || c === undefined || c === false) return;
      el.appendChild(typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c);
    });
    return el;
  }
  // Replace an element's children. Like h(), it flattens arrays and skips
  // null/undefined/false, so conditional children never render as "null".
  function put(el) {
    var kids = Array.prototype.slice.call(arguments, 1).flat(Infinity)
      .filter(function (c) { return c !== null && c !== undefined && c !== false; })
      .map(function (c) { return typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c; });
    el.replaceChildren.apply(el, kids);
  }
  function mount(node) {
    var app = document.getElementById('app');
    put(app, node);
  }
  function fmt(ts) {
    if (!ts) return '—';
    var d = new Date(ts);
    return isNaN(d) ? '—' : d.toLocaleString();
  }
  function notice(kind, text) { return h('div', { class: 'notice ' + kind }, text); }

  // ---- aperture mark: state indicator (closed = signed out, open = live session) ----
  var SVG_NS = 'http://www.w3.org/2000/svg';
  var aperture = (function () {
    var css = getComputedStyle(document.documentElement);
    function token(name, fallback) {
      var v = parseFloat(css.getPropertyValue(name));
      return isNaN(v) ? fallback : v;
    }
    var R = token('--aperture-radius', 44);
    var OPEN = token('--aperture-open', 13);
    var CLOSED = token('--aperture-closed', 0);
    var DURATION = token('--motion-aperture', 700);
    var blade = document.getElementById('aperture-blade');
    var reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
    var current = CLOSED;
    var frame = 0;

    function draw(a) {
      current = a;
      // One blade: M -R -R  L R -R  L R -a  L -a -a  Z, reused at 0/90/180/270 degrees.
      blade.setAttribute('d', 'M ' + -R + ' ' + -R + ' L ' + R + ' ' + -R + ' L ' + R + ' ' + -a + ' L ' + -a + ' ' + -a + ' Z');
    }
    function to(target) {
      cancelAnimationFrame(frame);
      if (reduced.matches || current === target) { draw(target); return Promise.resolve(); }
      var from = current;
      var start = performance.now();
      return new Promise(function (resolve) {
        function step(now) {
          var t = Math.min(1, (now - start) / DURATION);
          var eased = 1 - Math.pow(1 - t, 3);
          draw(from + (target - from) * eased);
          if (t < 1) frame = requestAnimationFrame(step); else resolve();
        }
        frame = requestAnimationFrame(step);
      });
    }
    function mark(size, label) {
      var svg = document.createElementNS(SVG_NS, 'svg');
      svg.setAttribute('class', 'aperture');
      svg.setAttribute('viewBox', [-R, -R, 2 * R, 2 * R].join(' '));
      svg.setAttribute('width', size);
      svg.setAttribute('height', size);
      if (label) { svg.setAttribute('role', 'img'); svg.setAttribute('aria-label', label); }
      else svg.setAttribute('aria-hidden', 'true');
      [0, 90, 180, 270].forEach(function (deg, i) {
        var use = document.createElementNS(SVG_NS, 'use');
        use.setAttribute('href', '#aperture-blade');
        use.setAttribute('class', i % 2 === 0 ? 'blade-light' : 'blade-dark');
        if (deg) use.setAttribute('transform', 'rotate(' + deg + ')');
        svg.appendChild(use);
      });
      return svg;
    }
    draw(CLOSED);
    return {
      mark: mark,
      open: function () { return to(OPEN); },
      close: function () { return to(CLOSED); },
    };
  })();
  document.getElementById('brand-mark').appendChild(aperture.mark(28));

  var SEV_ORDER = ['Critical', 'High', 'Medium', 'Low'];
  function sevClass(sev) {
    var k = String(sev || '').toLowerCase();
    return 'sev sev-' + (['critical', 'high', 'medium', 'low'].indexOf(k) >= 0 ? k : 'info');
  }
  function sevChip(sev) { return h('span', { class: sevClass(sev) }, sev || 'Unscored'); }

  // ---- API ----
  var confirming = null;
  // A sensitive change needs a recent passkey check: ask once, then repeat the request.
  function reauth() {
    if (!confirming) {
      confirming = api('POST', '/auth/reauth/options', {}).then(function (start) {
        return navigator.credentials.get(toGetOptions(start.options)).then(function (cred) {
          return api('POST', '/auth/login/verify', { flowId: start.flowId, response: assertionJSON(cred) });
        });
      });
      confirming.then(function () { confirming = null; }, function () { confirming = null; });
    }
    return confirming;
  }
  function api(method, path, body, extraHeaders, retried) {
    var opts = { method: method, headers: Object.assign({ 'x-socbridge': '1' }, extraHeaders || {}), credentials: 'same-origin' };
    if (body !== undefined) {
      opts.headers['content-type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    return fetch('/api' + path, opts).then(function (res) {
      return res.text().then(function (t) {
        var data = t ? JSON.parse(t) : {};
        if (res.status === 401 && state.me && state.me.user && path.indexOf('/auth/') !== 0) {
          // Session ended (expiry, revocation, restart): close the aperture and return to sign-in.
          state.me.user = null;
          aperture.close();
          route();
        }
        if (res.status === 403 && data.code === 'reauth' && !retried) {
          return reauth().then(function () { return api(method, path, body, extraHeaders, true); });
        }
        if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
        return data;
      });
    });
  }

  // ---- WebAuthn JSON <-> binary ----
  function b64uToBuf(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }
  function bufToB64u(buf) {
    var bytes = new Uint8Array(buf);
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function toCreateOptions(o) {
    var pk = Object.assign({}, o, {
      challenge: b64uToBuf(o.challenge),
      user: Object.assign({}, o.user, { id: b64uToBuf(o.user.id) }),
      excludeCredentials: (o.excludeCredentials || []).map(function (c) {
        return Object.assign({}, c, { id: b64uToBuf(c.id) });
      }),
    });
    return { publicKey: pk };
  }
  function toGetOptions(o) {
    var pk = Object.assign({}, o, {
      challenge: b64uToBuf(o.challenge),
      allowCredentials: (o.allowCredentials || []).map(function (c) {
        return Object.assign({}, c, { id: b64uToBuf(c.id) });
      }),
    });
    return { publicKey: pk };
  }
  function attestationJSON(cred) {
    var r = cred.response;
    return {
      id: cred.id,
      rawId: bufToB64u(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: cred.getClientExtensionResults(),
      response: {
        clientDataJSON: bufToB64u(r.clientDataJSON),
        attestationObject: bufToB64u(r.attestationObject),
        transports: typeof r.getTransports === 'function' ? r.getTransports() : [],
      },
    };
  }
  function assertionJSON(cred) {
    var r = cred.response;
    return {
      id: cred.id,
      rawId: bufToB64u(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: cred.getClientExtensionResults(),
      response: {
        clientDataJSON: bufToB64u(r.clientDataJSON),
        authenticatorData: bufToB64u(r.authenticatorData),
        signature: bufToB64u(r.signature),
        userHandle: r.userHandle ? bufToB64u(r.userHandle) : undefined,
      },
    };
  }
  function register(optionsPath, body, label) {
    return api('POST', optionsPath, body).then(function (start) {
      return navigator.credentials.create(toCreateOptions(start.options)).then(function (cred) {
        return api('POST', '/auth/register/verify', { flowId: start.flowId, response: attestationJSON(cred), label: label });
      });
    });
  }
  /**
   * phone: open on the QR code. The server lists phone-capable passkeys as hybrid-only (Windows Hello, used by Edge
   * and Chrome on Windows, ignores hints); hints ['hybrid'] covers browsers that honour hints when that list is empty.
   */
  function login(phone) {
    return api('POST', '/auth/login/options', phone ? { phone: true } : {}).then(function (start) {
      if (phone) start.options.hints = ['hybrid'];
      return navigator.credentials.get(toGetOptions(start.options)).then(function (cred) {
        return api('POST', '/auth/login/verify', { flowId: start.flowId, response: assertionJSON(cred) });
      });
    });
  }
  function deviceLabel() {
    var ua = navigator.userAgent;
    if (/iPhone|iPad/.test(ua)) return 'iOS device';
    if (/Android/.test(ua)) return 'Android device';
    if (/Mac/.test(ua)) return 'Mac';
    if (/Windows/.test(ua)) return 'Windows';
    return 'Passkey';
  }

  // ---- state & routing ----
  // chat: the conversation lives in memory only (never in browser storage).
  var state = { me: null, chat: [] };

  function refreshMe() {
    return api('GET', '/me').then(function (me) { state.me = me; return me; });
  }

  function route() {
    var hash = location.hash.replace(/^#\/?/, '');
    var parts = hash.split('/');
    var me = state.me;
    renderNav();
    if (me.user && me.user.role === 'admin') statusBar.start(); else statusBar.stop();
    if (!me.user) {
      if (parts[0] === 'invite' && parts[1]) return viewInvite(parts[1]);
      return viewSignIn();
    }
    var page = parts[0] || 'findings';
    if (page === 'authorize' && parts[1]) return viewAuthorize(parts[1]);
    if (page === 'findings') return viewFindings(parts[1]);
    if (page === 'fix') return viewFixFirst();
    if (page === 'attacks') return viewAttacks();
    if (page === 'map') return viewAttackMap();
    if (page === 'chat') return viewChat();
    if (page === 'passkeys') return viewPasskeys();
    if (page === 'users' && me.user.role === 'admin') return viewUsers();
    if (page === 'services' && me.user.role === 'admin') return viewServices();
    if (page === 'backends' && me.user.role === 'admin') return viewBackends();
    if (page === 'server' && me.user.role === 'admin') return viewServer();
    if (page === 'usage' && me.user.role === 'admin') return viewUsage();
    if (page === 'audit' && me.user.role === 'admin') return viewAudit();
    return viewTokens();
  }

  // ---- service status bar (above the top bar, administrators only) ----
  // Padlock for "is the connection to this backend encrypted". SVG needs its
  // namespace, so it is built here rather than with h().
  function lockIcon(open) {
    var ns = 'http://www.w3.org/2000/svg';
    var svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', '0 0 16 16');
    svg.setAttribute('class', 'lock');
    svg.setAttribute('aria-hidden', 'true');
    var body = document.createElementNS(ns, 'rect');
    [['x', 3], ['y', 7], ['width', 10], ['height', 7], ['rx', 1.5]].forEach(function (a) { body.setAttribute(a[0], a[1]); });
    var shackle = document.createElementNS(ns, 'path');
    shackle.setAttribute('d', open ? 'M5 7V5a3 3 0 0 1 5.8-1' : 'M5 7V5a3 3 0 0 1 6 0v2');
    svg.appendChild(body);
    svg.appendChild(shackle);
    return svg;
  }
  var TRANSPORT_TIP = {
    tls: 'Encrypted (https) with certificate verification',
    'tls-unverified': 'Encrypted (https), but the certificate is not verified',
    plaintext: 'Not encrypted (plain http)',
    local: 'Local files, no network connection',
  };
  // Lock for encrypted transports; open lock for plain http; nothing for local.
  function transportIcon(t) {
    if (t === 'tls') return lockIcon(false);
    if (t === 'tls-unverified' || t === 'plaintext') return lockIcon(true);
    return null;
  }

  var statusBar = (function () {
    var POLL_MS = 60000;
    var HEALTH = { up: 'OK', degraded: 'Degraded', down: 'Down', off: 'Off' };
    var timer = null;
    var last = null;      // { services, at }
    var loading = false;

    function el() { return document.getElementById('status-bar'); }

    function isAdmin() { return !!(state.me && state.me.user && state.me.user.role === 'admin'); }

    function target(s) {
      return s.kind === 'backend' ? '#/backends' : '#/server'; // the assistant and certificate settings live on Server
    }

    function pill(s) {
      var tip = [s.title + ': ' + HEALTH[s.health] + ' — ' + s.summary, s.detail || '', s.checkedAt ? 'Checked ' + fmt(s.checkedAt) : '']
        .filter(Boolean).join('\n');
      if (s.transport && s.health !== 'off') tip += '\n' + TRANSPORT_TIP[s.transport];
      if (s.connections && s.connections.length) tip += '\n' + s.connections.join('\n');
      var kids = [
        h('span', { class: 'dot', 'aria-hidden': 'true' }),
        h('span', { class: 'name' }, s.title),
        s.health !== 'off' && s.transport ? transportIcon(s.transport) : null,
        // A healthy backend needs no words: the dot and the lock say it, the tooltip spells it out.
        s.kind === 'backend' && s.health === 'up' ? null : h('span', { class: 'state' }, s.summary),
      ];
      var cls = 'svc ' + s.health + (s.transport && s.health !== 'off' ? ' t-' + s.transport : '');
      var attrs = { class: cls, title: tip, 'aria-label': s.title + ': ' + HEALTH[s.health] + ', ' + s.summary + (s.transport && s.health !== 'off' ? ', ' + TRANSPORT_TIP[s.transport] : '') };
      attrs.href = target(s);
      return h('a', attrs, kids);
    }

    function render() {
      var box = el();
      if (!box) return;
      if (!isAdmin()) { box.hidden = true; put(box); return; }
      box.hidden = false;
      var items = last
        ? last.services.map(function (s) { return pill(s); })
        : [h('span', { class: 'svc checking' }, h('span', { class: 'dot', 'aria-hidden': 'true' }), h('span', { class: 'state' }, 'Checking services…'))];
      var refresh = h('button', {
        class: 'small', title: 'Check every service again now', disabled: loading,
        onclick: function () { load(true); },
      }, loading ? 'Checking…' : 'Refresh');
      put(box,
        h('span', { class: 'label' }, 'Status'),
        items,
        h('span', { class: 'spacer' }),
        last && last.error ? h('span', { class: 'when' }, 'Status unavailable: ' + last.error) : null,
        last && !last.error ? h('span', { class: 'when' }, 'Updated ' + new Date(last.at).toLocaleTimeString()) : null,
        refresh);
      // Let views that show the same state (backend cards) follow along;
      // drop listeners whose element has left the page.
      listeners = listeners.filter(function (l) { return l.el.isConnected; });
      listeners.forEach(function (l) { l.fn(last); });
    }
    var listeners = [];
    // fn(last) runs on every update while el is on the page, and once now.
    function watch(el, fn) {
      listeners.push({ el: el, fn: fn });
      fn(last);
      if (!last) load(false);
    }

    function load(force) {
      if (loading || !isAdmin()) return;
      loading = true;
      render();
      api('GET', '/status' + (force ? '?refresh=1' : '')).then(function (r) {
        last = { services: r.services, at: Date.now() };
      }).catch(function (e) {
        last = { services: last ? last.services : [], at: Date.now(), error: e.message };
      }).finally(function () {
        loading = false;
        render();
      });
    }

    function startPolling() {
      if (timer) return;
      load(false);
      timer = setInterval(function () { if (!document.hidden) load(false); }, POLL_MS);
    }

    function stop() {
      if (timer) clearInterval(timer);
      timer = null;
      last = null;
      render();
    }

    document.addEventListener('visibilitychange', function () {
      if (!document.hidden && timer && last && Date.now() - last.at > POLL_MS) load(false);
    });

    return { render: render, start: startPolling, stop: stop, watch: watch, refresh: function () { load(false); } };
  })();

  function renderNav() {
    var nav = document.getElementById('nav');
    var me = state.me;
    if (!me || !me.user) { put(nav); return; }
    var current = location.hash.replace(/^#\/?/, '').split('/')[0] || 'findings';
    function link(id, text) {
      return h('a', { href: '#/' + id, class: current === id ? 'active' : '' }, text);
    }
    // A disclosure menu: the group title, marked active when one of its pages is open.
    function menu(title, pages, extra) {
      var active = pages.some(function (p) { return p[0] === current; });
      return h('details', { class: 'menu' },
        h('summary', { class: active ? 'active' : '' }, title),
        h('div', { class: 'menu-list' }, pages.map(function (p) { return link(p[0], p[1]); }), extra)
      );
    }
    put(nav,
      h('div', { class: 'nav-pages' },
        link('findings', 'Findings'),
        link('fix', 'Fix first'),
        link('attacks', 'Attack trend'),
        link('map', 'Pew pew map'),
        link('chat', 'Assistant')
      ),
      h('div', { class: 'nav-menus' },
        me.user.role === 'admin' ? menu('Admin', [
          ['users', 'Users'],
          ['backends', 'Backends'],
          ['services', 'Services'],
          ['server', 'Server'],
          ['usage', 'Usage'],
          ['audit', 'Audit'],
        ]) : null,
        menu('My account', [['tokens', 'Access tokens'], ['passkeys', 'Passkeys']], [
          h('div', { class: 'who' }, 'Signed in as ' + me.user.name + (me.user.role === 'admin' ? ' (admin)' : '')),
          h('button', {
            onclick: function () {
              api('POST', '/auth/logout', {}).then(function () { statusBar.stop(); }).then(aperture.close).then(start);
            },
          }, 'Sign out'),
        ])
      )
    );
  }

  // Close an open nav menu on a click elsewhere (or on one of its links), Escape, or focus leaving it.
  function closeMenus(keep) {
    document.querySelectorAll('#nav details[open]').forEach(function (d) { if (d !== keep) d.open = false; });
  }
  document.addEventListener('click', function (ev) {
    var inside = ev.target.closest('#nav details');
    closeMenus(inside && !ev.target.closest('.menu-list a') ? inside : null);
  });
  document.addEventListener('keydown', function (ev) {
    if (ev.key !== 'Escape') return;
    var open = document.querySelector('#nav details[open]');
    if (!open) return;
    open.open = false;
    open.querySelector('summary').focus();
  });
  document.addEventListener('focusin', function (ev) { closeMenus(ev.target.closest('#nav details')); });

  /**
   * Turns a WebAuthn failure into advice. Browsers report every refusal as
   * NotAllowedError/SecurityError without saying why, so name the causes we can
   * detect (wrong host name, untrusted certificate) and the one we cannot: a
   * certificate warning the user clicked past earlier, which keeps the site
   * "Not Secure" in Chrome even after the certificate is fixed.
   */
  function passkeyMessage(e) {
    var name = e && e.name;
    if (name !== 'NotAllowedError' && name !== 'SecurityError' && name !== 'InvalidStateError') return (e && e.message) || String(e);
    if (name === 'InvalidStateError') return 'This device already has a passkey for this account. Use it to sign in, or pick another device.';
    var me = state.me || {};
    var rpHost = '';
    try { rpHost = new URL(me.publicUrl).hostname; } catch (_) { /* no public URL known */ }
    if (rpHost && location.hostname !== rpHost) {
      return 'Passkeys are tied to ' + rpHost + ', but this page is open as ' + location.hostname + '. Open ' + me.publicUrl + ' and try again.';
    }
    if (me.tlsStaging) {
      return "The browser refused because this site uses a Let's Encrypt STAGING certificate, which browsers do not trust. " +
        'Switch to a real certificate (untick “Use Let’s Encrypt staging”, Save & apply), reload, and try again.';
    }
    if (me.tlsServing === 'builtin') {
      return 'The browser refused. The usual cause is that it does not trust the built-in CA certificate ' +
        '(passkeys are disabled on pages with a certificate warning). Get a trusted certificate or trust ca.crt, reload, and try again. ' +
        'If the address bar shows no warning, the prompt was simply cancelled or timed out.';
    }
    return 'The browser refused to use a passkey. If the passkey is on your phone, use the QR code choice with Bluetooth on in both devices. Otherwise the prompt was cancelled or timed out (try again), or the browser still ' +
      'treats this site as unsafe: if the address bar says “Not Secure” although the certificate is valid, it remembers a certificate ' +
      'warning you clicked past earlier. Quit the browser completely (⌘Q on a Mac) and reopen it, or use a private window, then try again.';
  }

  function busy(btn, promise, errBox) {
    btn.disabled = true;
    if (errBox) put(errBox);
    return promise.catch(function (e) {
      var msg = passkeyMessage(e);
      if (errBox) put(errBox, notice('error', msg));
      else alert(msg);
    }).finally(function () { btn.disabled = false; });
  }

  // ---- views: signed out ----
  function viewSignIn() {
    var me = state.me;
    if (me.setupRequired) return viewSetup();
    var err = h('div');
    function signIn(btn, phone) {
      put(phoneHelp);
      busy(btn, login(phone).then(aperture.open).then(start), err);
    }
    var phoneHelp = h('div');
    var btn = h('button', { class: 'primary', onclick: function () { signIn(btn); } }, 'Sign in with a passkey');
    var phone = h('button', { onclick: function () {
      signIn(phone, true);
      put(phoneHelp, notice('info', 'Scan the QR code with the camera of the phone that has the passkey. If no code appears, choose “iPhone, iPad or Android device” or “Use a phone or tablet” in the browser’s dialog. Bluetooth must be on in both devices, and both need internet access.'));
    } }, 'Use a phone (QR code)');
    var nodes = [
      h('div', { class: 'panel' },
        h('h1', null, 'Sign in'),
        h('p', { class: 'lede' }, 'Passkeys only. There are no passwords.'),
        /^#\/?authorize\//.test(location.hash) ? notice('info', 'An app is asking to connect to SocBridge. Sign in to review the request.') : null,
        h('div', { class: 'row' }, btn, phone), phoneHelp, err),
    ];
    mount(h('div', { class: 'gate' }, h('div', { class: 'gate-mark' }, aperture.mark(88, 'SocBridge')), nodes));
  }

  /**
   * First-time setup guide. Passkeys (WebAuthn) only work when the browser
   * trusts the certificate without a warning, so the certificate comes first:
   *   1. setup token (proves you can read the server log)
   *   2. certificate: Let's Encrypt via Cloudflare, or trust the built-in CA
   *   3. create the admin passkey
   */
  function viewSetup() {
    var me = state.me;
    var serving = me.tlsServing; // builtin | acme | file | env-acme | off
    var builtinCa = serving === 'builtin';
    var host = location.host;

    function step(n, title) {
      var rest = Array.prototype.slice.call(arguments, 2);
      return h('div', { class: 'panel step' },
        h('div', { class: 'step-head' }, h('span', { class: 'step-num' }, String(n)), h('h2', null, title)),
        rest);
    }

    // --- 1. setup token ---------------------------------------------------
    var token = h('input', { type: 'password', autocomplete: 'off', placeholder: 'Setup token from the server log' });
    var withToken = function (method, path, body) {
      return api(method, path, body, { 'x-setup-token': token.value.trim() });
    };
    var tokenStep = step(1, 'Setup token',
      h('p', { class: 'muted small' }, 'Shown in the server log in a box marked ', h('strong', null, 'SETUP TOKEN'),
        ' (repeated every 15 minutes until an administrator exists), or the value of SETUP_TOKEN if you set one. Find it with:'),
      h('pre', { class: 'small' }, 'docker logs socbridge 2>&1 | grep "SETUP TOKEN" | tail -1'),
      h('p', { class: 'muted small' }, 'A generated token changes when the service restarts, so use the latest one. It only works until the first administrator exists.'),
      token);

    // --- 2. certificate ---------------------------------------------------
    var certBody = h('div');
    var certStep = step(2, 'Certificate', certBody);

    function verifyHint() {
      return h('div', null,
        h('p', { class: 'small' }, 'Until the browser trusts this site, check that you are talking to your own server before sending any secret: ',
          'open the certificate details from the address bar and compare the CA fingerprint (SHA-256) with the ',
          h('code', null, 'Built-in CA ready'), ' line in the server log.'),
        me.caFingerprint ? h('div', { class: 'secret data small' }, me.caFingerprint) : null);
    }

    var reloadBox = h('div');
    function onTls(v) {
      if (v.serving === 'acme' && !v.staging && !v.settings.acmeStaging) {
        put(reloadBox, notice('success', "Let's Encrypt certificate is active. "),
          h('div', { class: 'row' }, h('button', { class: 'primary', onclick: function () { location.reload(); } }, 'Reload the page')),
          h('p', { class: 'muted small' }, 'After reloading, the address bar should show no warning; then create your passkey below. ',
            'The setup token stays the same until you do.'));
      } else put(reloadBox);
    }

    if (serving === 'off') {
      certStep.classList.add('done');
      put(certBody, h('p', { class: 'muted' }, 'TLS is handled by your reverse proxy (TLS_MODE=off). Make sure ', h('span', { class: 'data' }, host),
        ' has a certificate your browser trusts, then continue.'));
    } else if (me.tlsStaging) {
      // A staging certificate is "Let's Encrypt" but untrusted: passkeys fail, so keep the settings reachable here.
      var stagingBox = h('div');
      var stagingPanel = null;
      var openStaging = function () {
        if (stagingPanel) { stagingPanel.load(); return; }
        if (!token.value.trim()) {
          put(stagingBox, h('p', { class: 'muted small' }, 'Enter the setup token in step 1 to change the certificate.'));
          return;
        }
        stagingPanel = tlsPanel(withToken, onTls, { preferAcme: true });
        put(stagingBox, stagingPanel.node, reloadBox);
        stagingPanel.load();
      };
      token.addEventListener('change', openStaging);
      put(certBody,
        notice('error', "This server uses a Let's Encrypt STAGING certificate. Browsers do not trust it, so a passkey cannot be created. " +
          "Untick “Use Let's Encrypt staging” below and press “Save & apply” to get a real certificate (one to three minutes)."),
        h('div', { class: 'row' }, h('button', { onclick: openStaging }, 'Show certificate settings')),
        stagingBox);
    } else if (!builtinCa) {
      certStep.classList.add('done');
      put(certBody, h('p', { class: 'muted' }, 'This server already uses a ',
        serving === 'file' ? 'certificate from files' : "Let's Encrypt certificate",
        '. If the address bar shows no warning you can continue.'));
    } else {
      var pickAcme = h('input', { type: 'radio', name: 'certchoice', value: 'acme' });
      var pickCa = h('input', { type: 'radio', name: 'certchoice', value: 'ca' });
      var acmeBox = h('div', { class: 'hidden' });
      var caBox = h('div', { class: 'hidden' });
      var panel = null;


      function choose() {
        acmeBox.className = pickAcme.checked ? '' : 'hidden';
        caBox.className = pickCa.checked ? '' : 'hidden';
        if (pickAcme.checked && !panel) {
          if (!token.value.trim()) {
            put(acmeBox, notice('error', 'Enter the setup token in step 1 first.'));
            pickAcme.checked = false;
            acmeBox.className = '';
            return;
          }
          panel = tlsPanel(withToken, onTls, { preferAcme: true });
          put(acmeBox, verifyHint(), panel.node, reloadBox);
          panel.load();
        }
      }
      pickAcme.addEventListener('change', choose);
      pickCa.addEventListener('change', choose);
      // A corrected token reloads the certificate panel with the new value.
      token.addEventListener('change', function () { if (panel) panel.load(); });

      put(caBox,
        h('ol', { class: 'steps small' },
          h('li', null, h('a', { href: '/ca.crt' }, 'Download ca.crt'), '.'),
          h('li', null, 'Check its SHA-256 fingerprint against the ', h('code', null, 'Built-in CA ready'), ' line in the server log:',
            me.caFingerprint ? h('div', { class: 'secret data small' }, me.caFingerprint) : null,
            h('code', { class: 'small' }, 'openssl x509 -in socbridge-ca.crt -noout -fingerprint -sha256')),
          h('li', null, 'Trust it as a root certificate. macOS: ',
            h('code', { class: 'small' }, 'security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db socbridge-ca.crt'),
            '. Windows: open the file → Install Certificate → Trusted Root Certification Authorities. Linux/Firefox: import it under Certificate Manager → Authorities.'),
          h('li', null, 'Quit and reopen the browser, open ', h('span', { class: 'data' }, location.origin), ' and check that the address bar shows no warning.')),
        h('p', { class: 'muted small' }, 'Every device that signs in, and every MCP client, must trust the same ca.crt.'));

      put(certBody,
        h('p', { class: 'small' }, 'Passkeys only work when the browser trusts this site without a warning. ',
          'Right now it uses a certificate from SocBridge’s own built-in CA, which browsers do not trust by default. Choose one:'),
        h('label', { class: 'choice' }, pickAcme, h('strong', null, "Let's Encrypt via Cloudflare (recommended)"),
          h('div', { class: 'help' }, 'A publicly trusted certificate for ', h('span', { class: 'data' }, host.replace(/:\d+$/, '')),
            ' (from PUBLIC_URL). Needs a Cloudflare API token for that DNS zone. The service can stay internal: validation uses a DNS record, not inbound traffic.')),
        acmeBox,
        h('label', { class: 'choice' }, pickCa, h('strong', null, 'Trust the built-in CA'),
          h('div', { class: 'help' }, 'Works offline. Download ca.crt once and trust it on every device and client.')),
        caBox);
    }

    // --- 3. admin passkey -------------------------------------------------
    var name = h('input', { type: 'text', autocomplete: 'username', placeholder: 'admin' });
    var err = h('div');
    var btn = h('button', {
      class: 'primary',
      onclick: function () {
        btn.disabled = true;
        put(err);
        register('/auth/setup/options', { setupToken: token.value, name: name.value }, deviceLabel())
          .then(aperture.open).then(start)
          .catch(function (e) {
            put(err, notice('error', passkeyMessage(e)));
          })
          .finally(function () { btn.disabled = false; });
      },
    }, 'Create admin passkey');
    var passkeyStep = step(3, 'Administrator passkey',
      h('p', { class: 'muted small' }, 'Creates the first administrator. There are no passwords; sign-in is with this passkey.'),
      h('label', null, 'Your name'), name,
      h('div', { class: 'row' }, btn), err);

    mount(h('div', { class: 'gate setup' },
      h('div', { class: 'gate-mark' }, aperture.mark(88, 'SocBridge')),
      h('h1', null, 'First-time setup'),
      h('p', { class: 'lede' }, 'No administrator exists yet. Three steps: prove you run this server, give it a certificate your browser trusts, then create your passkey.'),
      tokenStep, certStep, passkeyStep));
  }

  function viewInvite(code) {
    var name = h('input', { type: 'text', autocomplete: 'username' });
    var err = h('div');
    var btn = h('button', {
      class: 'primary',
      onclick: function () {
        busy(btn, register('/auth/invite/options', { code: code, name: name.value }, deviceLabel()).then(function () {
          history.replaceState(null, '', '#/');
          return aperture.open().then(start);
        }), err);
      },
    }, 'Create passkey');
    mount(h('div', { class: 'gate' }, h('div', { class: 'gate-mark' }, aperture.mark(88, 'SocBridge')), h('div', { class: 'panel' },
      h('h1', null, 'Accept invite'),
      h('p', { class: 'lede' }, 'Choose a name and create a passkey on this device. The invite works once and expires after 24 hours.'),
      h('label', null, 'Your name'), name,
      h('div', { class: 'row' }, btn), err)));
  }

  // ---- views: signed in ----

  /** OAuth consent screen, reached from /oauth/authorize (e.g. a Claude custom connector). */
  function viewAuthorize(requestId) {
    var me = state.me;
    var box = h('div', { class: 'panel' }, h('p', { class: 'muted' }, 'Loading request…'));
    mount(h('div', null, h('h1', null, 'Connect an app'), box));
    var path = '/oauth/requests/' + encodeURIComponent(requestId);
    api('GET', path).then(function (r) {
      var err = h('div');
      var picker = scopePicker();
      // Nothing by default: the user picks each backend the app may use.
      picker.fill(r.scopes, { backends: {} });
      var mins = Math.max(0, Math.round((Date.now() - Date.parse(r.clientRegisteredAt)) / 60000));
      var age = mins < 60 ? mins + ' min ago' : mins < 2880 ? Math.round(mins / 60) + ' h ago' : Math.round(mins / 1440) + ' days ago';
      function decide(btn, approve) {
        var body = { approve: approve };
        if (approve) body.access = picker.value();
        busy(btn, api('POST', path, body).then(function (out) {
          put(box, notice('success', approve ? 'Approved. Returning to ' + r.redirectHost + '…' : 'Declined. Returning to ' + r.redirectHost + '…'));
          location.href = out.redirect;
        }), err);
      }
      var approve = h('button', { class: 'primary', onclick: function () { decide(approve, true); } }, 'Approve');
      var deny = h('button', { onclick: function () { decide(deny, false); } }, 'Deny');
      put(box,
        h('h2', null, r.clientName, ' ', h('span', { class: 'badge' }, 'name not verified')),
        h('p', null, 'An app calling itself ', h('strong', null, r.clientName), ' wants to use SocBridge as ', h('strong', null, me.user.name),
          '. Any app can choose that name; the address it returns to below is what identifies it. Choose what it may do on each backend; it never sees tools outside this choice.'),
        r.previouslyApproved ? null : notice('warning', 'This app registered ' + age + ' and has not been approved on this server before.'),
        picker.node,
        h('table', { class: 'kv' }, h('tbody', null,
          h('tr', null, h('th', null, 'Returns to'), h('td', null, h('span', { class: 'data' }, r.redirectUri))),
          h('tr', null, h('th', null, 'Registered'), h('td', null, fmt(r.clientRegisteredAt) + ' (' + age + ')')),
          h('tr', null, h('th', null, 'Endpoint'), h('td', null, 'MCP tools at ' + me.publicUrl + '/mcp')),
          h('tr', null, h('th', null, 'Until'), h('td', null, 'You disconnect it under Access tokens, or it stays unused for 30 days')))),
        h('p', { class: 'small muted' }, 'Only approve if you just started this connection yourself, from ' + r.redirectHost + '.'),
        h('div', { class: 'row' }, approve, deny), err);
    }).catch(function (e) {
      put(box, notice('error', e.message), h('p', { class: 'small muted' }, 'Start the connection again from your app.'));
    });
  }

  /**
   * Per-backend access picker (none, read, read and write), shared by the
   * token form and the OAuth consent screen. Write is offered only where an
   * administrator granted it to this user. `fill` takes /tokens/scopes.
   */
  function scopePicker() {
    var node = h('div', { class: 'scope-picker' }, h('p', { class: 'muted small' }, 'Loading backends…'));
    var sel = {};
    /** `current`: a scope to preselect (editing); default is read on every backend. */
    function fill(opts, current) {
      put(node, h('table', { class: 'compact' },
        h('thead', null, h('tr', null, h('th', null, 'Backend'), h('th', null, 'Access'), h('th', null, ''))),
        h('tbody', null, opts.map(function (o) {
          var cur = current ? (current.backends[o.id] || '') : 'read';
          var s = h('select', { 'aria-label': 'Access to ' + o.title },
            h('option', { value: '', selected: cur === '' }, 'No access'),
            h('option', { value: 'read', selected: cur === 'read' }, 'Read'),
            o.writeGranted || cur === 'write' ? h('option', { value: 'write', selected: cur === 'write' }, 'Read and write') : null);
          sel[o.id] = s;
          var hint = !o.writeGranted
            ? (o.writeTools.length ? 'Write needs a grant from an administrator.' : '')
            : !o.writeAllowed ? 'Write tools are switched off for this backend; it reads until an administrator switches them on.'
            : 'Write adds: ' + o.writeTools.join(', ');
          return h('tr', null, h('td', null, o.title + (o.enabled ? '' : ' (disabled)')), h('td', null, s), h('td', { class: 'help' }, hint));
        }))));
    }
    function value() {
      var backends = {};
      Object.keys(sel).forEach(function (id) { if (sel[id].value) backends[id] = sel[id].value; });
      return { backends: backends };
    }
    return { node: node, fill: fill, value: value };
  }

  /**
   * "Edit scope" button plus a hidden table row holding the picker, for a
   * token or a connected app. `save(scope)` returns a promise. Administrators
   * editing someone else's credential see that user's grants.
   */
  function scopeEditor(ownerId, current, colspan, save, note) {
    var row = h('tr', { class: 'hidden' });
    var button = h('button', {
      onclick: function () {
        if (!row.classList.contains('hidden')) { row.classList.add('hidden'); return; }
        var picker = scopePicker();
        var err = h('div');
        var saveBtn = h('button', { class: 'primary', onclick: function () { busy(saveBtn, save(picker.value()), err); } }, 'Save scope');
        var cancel = h('button', { onclick: function () { row.classList.add('hidden'); } }, 'Cancel');
        put(row, h('td', { colspan: String(colspan) }, h('p', { class: 'muted small' }, note), picker.node, h('div', { class: 'row' }, saveBtn, cancel), err));
        row.classList.remove('hidden');
        var who = ownerId !== state.me.user.id ? '?user=' + encodeURIComponent(ownerId) : '';
        api('GET', '/tokens/scopes' + who).then(function (opts) { picker.fill(opts, current); })
          .catch(function (e) { put(picker.node, notice('error', e.message)); });
      },
    }, 'Edit scope');
    return { button: button, row: row };
  }

  function scopeText(scope) {
    var parts = Object.keys(scope.backends).map(function (id) {
      return scope.backends[id] === 'write' ? h('span', { class: 'badge write' }, id + ': write') : h('span', { class: 'badge' }, id);
    });
    return parts.length ? parts : h('span', { class: 'muted' }, 'none');
  }

  function viewTokens() {
    var me = state.me;
    var isAdmin = me.user.role === 'admin';
    var listBox = h('div');
    var created = h('div');
    var label = h('input', { type: 'text', placeholder: 'e.g. Claude Code on laptop', class: 'grow' });
    var expiry = h('select', null,
      h('option', { value: '' }, 'No expiry'),
      h('option', { value: '30' }, '30 days'),
      h('option', { value: '90', selected: true }, '90 days'),
      h('option', { value: '365' }, '1 year'));
    var err = h('div');
    var showAll = h('input', { type: 'checkbox' });
    var picker = scopePicker();
    api('GET', '/tokens/scopes').then(picker.fill).catch(function (e) { put(picker.node, notice('error', e.message)); });

    function load() {
      api('GET', '/tokens' + (showAll.checked ? '?all=1' : '')).then(function (tokens) {
        if (!tokens.length) { put(listBox, h('p', { class: 'muted' }, 'No tokens yet.')); return; }
        put(listBox, h('div', { class: 'table-wrap' }, h('table', null,
          h('thead', null, h('tr', null,
            h('th', null, 'Label'), h('th', null, 'Token'), h('th', null, 'Scope'),
            showAll.checked ? h('th', null, 'User') : null,
            h('th', null, 'Created'), h('th', null, 'Expires'), h('th', null, 'Last used'), h('th'))),
          h('tbody', null, tokens.map(function (t) {
            var b = h('button', {
              class: 'danger',
              onclick: function () {
                if (!confirm('Revoke "' + t.label + '"? Clients using it stop working immediately.')) return;
                busy(b, api('DELETE', '/tokens/' + encodeURIComponent(t.id)).then(load));
              },
            }, 'Revoke');
            var editRow = scopeEditor(t.userId, t.scope, 8, function (scope) {
              return api('PATCH', '/tokens/' + encodeURIComponent(t.id), { scope: scope }).then(load);
            }, 'Applies from the next call; clients keep the same token.');
            return [h('tr', null,
              h('td', null, t.label),
              h('td', null, h('code', null, t.hint + '…')),
              h('td', null, h('div', { class: 'badges' }, scopeText(t.scope))),
              showAll.checked ? h('td', null, t.userName) : null,
              h('td', null, fmt(t.createdAt)),
              h('td', null, t.expired ? h('span', { class: 'badge error' }, 'expired') : fmt(t.expiresAt)),
              h('td', null, fmt(t.lastUsedAt)),
              h('td', null, h('div', { class: 'row' }, editRow.button, b))), editRow.row];
          })))));
      }).catch(function (e) { put(listBox, notice('error', e.message)); });
    }
    var appsBox = h('div');
    function loadApps() {
      api('GET', '/oauth/grants' + (showAll.checked ? '?all=1' : '')).then(function (grants) {
        if (!grants.length) { put(appsBox, h('p', { class: 'muted' }, 'No connected apps.')); return; }
        put(appsBox, h('div', { class: 'table-wrap' }, h('table', null,
          h('thead', null, h('tr', null,
            h('th', null, 'App'), h('th', null, 'Scope'), showAll.checked ? h('th', null, 'User') : null,
            h('th', null, 'Connected'), h('th', null, 'Last used'), h('th'))),
          h('tbody', null, grants.map(function (g) {
            var b = h('button', {
              class: 'danger',
              onclick: function () {
                if (!confirm('Disconnect "' + g.clientName + '"? It stops working immediately and must be approved again.')) return;
                busy(b, api('DELETE', '/oauth/grants/' + encodeURIComponent(g.id)).then(loadApps));
              },
            }, 'Disconnect');
            var editRow = scopeEditor(g.userId, g.access, 6, function (access) {
              return api('PATCH', '/oauth/grants/' + encodeURIComponent(g.id), { access: access }).then(loadApps);
            }, 'Applies from the app\'s next call; it stays connected.');
            return [h('tr', null,
              h('td', null, g.clientName),
              h('td', null, h('div', { class: 'badges' }, scopeText(g.access))),
              showAll.checked ? h('td', null, g.userName) : null,
              h('td', null, fmt(g.createdAt)),
              h('td', null, fmt(g.lastUsedAt)),
              h('td', null, h('div', { class: 'row' }, editRow.button, b))), editRow.row];
          })))));
      }).catch(function (e) { put(appsBox, notice('error', e.message)); });
    }
    showAll.addEventListener('change', load);
    showAll.addEventListener('change', loadApps);

    var connectBox = h('div');
    function showConnect(token) { put(connectBox, connectGuide(me, isAdmin, token)); }

    var createBtn = h('button', {
      class: 'primary',
      onclick: function () {
        var body = { label: label.value.trim(), scope: { backends: {} } };
        if (expiry.value) body.expiresInDays = Number(expiry.value);
        body.scope = picker.value();
        busy(createBtn, api('POST', '/tokens', body).then(function (t) {
          label.value = '';
          put(created, h('div', { class: 'notice success' },
            h('strong', null, 'Copy this token now — it will not be shown again.'),
            h('div', { class: 'secret data' }, t.token),
            h('p', { class: 'small' }, 'The setup steps under Connect a client below now include this token.')));
          showConnect(t.token);
          connectBox.scrollIntoView({ behavior: 'smooth', block: 'start' });
          load();
        }), err);
      },
    }, 'Create token');

    mount(h('div', null,
      h('h1', null, 'Access tokens'),
      h('div', { class: 'panel' },
        h('h2', null, 'New token'),
        h('p', { class: 'muted small' }, 'Tokens authenticate MCP clients to ' + me.publicUrl + '/mcp. Each token acts as you; revoking it takes effect on the next request.'),
        h('div', { class: 'row' }, label, expiry),
        h('h3', null, 'Scope'),
        h('p', { class: 'muted small' }, 'What this token may do on each backend. A client never sees tools outside the scope. Tools marked write change the backend and every call is in the audit log.'),
        picker.node,
        h('div', { class: 'row' }, createBtn), err, created),
      h('div', { class: 'panel' },
        h('h2', null, 'Connect a client'),
        connectBox),
      h('div', { class: 'panel' },
        h('div', { class: 'row' }, h('h2', { class: 'grow' }, 'Tokens'),
          isAdmin ? h('label', { class: 'inline' }, showAll, 'Show all users') : null),
        listBox),
      h('div', { class: 'panel' },
        h('h2', null, 'Connected apps'),
        me.oauthEnabled ? [
          h('p', { class: 'muted small' }, 'Apps that signed in with OAuth instead of a token, such as a Claude custom connector or a ChatGPT app. See Connect a client above for how to add one.'),
        ] : h('p', { class: 'muted small' }, isAdmin
          ? 'Connectors (OAuth sign-in for apps such as Claude custom connectors) are turned off. Turn them on under Server.'
          : 'Connectors (OAuth sign-in for apps such as Claude custom connectors) are turned off. An administrator can turn them on.'),
        appsBox)));
    showConnect(null);
    load();
    loadApps();
  }

  /**
   * True when clients must trust the built-in CA: the server serves a
   * certificate it signed itself. A CA file can exist while Let's Encrypt
   * serves, so caAvailable alone is not enough.
   */
  function usesBuiltinCa(me) {
    return !!me.caAvailable && me.tlsServing === 'builtin';
  }

  /**
   * Setup steps per MCP client. Claude Code and Claude Desktop take an access
   * token; Claude connectors and ChatGPT cannot send a header and sign in with
   * OAuth. `token` is the token just created, or null (then the token snippets wait for one).
   */
  function connectGuide(me, isAdmin, token) {
    var url = me.publicUrl + '/mcp';
    var tok = token || 'msec_…';
    // Without a fresh token the snippets would only be templates: ask for a
    // token first and keep the template behind "I already have a token".
    // Tokens are stored hashed, so an existing token cannot be filled in.
    function withToken(body) {
      if (token) return body;
      return h('div', null,
        h('p', { class: 'small' }, h('strong', null, 'Create a token above'),
          ' and these steps show the config with your token filled in, ready to copy and paste. ',
          'An existing token cannot be shown again; revoke it and create a new one if you no longer have it.'),
        h('details', { class: 'help' }, h('summary', null, 'I already have a token'),
          h('p', { class: 'small muted' }, 'Replace ', h('code', null, 'msec_…'), ' with your token.'),
          body));
    }
    var oauthOff = !me.oauthEnabled ? notice('warning', isAdmin
      ? 'Connectors are turned off on this server. Turn them on under Server first.'
      : 'Connectors are turned off on this server. Ask an administrator to turn them on.') : null;
    var publicCert = usesBuiltinCa(me) ? notice('warning',
      'This server uses its built-in CA. Connectors are called from the vendor\'s cloud, which needs a publicly trusted certificate (Let\'s Encrypt) and a URL reachable from the internet.') : null;
    // A function, not a node: one DOM node appended in two sections ends up only in the last.
    function caNode() {
      return usesBuiltinCa(me) ? h('p', { class: 'small muted' },
        'This server uses its built-in CA. Download ', h('a', { href: '/ca.crt' }, 'ca.crt'),
        ' and point NODE_EXTRA_CA_CERTS at it.') : null;
    }

    var desktopEnv = { SOCBRIDGE_AUTH: 'Bearer ' + tok };
    if (usesBuiltinCa(me)) desktopEnv.NODE_EXTRA_CA_CERTS = '/path/to/socbridge-ca.crt';
    var desktopJson = JSON.stringify({ mcpServers: { 'socbridge': {
      command: 'npx',
      // http-only: /mcp is stateless Streamable HTTP and has no SSE to fall back to.
      // No space after the colon: Claude Desktop splits args with spaces badly
      // (Windows), so the space lives in the env value instead.
      args: ['-y', 'mcp-remote', url, '--transport', 'http-only', '--header', 'Authorization:${SOCBRIDGE_AUTH}'],
      env: desktopEnv,
    } } }, null, 2);
    // Clients that speak HTTP themselves (Claude Code .mcp.json, Cursor, VS Code…).
    var httpJson = JSON.stringify({ mcpServers: { 'socbridge': {
      type: 'http',
      url: url,
      headers: { Authorization: 'Bearer ' + tok },
    } } }, null, 2);
    var curlCmd = 'curl -s ' + url + ' -H "Authorization: Bearer ' + tok + '" -H "Content-Type: application/json"' +
      ' -H "Accept: application/json, text/event-stream" -d \'{"jsonrpc":"2.0","id":1,"method":"tools/list"}\'';

    // A code block with a Copy button, so a snippet can be pasted as-is.
    function code(text) {
      var btn = h('button', { class: 'small', type: 'button', onclick: function () {
        navigator.clipboard.writeText(text).then(function () {
          btn.textContent = 'Copied';
          setTimeout(function () { btn.textContent = 'Copy'; }, 1500);
        }, function () { btn.textContent = 'Select and copy manually'; });
      } }, 'Copy');
      return h('div', null, h('pre', null, text), btn);
    }

    function section(title, open, body) {
      return h('details', { class: 'help', open: open || null }, h('summary', null, title), body);
    }

    return h('div', null,
      h('p', { class: 'muted small' }, 'Server URL for every client:'),
      h('div', { class: 'secret data' }, url),
      section('Claude Code (token)', !!token, h('div', null,
        withToken(h('div', null,
          h('p', { class: 'small' }, 'Run in a terminal:'),
          code('claude mcp add --transport http socbridge ' + url + ' --header "Authorization: Bearer ' + tok + '"'))),
        caNode())),
      section('Claude Desktop with a token (config file)', !!token, h('div', null,
        h('p', { class: 'small' }, 'Claude Desktop\'s config file only starts local servers, so the small mcp-remote bridge (needs Node.js) forwards to the URL above with your token.'),
        h('ol', { class: 'steps small' },
          h('li', null, 'In Claude Desktop open Settings → Developer → Edit Config. The file is ',
            h('code', null, '~/Library/Application Support/Claude/claude_desktop_config.json'), ' on macOS and ',
            h('code', null, '%APPDATA%\\Claude\\claude_desktop_config.json'), ' on Windows.'),
          h('li', null, 'Add this (merge with any existing mcpServers):', withToken(code(desktopJson))),
          h('li', null, 'Quit Claude Desktop completely and start it again. The tools in the token\'s scope appear in the tools menu.')),
        usesBuiltinCa(me) ? h('p', { class: 'small muted' },
          'This server uses its built-in CA: download ', h('a', { href: '/ca.crt' }, 'ca.crt'),
          ', check its fingerprint, and set NODE_EXTRA_CA_CERTS above to where you saved it.') : null,
        h('p', { class: 'small muted' }, 'Logs: ', h('code', null, '~/Library/Logs/Claude/mcp-server-socbridge.log'),
          '. A 401 means a wrong or revoked token. Without a token you can use a custom connector instead (below).'))),
      section('Other clients with a config file (URL + header)', false, h('div', null,
        h('p', { class: 'small' }, 'Clients that speak HTTP themselves need no bridge — Claude Code (.mcp.json), Cursor, VS Code and similar. The format is the same or nearly so:'),
        withToken(h('div', null,
          code(httpJson),
          h('p', { class: 'small' }, 'Test the token without a client:'),
          code(curlCmd))),
        caNode())),
      section('Claude: claude.ai, Desktop, mobile (connector, OAuth)', false, h('div', null,
        oauthOff, publicCert,
        h('ol', { class: 'steps small' },
          h('li', null, 'Open Settings → Connectors → Add custom connector.'),
          h('li', null, 'Name it (e.g. SocBridge) and enter the server URL above. Leave the advanced OAuth fields empty.'),
          h('li', null, 'Click Add, then Connect. This console opens: sign in with your passkey and click Approve.')),
        h('p', { class: 'small muted' }, 'No token is needed. The connection appears under Connected apps below; on Team and Enterprise plans an owner may have to add the connector first.'))),
      section('ChatGPT (app, OAuth)', false, h('div', null,
        oauthOff, publicCert,
        me.chatgptRedirectAllowed ? null : notice('warning', isAdmin
          ? 'This server does not accept ChatGPT sign-ins yet: add chatgpt.com to OAUTH_REDIRECT_HOSTS (e.g. claude.ai,claude.com,chatgpt.com) and restart.'
          : 'This server does not accept ChatGPT sign-ins yet. Ask an administrator to add chatgpt.com to OAUTH_REDIRECT_HOSTS.'),
        h('ol', { class: 'steps small' },
          h('li', null, 'In ChatGPT on the web open Settings → Apps & Connectors → Advanced settings and turn on Developer mode.'),
          h('li', null, 'Back in Apps & Connectors, click Create. Enter a name, the server URL above, and choose OAuth as authentication.'),
          h('li', null, 'Confirm you trust the app and click Create. This console opens: sign in with your passkey and click Approve.'),
          h('li', null, 'In a chat, pick the app from the + menu (Developer mode) to use its tools.')),
        h('p', { class: 'small muted' }, 'ChatGPT cannot send a token, so it always signs in with OAuth. Developer mode needs a paid plan, and the menu names may differ slightly between ChatGPT versions.'))));
  }

  /** Every data source with what it lacks; shown when Findings has nothing to show yet. */
  function sourcesStatus(backends, admin) {
    var LABEL = {
      ready: ['Ready', 'on'],
      incomplete: ['Enabled, settings incomplete', 'error'],
      disabled: ['Configured, disabled', ''],
      'not-configured': ['Not configured', 'error'],
      planned: ['Planned (not implemented yet)', ''],
    };
    var usable = backends.filter(function (b) { return b.state === 'ready'; }).length;
    return h('div', null,
      h('h2', null, usable === 0 ? 'No data sources are set up yet' : 'No findings source is ready'),
      h('p', { class: 'muted small' },
        'This page shows findings from Wazuh, Trivy and DefectDojo, and triggered events and recent error messages from Graylog. MCP clients and the assistant can only use sources marked Ready. ',
        usable === 0 ? 'Right now SocBridge has nothing to query.' : ''),
      h('div', { class: 'table-wrap' }, h('table', null,
        h('thead', null, h('tr', null, h('th', null, 'Source'), h('th', null, 'Status'), h('th', null, admin ? 'Missing' : ''))),
        h('tbody', null, backends.map(function (b) {
          var l = LABEL[b.state] || [b.state, ''];
          var missing = b.state === 'not-configured' ? 'URL and credentials'
            : b.state === 'disabled' ? 'Tick “Enabled”'
            : (b.issues && b.issues.length ? b.issues.join('; ') : '');
          return h('tr', null,
            h('td', null, h('strong', null, b.title), b.findings ? h('span', { class: 'muted small' }, ' · shown on this page') : null,
              h('div', { class: 'help' }, b.description)),
            h('td', null, h('span', { class: 'badge ' + l[1] }, l[0])),
            h('td', { class: 'small' }, admin && b.state !== 'ready' && b.state !== 'planned' ? missing : ''));
        })))),
      admin
        ? h('p', null, h('a', { href: '#/backends' }, 'Configure backends'), h('span', { class: 'muted small' }, ' — start with Wazuh: manager API and indexer.'))
        : h('p', { class: 'muted small' }, 'Ask an administrator to configure the backends.'));
  }

  // ---- findings: one tab per source (Wazuh, Trivy, DefectDojo, Graylog) ----
  var findingsSeverity = SEV_ORDER.slice(); // shared by the tabs that have a severity scale
  var HEALTH_DOT = { ok: 'up', degraded: 'degraded', down: 'down' };

  function sevQuery() {
    return findingsSeverity.length === SEV_ORDER.length ? '' : '?severity=' + encodeURIComponent(findingsSeverity.join(','));
  }

  function sevBar(bySev, total, keyOf) {
    keyOf = keyOf || function (k) { return k; };
    return h('div', { class: 'sev-bar', title: SEV_ORDER.map(function (k) { return k + ': ' + (bySev[keyOf(k)] || 0); }).join(', ') },
      SEV_ORDER.map(function (k) {
        var n = bySev[keyOf(k)] || 0;
        if (!n || !total) return null;
        var span = h('span', { class: k.toLowerCase() });
        span.style.width = (100 * n / total).toFixed(2) + '%'; // CSSOM, permitted by the CSP
        return span;
      }));
  }

  function sevTiles(bySev, keyOf) {
    keyOf = keyOf || function (k) { return k; };
    return h('div', { class: 'sev-tiles' }, SEV_ORDER.filter(function (k) { return findingsSeverity.indexOf(k) >= 0; }).map(function (k) {
      return h('div', { class: 'sev-tile ' + sevClass(k).replace('sev ', '') },
        h('div', { class: 'label' }, k), h('div', { class: 'count' }, String(bySev[keyOf(k)] || 0)));
    }));
  }

  /** A failed source: its error, and a hint that this is an outage rather than "nothing found". */
  function sourceError(title, e) {
    return h('div', { class: 'panel' },
      notice('error', title + ': ' + (e.message || String(e))),
      h('p', { class: 'muted small' }, 'This is a failure of the ' + title + ' backend, not an empty result. Other sources are unaffected; see the status bar for its health.'));
  }

  function short(text, n) {
    var s = String(text || '');
    return s.length > n ? s.slice(0, n) + '…' : s;
  }

  function viewFindings(tab) {
    var me = state.me;
    var summary = h('p', { class: 'muted small' }, 'Loading…');
    var body = h('div');
    mount(h('div', null, h('div', { class: 'page-head' }, h('h1', null, 'Findings'), summary), body));

    api('GET', '/findings/sources').then(function (src) {
      var admin = me.user.role === 'admin';
      var sources = src.backends.filter(function (b) { return b.findings; });
      var usable = sources.filter(function (b) { return b.state === 'ready'; });
      if (usable.length === 0) {
        put(summary);
        put(body, h('div', { class: 'panel' }, sourcesStatus(src.backends, admin)));
        return;
      }
      var current = usable.filter(function (b) { return b.id === tab; })[0] || usable[0];
      var missing = sources.filter(function (b) { return b.state !== 'ready'; });
      var filters = h('div', { class: 'row' });
      var pane = h('div');

      function renderFilters() {
        if (current.id === 'graylog') { put(filters); return; }
        put(filters, h('span', { class: 'muted small' }, 'Severity'), ...SEV_ORDER.map(function (sev) {
          var on = findingsSeverity.indexOf(sev) >= 0;
          return h('button', {
            class: 'chip-toggle ' + (on ? sevClass(sev) : ''),
            'aria-pressed': on ? 'true' : 'false',
            onclick: function () {
              if (on && findingsSeverity.length === 1) return; // keep at least one severity selected
              findingsSeverity = on
                ? findingsSeverity.filter(function (x) { return x !== sev; })
                : SEV_ORDER.filter(function (x) { return x === sev || findingsSeverity.indexOf(x) >= 0; });
              renderFilters();
              load();
            },
          }, sev);
        }));
      }

      function load() {
        var render = { wazuh: wazuhFindings, trivy: trivyFindings, defectdojo: defectdojoFindings, graylog: graylogEvents }[current.id];
        render(pane, summary, current);
      }

      var tabs = h('div', { class: 'source-tabs', role: 'tablist' }, usable.map(function (b) {
        var dot = HEALTH_DOT[b.health];
        return h('a', {
          href: '#/findings/' + b.id, role: 'tab',
          class: 'source-tab' + (b.id === current.id ? ' active' : ''),
          'aria-selected': b.id === current.id ? 'true' : 'false',
          title: b.health && b.health !== 'ok' ? b.title + ' health: ' + b.health : b.description,
        }, dot && dot !== 'up' ? h('span', { class: 'dot ' + dot, 'aria-hidden': 'true' }) : null, b.title);
      }));

      put(body,
        tabs,
        missing.length
          ? h('p', { class: 'muted small' }, 'Not shown: ', missing.map(function (b) { return b.title; }).join(', '), ' (not set up). ',
              admin ? h('a', { href: '#/backends' }, 'Configure backends') : null)
          : null,
        filters,
        pane);
      renderFilters();
      load();
    }).catch(function (e) { put(summary); put(body, notice('error', e.message)); });
  }

  // ---- fix first: ranked actions with the evidence behind them ----
  var TIER_TITLE = { A1: 'Fix now', A2: 'Fix next', A3: 'Plan', A4: 'Routine' };
  var EXPOSURE_TEXT = { confirmed: 'internet, confirmed', declared: 'internet, declared', observed: 'internet, seen', internal: 'internal', unknown: 'exposure unknown' };
  var ATTACK_TEXT = { cve_matched: 'attack names its CVE', reached: 'reached by attacks', blocked: 'blocked or scanned only', none: 'no attacks seen', unknown: 'attacks unknown' };
  var fixFilter = { hours: '24', tier: '', attacked: '0' };

  function viewFixFirst() {
    var admin = state.me.user.role === 'admin';
    var summary = h('p', { class: 'muted small' }, 'Loading…');
    var body = h('div');
    var controls = h('div', { class: 'row' });
    var seq = 0;
    mount(h('div', null, h('div', { class: 'page-head' }, h('h1', null, 'Fix first'), summary), controls, body));

    function choose(key, label, options) {
      return h('label', { class: 'inline' }, label, h('select', {
        onchange: function (ev) { fixFilter[key] = ev.target.value; load(0); },
      }, options.map(function (o) { return h('option', { value: o[0], selected: fixFilter[key] === o[0] }, o[1]); })));
    }
    put(controls,
      choose('hours', 'Attacks in', [['24', '24 hours'], ['72', '3 days'], ['168', '7 days']]),
      choose('tier', 'Tier', [['', 'All']].concat(Object.keys(TIER_TITLE).map(function (t) { return [t, t + ' ' + TIER_TITLE[t]]; }))),
      choose('attacked', 'Services', [['0', 'All'], ['1', 'Reached by attacks']]));

    function evidenceItem(e) {
      return h('li', null, e.summary,
        h('span', { class: 'muted small' }, ' · ', e.source.replace('_', ' '), e.observed_at ? ' · ' + fmt(e.observed_at) : ''),
        e.lookup ? h('div', null, h('code', { class: 'args' }, e.lookup.tool + ' ' + JSON.stringify(e.lookup.args))) : null);
    }

    function actionCard(a, byId) {
      return h('details', { class: 'panel fix' },
        h('summary', null,
          h('span', { class: 'badge fix-tier' + (a.tier === 'A1' ? ' on' : '') }, a.tier + ' ' + TIER_TITLE[a.tier]),
          h('strong', { class: 'fix-target' }, a.target),
          h('span', { class: 'badges' },
            a.services.length
              ? a.services.map(function (s) { return h('span', { class: 'badge on' }, s.name + ' · ' + EXPOSURE_TEXT[s.exposure] + ' · ' + ATTACK_TEXT[s.attack]); })
              : h('span', { class: 'badge' }, 'not in the service map'),
            h('span', { class: 'badge' }, a.confidence + ' confidence'),
            h('span', { class: 'badge' }, a.cve_count + (a.cve_count === 1 ? ' CVE' : ' CVEs'))),
          h('span', { class: 'fix-do' }, a.recommendation)),
        h('p', { class: 'muted small' }, a.caveat),
        h('h3', null, 'Why'), h('ul', null, a.reasons.map(function (r) { return h('li', null, r); })),
        h('h3', null, 'Confidence: ' + a.confidence), h('ul', null, a.confidence_reasons.map(function (r) { return h('li', null, r); })),
        h('h3', null, 'CVEs'), h('div', { class: 'badges' }, a.cves.map(function (c) {
          return h('span', { class: 'badge' + (c.kev ? ' on' : '') }, c.cve + ' · ' + c.severity + (c.kev ? ' · KEV' : '') + (c.epss !== undefined ? ' · EPSS ' + c.epss : ''));
        }), a.cves_truncated ? h('span', { class: 'badge' }, '+' + a.cves_truncated + ' more') : null),
        h('h3', null, 'Evidence'), h('ul', null, a.evidence.map(function (id) { return byId[id] ? evidenceItem(byId[id]) : null; })));
    }

    function load(offset) {
      var mine = ++seq;
      var more = offset > 0;
      if (!more) put(body, h('p', { class: 'muted' }, 'Reading the backends…'));
      var q = '?hours=' + fixFilter.hours + '&attacked=' + fixFilter.attacked + (fixFilter.tier ? '&tier=' + fixFilter.tier : '') + '&offset=' + offset;
      return api('GET', '/priorities' + q).then(function (r) {
        if (mine !== seq) return;
        var byId = {};
        r.evidence.forEach(function (e) { byId[e.id] = e; });
        put(summary, Object.keys(TIER_TITLE).map(function (t) { return r.by_tier[t] + ' ' + TIER_TITLE[t].toLowerCase(); }).join(' · '));
        var cards = r.actions.map(function (a) { return actionCard(a, byId); });
        var shown = offset + r.returned;
        var next = shown < r.matching
          ? h('button', { onclick: function (ev) { var b = ev.target; busy(b, load(shown).then(function () { b.remove(); })); } }, 'Show more (' + (r.matching - shown) + ' left)')
          : null;
        if (more) { body.append.apply(body, cards.concat(next ? [next] : [])); return; }
        put(body,
          r.gaps.length
            ? h('details', { class: 'notice', open: r.gaps.length <= 4 },
                h('summary', null, r.gaps.length + (r.gaps.length === 1 ? ' gap' : ' gaps') + ' in what is known'),
                h('ul', null, r.gaps.map(function (g) { return h('li', null, g); })),
                admin ? h('a', { href: '#/services' }, 'Edit the service map') : null)
            : null,
          cards.length ? cards : h('p', { class: 'muted' }, 'No action matches the filter. Read the gaps above before taking that as good news.'),
          next,
          h('p', { class: 'muted small' }, r.rules));
      }).catch(function (e) {
        if (mine !== seq) return;
        if (more) throw e;
        put(summary);
        put(body, notice('error', e.message), admin ? h('a', { href: '#/backends' }, 'Configure backends') : null);
      });
    }
    load(0);
  }

  // ---- services: the map that links hosts, images and addresses (administrators) ----
  function viewServices() {
    var listBox = h('div');
    var formBox = h('div');
    var suggestBox = h('div', { class: 'panel' }, h('p', { class: 'muted' }, 'Looking for what is not mapped…'));
    var coverage = h('p', { class: 'muted small' });
    var services = [];
    var known = { agents: [], images: [] };
    mount(h('div', null,
      h('div', { class: 'page-head' }, h('h1', null, 'Services'), coverage),
      h('p', { class: 'muted' }, 'Links hosts, images and public addresses that belong together, so SocBridge can tell which vulnerabilities are exposed and attacked. It uses only the links you make here.'),
      listBox, formBox, suggestBox));

    var EMPTY = { name: '', importance: 'normal', exposure: 'unknown', endpoints: [], agents: [], images: [], logTargets: [], note: '' };
    function lines(text) { return text.split('\n').map(function (l) { return l.trim(); }).filter(Boolean); }
    // "host, alias 443": aliases separated by commas, then an optional port.
    function parseAddress(line) {
      var m = /^(.*?)(?:\s+(\d{1,5}))?$/.exec(line);
      var out = { hosts: m[1].split(',').map(function (x) { return x.trim(); }).filter(Boolean) };
      if (m[2]) out.port = Number(m[2]);
      return out;
    }

    function openForm(s, note) {
      function text(v, ph) { return h('input', { type: 'text', value: v || '', placeholder: ph }); }
      function pick(v, opts) { return h('select', null, opts.map(function (o) { return h('option', { value: o[0], selected: o[0] === v }, o[1]); })); }
      function area(v, ph) { return h('textarea', { value: v, placeholder: ph }); }
      var name = text(s.name, 'e.g. Webmail');
      var importance = pick(s.importance, [['critical', 'Critical'], ['high', 'High'], ['normal', 'Normal'], ['low', 'Low']]);
      var exposure = pick(s.exposure, [['unknown', 'Not known'], ['internet', 'Internet-facing'], ['internal', 'Internal only']]);
      var endpoints = area(s.endpoints.map(function (e) { return e.hosts.join(', ') + (e.port ? ' ' + e.port : ''); }).join('\n'), '203.0.113.1, mail.example.com 443');
      var agentIds = known.agents.map(function (a) { return a.id; });
      var boxes = known.agents.concat(s.agents.filter(function (id) { return agentIds.indexOf(id) < 0; }).map(function (id) { return { id: id, name: 'agent ' + id }; }))
        .map(function (a) { return { id: a.id, name: a.name, el: h('input', { type: 'checkbox', checked: s.agents.indexOf(a.id) >= 0 }) }; });
      var images = area(s.images.join('\n'), 'nginx:1.27');
      var targets = area(s.logTargets.map(function (t) { return t.ip + (t.port ? ' ' + t.port : ''); }).join('\n'), '192.0.2.10 8443');
      var remark = text(s.note, 'Optional');
      var err = h('div');
      var save = h('button', { class: 'primary', onclick: function () {
        put(err);
        var body = {
          name: name.value, importance: importance.value, exposure: exposure.value,
          endpoints: lines(endpoints.value).map(parseAddress),
          agents: boxes.filter(function (b) { return b.el.checked; }).map(function (b) { return b.id; }),
          images: lines(images.value),
          logTargets: lines(targets.value).map(function (l) { var a = parseAddress(l); return a.port ? { ip: a.hosts[0] || '', port: a.port } : { ip: a.hosts[0] || '' }; }),
        };
        if (remark.value.trim()) body.note = remark.value;
        busy(save, api(s.id ? 'PUT' : 'POST', '/services' + (s.id ? '/' + encodeURIComponent(s.id) : ''), body)
          .then(function () { put(formBox); load(); })
          .catch(function (e) { put(err, notice('error', e.message)); }));
      } }, s.id ? 'Save' : 'Add service');
      function field(label, el, help) { return [h('label', null, label, el), help ? h('div', { class: 'help' }, help) : null]; }
      put(formBox, h('div', { class: 'panel' },
        h('h2', null, s.id ? 'Edit ' + s.name : 'New service'),
        note ? notice('', note) : null,
        field('Name', name),
        field('Importance', importance, 'Orders actions within a tier.'),
        field('Exposure', exposure),
        field('Public addresses', endpoints, 'One endpoint per line: names and IP of the same endpoint separated by commas, then the port. Without a port, every port on those hosts belongs to this service.'),
        h('label', null, 'Wazuh agents'),
        boxes.length ? h('div', { class: 'row tight' }, boxes.map(function (b) { return h('label', { class: 'inline' }, b.el, b.name); })) : h('div', { class: 'help' }, 'No agents found.'),
        field('Trivy images', images, 'One per line, exactly as Trivy names them.'),
        field('Addresses in firewall logs', targets, 'Only if different from the public addresses: one IP per line, then an optional port.'),
        field('Note', remark),
        err,
        h('div', { class: 'row' }, save, h('button', { onclick: function () { put(formBox); } }, 'Cancel'))));
      formBox.scrollIntoView({ block: 'start' });
      name.focus();
    }

    function merge(s, x) {
      function union(a, b) { return a.concat(b.filter(function (v) { return a.indexOf(v) < 0; })); }
      return Object.assign({}, s, {
        exposure: s.exposure === 'unknown' ? x.exposure : s.exposure,
        endpoints: s.endpoints.concat(x.endpoints), agents: union(s.agents, x.agents), images: union(s.images, x.images),
      });
    }

    function renderList() {
      put(listBox, h('div', { class: 'panel' },
        services.length === 0 ? h('p', { class: 'muted' }, 'No services yet. Start from a suggestion below, or add one.') :
        h('div', { class: 'table-wrap' }, h('table', null,
          h('thead', null, h('tr', null, ['Service', 'Importance', 'Exposure', 'Addresses', 'Agents', 'Images', ''].map(function (t) { return h('th', null, t); }))),
          h('tbody', null, services.map(function (s) {
            var del = h('button', { class: 'danger', onclick: function () {
              if (!confirm('Delete the service "' + s.name + '"? Its links are removed; nothing in the backends changes.')) return;
              busy(del, api('DELETE', '/services/' + encodeURIComponent(s.id)).then(load));
            } }, 'Delete');
            return h('tr', null,
              h('td', null, s.name), h('td', null, s.importance), h('td', null, s.exposure),
              h('td', null, String(s.endpoints.length)), h('td', null, String(s.agents.length)), h('td', null, String(s.images.length)),
              h('td', null, h('div', { class: 'row tight' }, h('button', { onclick: function () { openForm(s); } }, 'Edit'), del)));
          })))),
        h('div', { class: 'row' }, h('button', { onclick: function () { openForm(EMPTY); } }, 'Add service'))));
    }

    function renderSuggestions(r) {
      var c = r.coverage;
      function part(x, what) { return x ? x.mapped + ' of ' + x.total + ' ' + what : what + ' not read'; }
      put(coverage, 'Mapped: ', part(c.agents, 'agents'), ' · ', part(c.images, 'images'), ' · ', part(c.endpoints, 'endpoints'));
      put(suggestBox,
        h('h2', null, 'Not mapped yet'),
        r.errors.map(function (e) { return notice('error', e.source + ': ' + e.message); }),
        r.suggestions.length === 0 ? h('p', { class: 'muted' }, r.errors.length ? 'No suggestions from the sources that could be read.' : 'Everything found is mapped.') :
        h('div', { class: 'table-wrap' }, h('table', null,
          h('thead', null, h('tr', null, ['Found', 'Why', 'Put it in', ''].map(function (t) { return h('th', null, t); }))),
          h('tbody', null, r.suggestions.map(function (x) {
            var into = h('select', { 'aria-label': 'Service for ' + x.name }, h('option', { value: '' }, 'New service'), services.map(function (s) { return h('option', { value: s.id }, s.name); }));
            return h('tr', null,
              h('td', null, h('strong', null, x.name), x.images.length ? h('div', null, h('code', { class: 'args' }, x.images.join(', '))) : null),
              h('td', null, x.reasons.map(function (t) { return h('div', { class: 'small' }, t); })),
              h('td', null, into),
              h('td', null, h('button', { onclick: function () {
                var s = services.filter(function (y) { return y.id === into.value; })[0];
                openForm(merge(s || Object.assign({}, EMPTY, { name: x.name }), x), 'A suggestion: check every link before saving.');
              } }, 'Review')));
          })))));
    }

    function load() {
      return api('GET', '/services').then(function (list) {
        services = list;
        renderList();
        return api('GET', '/services/suggestions').then(function (r) { known = r.known; renderSuggestions(r); });
      }).catch(function (e) { put(suggestBox, notice('error', e.message)); });
    }
    load();
  }

  // ---- attack trend: one small chart per attack category, all on the same time axis ----
  // Remembered across page switches: a preset, or an absolute range picked as dates.
  var attackRange = { window: '7d' };
  var attackMeasure = 'attempts';
  var ATTACK_WINDOWS = [['24h', '24 hours'], ['7d', '7 days'], ['30d', '30 days'], ['90d', '3 months'], ['1y', '1 year'], ['3y', '3 years']];
  var ATTACK_MEASURES = [['attempts', 'Attempts'], ['unique_ips', 'Unique IPs']];

  function viewAttacks() {
    var controls = h('div', { class: 'attack-controls' });
    var groups = h('div');
    var detail = h('div', { class: 'panel' });
    var selected = null; // { group, id, column } — column null means the whole window
    var loadSeq = 0; // drops answers to requests that a newer one replaced
    var detailSeq = 0;
    var sources = [];
    mount(h('div', null, h('div', { class: 'page-head' }, h('h1', null, 'Attack trend')), controls, groups, detail));

    function num(n) { return Number(n).toLocaleString(); }

    function toggles(label, options, current, pick) {
      return h('div', { class: 'row trend-window', role: 'group', 'aria-label': label }, options.map(function (o) {
        return h('button', {
          class: 'chip-toggle', 'aria-pressed': o[0] === current ? 'true' : 'false',
          onclick: function () { if (o[0] !== current) pick(o[0]); },
        }, o[1]);
      }));
    }

    /** yyyy-mm-dd in local time, as a date field wants it. */
    function day(d) {
      function two(n) { return (n < 10 ? '0' : '') + n; }
      return d.getFullYear() + '-' + two(d.getMonth() + 1) + '-' + two(d.getDate());
    }

    function renderControls() {
      var today = day(new Date());
      var from = h('input', { type: 'date', max: today, 'aria-label': 'From date', value: attackRange.days ? attackRange.days[0] : '' });
      var to = h('input', { type: 'date', max: today, 'aria-label': 'To date', value: attackRange.days ? attackRange.days[1] : today });
      var error = h('span', { class: 'attack-change worse', role: 'alert' });
      function show() {
        if (!from.value || !to.value) { put(error, 'Pick both dates.'); return; }
        // Whole local days, the last one included.
        var a = new Date(from.value + 'T00:00:00');
        var b = new Date(to.value + 'T00:00:00');
        if (isNaN(a) || isNaN(b) || a > b) { put(error, 'The first date must not be after the second.'); return; }
        if (a > new Date()) { put(error, 'The first date is in the future.'); return; }
        b.setDate(b.getDate() + 1);
        if (b - a > 1830 * 86400000) { put(error, 'At most five years.'); return; }
        attackRange = { days: [from.value, to.value], from: a.toISOString(), to: b.toISOString() };
        renderControls();
        load();
      }
      put(controls,
        toggles('Time window', ATTACK_WINDOWS, attackRange.window, function (w) { attackRange = { window: w }; renderControls(); load(); }),
        toggles('Count', ATTACK_MEASURES, attackMeasure, function (m) { attackMeasure = m; renderControls(); sources.forEach(function (g) { g.render(); }); }),
        h('form', { class: 'row attack-dates', onsubmit: function (ev) { ev.preventDefault(); show(); } },
          from, h('span', { class: 'muted' }, 'to'), to,
          h('button', { class: 'chip-toggle' + (attackRange.days ? ' on' : '') }, 'Show dates'), error));
    }

    function rangeQuery() {
      return attackRange.from
        ? 'from=' + encodeURIComponent(attackRange.from) + '&to=' + encodeURIComponent(attackRange.to)
        : 'window=' + attackRange.window;
    }

    function stepText(seconds) {
      var hours = seconds / 3600;
      return hours >= 24 ? (hours === 24 ? '1 day' : hours / 24 + ' days') : hours === 1 ? '1 hour' : hours + ' hours';
    }

    function topList(title, rows, mono) {
      if (!rows || !rows.length) return null;
      return h('div', null, h('h3', null, title), h('table', null, h('tbody', null, rows.map(function (x) {
        return h('tr', null, h('td', null, mono ? h('span', { class: 'data' }, x.key) : x.key),
          h('td', { class: 'num' }, x.ports ? x.ports + ' ports' : num(x.count)));
      }))));
    }

    function wazuhDetails(d) {
      return [
        h('div', { class: 'attack-tops' },
          topList('Source IPs', d.top_ips, true), topList('Countries', d.top_countries),
          topList('User names tried', d.top_users, true), topList('Targets', d.top_agents), topList('Rules', d.top_rules)),
        d.alerts.length ? [h('h3', null, 'Newest alerts'), h('div', { class: 'table-wrap' }, h('table', null,
          h('thead', null, h('tr', null, h('th', null, 'Time'), h('th', null, 'Target'), h('th', null, 'Source IP'), h('th', null, 'User'), h('th', null, 'Rule'))),
          h('tbody', null, d.alerts.map(function (a) {
            var x = a.data || {}, rule = a.rule || {};
            return h('tr', null,
              h('td', null, fmt(a.timestamp)),
              h('td', null, (a.agent && a.agent.name) || '—'),
              h('td', null, h('span', { class: 'data' }, x.srcip || '—'), a.GeoLocation && a.GeoLocation.country_name ? h('div', { class: 'muted small' }, a.GeoLocation.country_name) : null),
              h('td', null, h('span', { class: 'data' }, x.dstuser || x.srcuser || '—')),
              h('td', null, rule.description || '—', h('div', { class: 'data muted' }, rule.id || '')));
          }))))] : null];
    }

    function firewallDetails(d) {
      return [
        h('div', { class: 'attack-tops' },
          topList('Source IPs', d.top_ips, true), topList('Ports', d.top_ports, true),
          topList('Targets', d.top_targets, true), topList('Signatures', d.top_signatures)),
        d.messages.length ? [h('h3', null, 'Newest messages'), h('div', { class: 'table-wrap' }, h('table', null,
          h('thead', null, h('tr', null, h('th', null, 'Time'), h('th', null, 'Source IP'), h('th', null, 'Target'), h('th', null, 'Port'), h('th', null, 'Signature'))),
          h('tbody', null, d.messages.map(function (m) {
            return h('tr', null,
              h('td', null, fmt(m.timestamp)),
              h('td', null, h('span', { class: 'data' }, m.src_ip || '—')),
              h('td', null, h('span', { class: 'data' }, m.dst_ip || '—')),
              h('td', null, h('span', { class: 'data' }, m.dst_port === undefined || m.dst_port === '-' ? '—' : String(m.dst_port))),
              h('td', null, m.UNIFIipsSignature && m.UNIFIipsSignature !== '-' ? m.UNIFIipsSignature : '—'));
          }))))] : null];
    }

    /** One panel of charts from one backend; it loads and fails on its own. */
    function group(id, title, path, note, details) {
      var head = h('p', { class: 'muted small' });
      var charts = h('div');
      var data = null;
      var el = h('div', { class: 'panel' }, h('div', { class: 'page-head' }, h('h2', null, title), head), charts);

      function columnRange(i) {
        var start = Date.parse(data.columns_from) + i * data.step_seconds * 1000;
        return [Math.max(start, Date.parse(data.from)), Math.min(start + data.step_seconds * 1000, Date.parse(data.to))];
      }

      function change(c) {
        if (!c.previous) return h('span', { class: 'muted small' }, 'no earlier data');
        var now = c[attackMeasure], before = c.previous[attackMeasure];
        if (now === before) return h('span', { class: 'muted small' }, '■ unchanged');
        var text = before ? Math.round(100 * Math.abs(now - before) / before) + '%' : 'new';
        return h('span', { class: 'attack-change ' + (now > before ? 'worse' : 'better'), title: num(before) + ' in the period before' },
          now > before ? '▲ ' : '▼ ', text, h('span', { class: 'muted' }, ' vs period before'));
      }

      function chart(c) {
        var max = 1;
        c.points.forEach(function (p) { max = Math.max(max, p[attackMeasure]); });
        return h('div', { class: 'attack-bars', role: 'group', 'aria-label': c.title + ' over time, highest ' + num(max) },
          c.points.map(function (p, i) {
            var r = columnRange(i);
            var when = fmt(r[0]) + ' – ' + fmt(r[1]);
            if (!p.attempts) {
              var none = !data.data_from || r[1] <= Date.parse(data.data_from);
              return h('span', { class: 'col' + (none ? ' nodata' : ''), title: when + (none ? ': no data this far back' : ': none') });
            }
            var text = when + ': ' + num(p.attempts) + ' attempts, ' + num(p.unique_ips) + ' unique IPs' + (p.brute_force ? ', ' + num(p.brute_force) + ' brute-force alerts' : '');
            var on = !!selected && selected.group === id && selected.id === c.id && selected.column === i;
            return h('button', {
              class: 'col' + (on ? ' on' : ''), title: text, 'aria-label': text, 'aria-pressed': on ? 'true' : 'false',
              'data-group': id, 'data-category': c.id, 'data-column': String(i),
              onclick: function () { select(c, i); },
            }, p[attackMeasure] ? h('span', { class: 'bar' + (p.brute_force ? ' brute' : ''), style: { height: Math.max(4, Math.round(100 * p[attackMeasure] / max)) + '%' } }) : null);
          }));
      }

      function render() {
        if (!data) return;
        var seen = data.categories.filter(function (c) { return c.attempts; });
        var quiet = data.categories.filter(function (c) { return !c.attempts && !c.error; });
        var partial = data.data_from && Date.parse(data.data_from) > Date.parse(data.from) + data.step_seconds * 1000;
        put(head, 'One bar = ' + stepText(data.step_seconds));
        put(charts,
          partial ? notice('warning', 'Data only reaches back to ' + fmt(data.data_from) + '. Earlier parts of the charts are empty.') : null,
          data.categories.filter(function (c) { return c.error; }).map(function (c) { return notice('error', c.title + ' could not be read: ' + c.error); }),
          seen.length === 0 ? h('p', { class: 'muted' }, data.data_from ? 'No attacks in this period.' : 'No data found for this period.') : null,
          seen.map(function (c) {
            return h('div', { class: 'attack-row' },
              h('div', { class: 'attack-head' },
                h('button', { class: 'attack-name', title: c.description, onclick: function () { select(c, null); } }, c.title),
                h('div', { class: 'count' }, num(c[attackMeasure])),
                change(c),
                c.brute_force ? h('div', { class: 'attack-change worse' }, '◆ ' + num(c.brute_force) + ' brute-force alerts') : null),
              chart(c));
          }),
          seen.length ? h('div', { class: 'attack-axis help' }, h('span', null, fmt(data.from)), h('span', null, fmt(data.to))) : null,
          h('p', { class: 'muted small' },
            seen.length ? 'Each chart has its own scale. Select a name or a bar for details. ' : '',
            quiet.length ? 'Nothing seen: ' + quiet.map(function (c) { return c.title; }).join(', ') + '. ' : '',
            note));
      }

      function select(c, column) {
        selected = { group: id, id: c.id, column: column };
        Array.prototype.forEach.call(groups.querySelectorAll('button.col'), function (b) {
          var on = b.getAttribute('data-group') === id && b.getAttribute('data-category') === c.id && b.getAttribute('data-column') === String(column);
          b.classList.toggle('on', on);
          b.setAttribute('aria-pressed', on ? 'true' : 'false');
        });
        var r = column === null ? [Date.parse(data.from), Date.parse(data.to)] : columnRange(column);
        var seq = ++detailSeq;
        put(detail, h('p', { class: 'muted' }, 'Loading details…'));
        api('GET', path + '/' + encodeURIComponent(c.id) + '?from=' + encodeURIComponent(new Date(r[0]).toISOString()) + '&to=' + encodeURIComponent(new Date(r[1]).toISOString())).then(function (d) {
          if (seq !== detailSeq) return;
          put(detail,
            h('div', { class: 'page-head' }, h('h2', null, c.title), h('span', { class: 'muted small' }, fmt(d.from) + ' – ' + fmt(d.to))),
            h('p', { class: 'muted small' }, c.description),
            details(d));
          detail.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }).catch(function (e) { if (seq === detailSeq) put(detail, notice('error', e.message)); });
      }

      return {
        el: el,
        render: render,
        load: function (seq) {
          data = null;
          put(head);
          put(charts, h('p', { class: 'muted' }, 'Loading attacks…'));
          api('GET', path + '?' + rangeQuery()).then(function (d) {
            if (seq !== loadSeq) return;
            data = d;
            render();
          }).catch(function (e) { if (seq === loadSeq) put(charts, notice('error', e.message)); });
        },
      };
    }

    function load() {
      var seq = ++loadSeq;
      detailSeq++;
      selected = null;
      put(detail, h('p', { class: 'muted' }, 'Select an attack type or a bar to see who is behind it.'));
      sources.forEach(function (g) { g.load(seq); });
    }

    put(groups, h('p', { class: 'muted' }, 'Loading…'));
    renderControls();
    api('GET', '/findings/sources').then(function (src) {
      var graylog = src.backends.filter(function (b) { return b.id === 'graylog'; })[0];
      if (src.wazuh === 'ready') sources.push(group('wazuh', 'Logins and services · Wazuh', '/findings/attacks',
        'Red bars include brute-force alerts: Wazuh saw repeated failures against that service. Counts are Wazuh alerts; some services log one attempt as several alerts.', wazuhDetails));
      if (graylog && graylog.state === 'ready') sources.push(group('graylog', 'Network edge · Graylog', '/findings/firewall',
        'Port scans are also part of the firewall blocks; they are counted over the whole period, so a longer period finds slower scans. Which messages count is set on the Graylog backend.', firewallDetails));
      if (!sources.length) {
        put(groups, notice('warning', 'This page needs Wazuh with its indexer, or Graylog. Neither is ready.'));
        put(detail);
        return;
      }
      put(groups, sources.map(function (g) { return g.el; }));
      load();
    }).catch(function (e) { put(groups, notice('error', e.message)); });
  }

  // ---- pew pew map: real alerts on a low-resolution amber screen ----
  // Equirectangular, half a degree per pixel; shots follow great circles.
  var MAP_MODES = [['live', 'Live'], ['24h', 'Replay 24 hours'], ['7d', 'Replay 7 days']];
  var mapMode = 'live';
  var mapSound = false;
  var MAP_STYLES = [['missiles', 'Missiles'], ['squares', 'Squares']];
  // Network edge, from Graylog. Plain firewall blocks are mostly background noise, so they start off.
  var MAP_LAYERS = [['port_scan', 'Port scans'], ['ips', 'IPS'], ['firewall', 'Firewall']];
  var mapLayers = { port_scan: true, ips: true, firewall: false };
  var mapStyle = 'missiles'; // shots flying to the target, or squares growing at the source

  function viewAttackMap() {
    var W = 720, H = 290, TOP = 85; // latitudes 85 N to 60 S
    var REPLAY_MS = { '24h': 120000, '7d': 300000 };
    var FLIGHT = 1100, FADE = 900;
    var reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    var css = getComputedStyle(document.documentElement);
    function color(name) { return css.getPropertyValue('--crt-' + name).trim(); }
    var colors = {};
    ['ssh', 'smtp', 'imap', 'ftp', 'other_login', 'web', 'scan', 'other_attack', 'port_scan', 'ips', 'firewall'].forEach(function (id) { colors[id] = color(id.replace('_', '-')); });
    var titles = {}; // category id -> title, for every category seen on the map
    var extras = 0;

    /** Categories come with the alerts: a service seen for the first time gets a colour and a legend entry. */
    function learn(categories) {
      var added = false;
      categories.forEach(function (c) {
        if (!colors[c.id]) colors[c.id] = color('extra-' + (extras++ % 6 + 1));
        if (!Object.prototype.hasOwnProperty.call(titles, c.id)) { titles[c.id] = c.title; added = true; }
      });
      if (added) renderLegend();
    }
    function renderLegend() {
      put(legend, Object.keys(titles).map(function (id) { return h('span', null, h('span', { class: 'key', style: { background: colors[id] } }), titles[id]); }),
        h('span', null, 'Few', h('span', { class: 'crt-ramp' }), 'Many'));
    }

    var canvas = h('canvas', { width: String(W), height: String(H), role: 'img', 'aria-label': 'World map of attack sources' });
    var ctx = canvas.getContext('2d');
    var land = document.createElement('canvas');
    land.width = W; land.height = H;
    var controls = h('div', { class: 'row trend-window' });
    var messages = h('div'), edgeMessages = h('div'), hint = h('div');
    var edgeReady = false; // Graylog is there to ask
    var homeless = null; // null, or 'all' / 'some' when attacks have no target to fly to
    var clock = h('span'), score = h('span'), state_ = h('span');
    var countries = h('ol'), log = h('ol'), legend = h('div', { class: 'crt-legend' });
    var note = h('p', { class: 'muted small' }), edgeNote = h('p', { class: 'muted small' });
    var audio = null;
    var run = 0; // a new mode ends the previous loop and drops its answers
    var paused = false;
    mount(h('div', null,
      h('div', { class: 'page-head' }, h('h1', null, 'Pew pew map'), controls),
      messages, edgeMessages, hint,
      h('div', { class: 'crt' },
        h('div', { class: 'crt-top' }, state_, clock, score),
        canvas, legend,
        h('div', { class: 'crt-boards' }, h('div', null, h('h2', null, 'High scores'), countries), h('div', null, h('h2', null, 'Incoming'), log))),
      note, edgeNote));

    function px(lon, lat) { return [(lon + 180) * 2, (TOP - lat) * 2]; }

    // Heat: countries glow from brown to deep red by how many attacks came from inside their borders.
    var world = null; // [{ rings, boxes, path }]
    var whereCache = {};

    function loadWorld(list) {
      world = list.map(function (rings) {
        var path = new Path2D();
        var boxes = rings.map(function (r) {
          var b = [180, 90, -180, -90];
          for (var i = 0; i < r.length; i += 2) {
            var p = px(r[i], r[i + 1]);
            if (i) path.lineTo(p[0], p[1]); else path.moveTo(p[0], p[1]);
            b = [Math.min(b[0], r[i]), Math.min(b[1], r[i + 1]), Math.max(b[2], r[i]), Math.max(b[3], r[i + 1])];
          }
          path.closePath();
          return b;
        });
        return { rings: rings, boxes: boxes, path: path };
      });
    }

    function inRing(r, lon, lat) {
      var inside = false;
      for (var i = 0, j = r.length - 2; i < r.length; j = i, i += 2) {
        if ((r[i + 1] > lat) !== (r[j + 1] > lat) && lon < (r[j] - r[i]) * (lat - r[i + 1]) / (r[j + 1] - r[i + 1]) + r[i]) inside = !inside;
      }
      return inside;
    }

    /** Index of the country a place is in; a spot of its own ("lon,lat") for islands and coasts the outlines miss. */
    function areaOf(e) {
      var key = e.lon + ',' + e.lat;
      if (whereCache[key] === undefined) {
        var found = -1;
        for (var c = 0; c < world.length && found < 0; c++) {
          var odd = false; // even-odd, so holes (a country inside another) do not count
          world[c].rings.forEach(function (r, i) {
            var b = world[c].boxes[i];
            if (e.lon >= b[0] && e.lon <= b[2] && e.lat >= b[1] && e.lat <= b[3] && inRing(r, e.lon, e.lat)) odd = !odd;
          });
          if (odd) found = c;
        }
        whereCache[key] = found < 0 ? key : found;
      }
      return whereCache[key];
    }

    function rgb(hex) { return [1, 3, 5].map(function (i) { return parseInt(hex.slice(i, i + 2), 16); }); }
    var RAMP = ['land', 'heat-low', 'heat-mid', 'heat-high'].map(function (n) { return rgb(color(n)); });
    function ramp(t) {
      var x = Math.min(0.9999, Math.max(0, t)) * (RAMP.length - 1), i = Math.floor(x);
      return 'rgb(' + RAMP[i].map(function (v, k) { return Math.round(v + (RAMP[i + 1][k] - v) * (x - i)); }).join(',') + ')';
    }

    function drawLand(heat) {
      var g = land.getContext('2d');
      var max = 1;
      Object.keys(heat).forEach(function (k) { max = Math.max(max, heat[k]); });
      // Logarithmic, or one busy country would leave all the others cold.
      function shade(n) { return n ? ramp(0.15 + 0.85 * Math.log(1 + n) / Math.log(1 + max)) : color('land'); }
      g.clearRect(0, 0, W, H);
      g.strokeStyle = color('line');
      g.lineWidth = 0.6;
      world.forEach(function (c, i) {
        g.fillStyle = shade(heat[i]);
        g.fill(c.path, 'evenodd');
        g.stroke(c.path);
      });
      Object.keys(heat).forEach(function (k) {
        if (k.indexOf(',') < 0 || !heat[k]) return;
        var p = px.apply(null, k.split(',').map(Number));
        g.fillStyle = shade(heat[k]);
        g.fillRect(Math.round(p[0]) - 2, Math.round(p[1]) - 2, 4, 4);
      });
    }

    /** Points along the great circle between two places. */
    function greatCircle(a, b) {
      var rad = Math.PI / 180;
      function vec(p) {
        var la = p.lat * rad, lo = p.lon * rad;
        return [Math.cos(la) * Math.cos(lo), Math.cos(la) * Math.sin(lo), Math.sin(la)];
      }
      var u = vec(a), v = vec(b);
      var w = Math.acos(Math.max(-1, Math.min(1, u[0] * v[0] + u[1] * v[1] + u[2] * v[2])));
      var n = 64, out = [];
      for (var i = 0; i <= n; i++) {
        var t = i / n;
        var s1 = w < 1e-6 ? 1 - t : Math.sin((1 - t) * w) / Math.sin(w);
        var s2 = w < 1e-6 ? t : Math.sin(t * w) / Math.sin(w);
        var x = s1 * u[0] + s2 * v[0], y = s1 * u[1] + s2 * v[1], z = s1 * u[2] + s2 * v[2];
        out.push(px(Math.atan2(y, x) / rad, Math.atan2(z, Math.sqrt(x * x + y * y)) / rad));
      }
      return out;
    }

    function pew() {
      if (!mapSound || !audio) return;
      var t = audio.currentTime;
      var osc = audio.createOscillator(), gain = audio.createGain();
      osc.type = 'square';
      osc.frequency.setValueAtTime(880, t);
      osc.frequency.exponentialRampToValueAtTime(110, t + 0.15);
      gain.gain.setValueAtTime(0.03, t);
      gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.15);
      osc.connect(gain);
      gain.connect(audio.destination);
      osc.start(t);
      osc.stop(t + 0.16);
    }

    /** Without a target a missile is drawn as a square, so say why next to the buttons. */
    function renderHint() {
      put(hint, mapStyle === 'missiles' && homeless ? notice('info', [
        homeless === 'all' ? 'Missiles need a target, and none is set, so attacks are shown as squares. ' : 'Some machines have no position, so attacks on them are shown as squares. ',
        state.me.user.role === 'admin' ? h('a', { href: '#/backends' }, 'Set where your machines are on the Wazuh backend') : 'Ask an administrator to set where your machines are on the Wazuh backend', '.']) : null);
    }

    function renderControls() {
      renderHint();
      put(controls,
        MAP_MODES.map(function (m) {
          return h('button', {
            class: 'chip-toggle', 'aria-pressed': m[0] === mapMode ? 'true' : 'false',
            onclick: function () { mapMode = m[0]; paused = false; renderControls(); start_(); },
          }, m[1]);
        }),
        h('span', { class: 'row trend-window map-style', role: 'group', 'aria-label': 'How attacks are shown' }, MAP_STYLES.map(function (o) {
          return h('button', {
            class: 'chip-toggle', 'aria-pressed': o[0] === mapStyle ? 'true' : 'false',
            onclick: function () { mapStyle = o[0]; renderControls(); },
          }, o[1]);
        })),
        edgeReady ? h('span', { class: 'row trend-window map-style', role: 'group', 'aria-label': 'Network edge layers' }, MAP_LAYERS.map(function (l) {
          return h('button', {
            class: 'chip-toggle', 'aria-pressed': mapLayers[l[0]] ? 'true' : 'false',
            onclick: function () { mapLayers[l[0]] = !mapLayers[l[0]]; renderControls(); start_(); },
          }, l[1]);
        })) : null,
        h('button', { class: 'chip-toggle', 'aria-pressed': paused ? 'true' : 'false', onclick: function () { paused = !paused; renderControls(); } }, 'Pause'),
        h('button', {
          class: 'chip-toggle', 'aria-pressed': mapSound ? 'true' : 'false',
          onclick: function () {
            mapSound = !mapSound;
            // Browsers allow sound only after a click, so the context starts here.
            var Ctx = window.AudioContext || window.webkitAudioContext;
            if (mapSound && !audio && Ctx) audio = new Ctx();
            renderControls();
          },
        }, 'Sound'));
    }

    function start_() {
      var my = ++run;
      var live = mapMode === 'live';
      var windowMs = mapMode === '7d' ? 7 * 86400000 : 86400000;
      var heat = {}, heatChanged = true, heatDrawn = 0, counted = [];
      var queue = [], next = 0, shots = [], scores = {}, hits = 0, targets = {}, seen = {};
      var simFrom = 0, simTo = 0, sim = 0, last = performance.now(), lastPew = 0;
      homeless = null; renderHint();
      titles = {};
      put(messages); put(edgeMessages); put(note); put(edgeNote); put(legend); put(clock); put(score); put(countries); put(log);
      put(state_, 'Loading…');

      function targetOf(e) { return targets[e.agent] || targets[''] || null; }

      /** Adds an attack to scores and heat, or takes one out that is older than the live window. */
      function count(e, n) {
        if (e.repeat) return;
        var place = e.country || 'Unknown', area = areaOf(e);
        hits += n;
        scores[place] = (scores[place] || 0) + n;
        if (scores[place] <= 0) delete scores[place];
        heat[area] = (heat[area] || 0) + n;
        heatChanged = true;
      }

      function fire(e, now) {
        var target = targetOf(e);
        count(e, 1);
        counted.push(e);
        shots.push({ t: now, e: e, from: px(e.lon, e.lat), path: target ? greatCircle(e, target) : null });
        logLine(e);
        if (now - lastPew > 120) { lastPew = now; pew(); }
      }

      function logLine(e) {
        var place = e.country || 'Unknown';
        log.insertBefore(h('li', { style: { color: colors[e.category] || color('text') } },
          h('span', null, (e.ip || '?') + ' ' + place), h('span', null, (titles[e.category] || e.category) + (e.agent ? ' > ' + e.agent : '') + (e.n ? ' ×' + e.n : ''))), log.firstChild);
        while (log.children.length > 8) log.removeChild(log.lastChild);
      }

      function board() {
        put(score, 'Score ' + String(hits).padStart(6, '0'));
        put(countries, Object.keys(scores).sort(function (a, b) { return scores[b] - scores[a]; }).slice(0, 8).map(function (c, i) {
          return h('li', null, h('span', null, (i + 1) + '. ' + c), h('span', null, String(scores[c]).padStart(5, '0')));
        }));
      }

      function dot(p, size, c) {
        ctx.fillStyle = c;
        ctx.fillRect(Math.round(p[0] - size / 2), Math.round(p[1] - size / 2), size, size);
      }

      function draw(now) {
        ctx.globalAlpha = 1;
        ctx.fillStyle = color('bg');
        ctx.fillRect(0, 0, W, H);
        ctx.drawImage(land, 0, 0);
        shots = shots.filter(function (s) { return now - s.t < FLIGHT + FADE; });
        shots.forEach(function (s) {
          var age = now - s.t, c = colors[s.e.category] || color('text');
          ctx.globalAlpha = Math.max(0, 1 - age / (FLIGHT + FADE));
          dot(s.from, 3, c);
          if (!s.path || mapStyle === 'squares') {
            ctx.strokeStyle = c;
            ctx.strokeRect(Math.round(s.from[0] - age / 150) + 0.5, Math.round(s.from[1] - age / 150) + 0.5, Math.round(age / 75), Math.round(age / 75));
            return;
          }
          var head = Math.min(1, age / FLIGHT) * (s.path.length - 1);
          ctx.globalAlpha = age < FLIGHT ? 0.9 : 0.9 * Math.max(0, 1 - (age - FLIGHT) / FADE);
          ctx.strokeStyle = c;
          ctx.lineWidth = 1;
          ctx.beginPath();
          for (var i = Math.max(0, Math.floor(head) - 22); i <= head; i++) {
            var p = s.path[i], q = s.path[i - 1];
            // Crossing the date line continues on the other edge, without a line across the map.
            if (!q || i === Math.max(0, Math.floor(head) - 22) || Math.abs(p[0] - q[0]) > W / 2) ctx.moveTo(p[0], p[1]); else ctx.lineTo(p[0], p[1]);
          }
          ctx.stroke();
          if (age < FLIGHT) dot(s.path[Math.floor(head)], 3, color('text'));
          else {
            var r = Math.round((age - FLIGHT) / 60);
            var end = s.path[s.path.length - 1];
            ctx.strokeRect(Math.round(end[0]) - r + 0.5, Math.round(end[1]) - r + 0.5, 2 * r, 2 * r);
          }
        });
        ctx.globalAlpha = 1;
        Object.keys(targets).forEach(function (k) {
          var p = px(targets[k].lon, targets[k].lat);
          dot(p, 5, color('bg'));
          dot(p, 3, color('text'));
        });
      }

      function frame(now) {
        if (my !== run || !canvas.isConnected) return;
        var dt = Math.min(100, now - last);
        last = now;
        if (!paused) {
          sim = live ? Date.now() : sim + dt * (simTo - simFrom) / REPLAY_MS[mapMode];
          var fired = next;
          while (next < queue.length && queue[next].at <= sim) fire(queue[next++], now);
          if (fired !== next) board();
          if (live) {
            var expired = false;
            while (counted.length && counted[0].seenAt < sim - windowMs) { count(counted.shift(), -1); expired = true; }
            if (expired) board();
          } else if (sim >= simTo) { sim = simFrom; next = first; hits = 0; scores = {}; heat = {}; heatChanged = true; counted = []; board(); }
        }
        if (heatChanged && now - heatDrawn > 250) {
          heatChanged = false;
          heatDrawn = now;
          drawLand(heat);
        }
        put(clock, fmt(sim));
        draw(now);
        requestAnimationFrame(frame);
      }

      function accept(d) {
        learn(d.categories);
        d.targets.forEach(function (t) { targets[t.agent || ''] = t; });
        homeless = !d.targets.length ? 'all' : homeless === 'some' || d.events.some(function (e) { return !targetOf(e); }) ? 'some' : null;
        renderHint();
        d.events.forEach(function (e) { if (!seen[e.id]) { seen[e.id] = true; e.seenAt = e.at; queue.push(e); } });
      }

      // Network edge: one shot per source and time slot, counted once an hour however often the source tries.
      var layers = MAP_LAYERS.map(function (l) { return l[0]; }).filter(function (id) { return mapLayers[id]; });
      var edgeFrom = null, hours = {};
      function fetchEdge(since) {
        if (!edgeReady || !layers.length) return Promise.resolve(null);
        return api('GET', '/findings/edge-map?layers=' + layers.join(',') + '&since=' + encodeURIComponent(new Date(since).toISOString()));
      }
      function acceptEdge(d) {
        if (!d.geoip) {
          put(edgeMessages, notice('info', 'The network edge layers need a GeoIP city database, and none is loaded. ' +
            (d.geoip_file ? 'Place one at ' + d.geoip_file + ' on the server (GEOIP_DB); it is picked up within a minute.' : 'Ask an administrator to add one.')));
          return;
        }
        var failed = d.categories.filter(function (c) { return c.error; });
        put(edgeMessages, failed.map(function (c) { return notice('error', c.title + ' ' + c.error + '.'); }));
        if (edgeFrom === null) {
          put(edgeNote, 'Port scans, IPS and firewall blocks come from Graylog and were stopped at the edge. Each shot sums one source over a time slot, so the exact moment is approximate; scores count a source once per slot. At most ' + d.sources_limit + ' sources per layer. ',
            d.without_location ? d.without_location + ' sources without a position are left out. ' : '',
            /^DBIP/i.test(d.geoip) ? h('a', { href: 'https://db-ip.com', rel: 'noreferrer' }, 'IP Geolocation by DB-IP') : /^GeoLite2/i.test(d.geoip) ? ['Uses GeoLite2 data by ', h('a', { href: 'https://www.maxmind.com', rel: 'noreferrer' }, 'MaxMind')] : null);
        }
        edgeFrom = Date.parse(d.to);
        learn(d.categories.filter(function (c) { return d.events.some(function (e) { return e.category === c.id; }); }));
        d.events.forEach(function (e) {
          if (seen[e.id]) return;
          seen[e.id] = true;
          var hour = e.category + ':' + e.ip + ':' + Math.floor(e.at / 3600000);
          e.repeat = !!hours[hour];
          hours[hour] = true;
          e.seenAt = e.at;
          queue.push(e);
        });
        if (homeless !== 'all' && d.events.some(function (e) { return !targetOf(e); })) { homeless = 'some'; renderHint(); }
      }
      function edgeFailed(e) { if (my === run) put(edgeMessages, notice('error', 'The network edge layers could not be read: ' + e.message)); }

      function pollEdge() {
        if (my !== run || !canvas.isConnected || !edgeReady || !layers.length) return;
        fetchEdge(edgeFrom === null ? asked : edgeFrom).then(function (d) {
          if (my !== run) return;
          var first = edgeFrom === null;
          var before = queue.length;
          acceptEdge(d);
          var fresh = queue.splice(before);
          var now = Date.now();
          if (first) {
            fresh.forEach(function (e) { count(e, 1); counted.push(e); });
            counted.sort(function (a, b) { return a.seenAt - b.seenAt; });
            board();
            return;
          }
          fresh.forEach(function (e, i) { queue.push(Object.assign({}, e, { at: now + i * 60000 / fresh.length })); });
          sortQueue();
        }).catch(edgeFailed).finally(function () { setTimeout(pollEdge, 60000); });
      }
      /** Two sources feed the queue; what is not yet shot must be in order. */
      function sortQueue() {
        var waiting = queue.splice(next).sort(function (a, b) { return a.at - b.at; });
        waiting.forEach(function (e) { queue.push(e); });
      }

      var asked = Date.now() - windowMs;
      function fetchMap(since) { return api('GET', '/findings/attack-map?since=' + encodeURIComponent(new Date(since).toISOString())); }

      function poll() {
        if (my !== run || !canvas.isConnected) return;
        // Overlap: an alert reaches the index some time after it happened. Repeats are dropped by id.
        fetchMap(Date.now() - 180000).then(function (d) {
          if (my !== run) return;
          var before = queue.length;
          accept(d);
          // Late arrivals must not be skipped, so they play now, spread over the poll interval.
          var fresh = queue.splice(before);
          var now = Date.now();
          fresh.forEach(function (e, i) { queue.push(Object.assign({}, e, { at: now + i * 10000 / fresh.length })); });
          sortQueue();
          put(state_, 'Live');
          put(messages);
        }).catch(function (e) { if (my === run) { put(state_, 'No signal'); put(messages, notice('error', e.message)); } })
          .finally(function () { setTimeout(poll, 10000); });
      }

      var worldReady = world ? Promise.resolve() : fetch('/design/world.json?v=2').then(function (r) {
        if (!r.ok) throw new Error('The map could not be loaded');
        return r.json();
      }).then(function (list) { if (!world) loadWorld(list); });

      Promise.all([fetchMap(asked), worldReady, fetchEdge(asked).catch(function (e) { edgeFailed(e); return null; })]).then(function (x) {
        if (my !== run) return;
        var d = x[0];
        accept(d);
        simTo = Date.now();
        simFrom = Math.max(asked, Date.parse(d.complete_from || d.since));
        sim = simFrom;
        if (x[2]) { acceptEdge(x[2]); sortQueue(); }
        // A replay starts where both sources have data.
        while (!live && next < queue.length && queue[next].at < simFrom) next++;
        var first = next;
        renderLegend();
        put(state_, live ? 'Live' : 'Replay ' + (mapMode === '24h' ? '24 hours' : '7 days'));
        put(note,
          live ? 'New alerts are fetched every 10 seconds; scores and heat cover the last 24 hours. ' : '',
          'Shots at logins and services are real Wazuh alerts. Positions come from GeoIP: they are approximate, often only the country, and show where the address is registered or used, not who is behind it. ',
          d.without_location ? d.without_location + ' alerts without a position are left out. ' : '',
          simFrom > asked + 60000 ? 'Only the newest alerts are included, from ' + fmt(simFrom) + '. ' : '');
        if (live) {
          // Heat and scores start from the last 24 hours; only new attacks are shot.
          queue.forEach(function (e) { count(e, 1); counted.push(e); });
          queue.slice(-8).forEach(logLine);
          next = queue.length;
          board();
          setTimeout(poll, 0);
          setTimeout(pollEdge, x[2] ? 60000 : 0);
        }
        if (reduced && !live) {
          // No animation: every source at once, with the final scores.
          queue = queue.slice(first);
          queue.forEach(function (e) { count(e, 1); });
          board();
          drawLand(heat);
          draw(performance.now());
          queue.forEach(function (e) { dot(px(e.lon, e.lat), 3, colors[e.category] || color('text')); });
          put(clock, fmt(simFrom) + ' – ' + fmt(simTo));
          return;
        }
        if (!live) board();
        last = performance.now();
        requestAnimationFrame(frame);
      }).catch(function (e) { if (my === run) { put(state_, 'No signal'); put(messages, notice('error', e.message)); } });
    }

    renderControls();
    // Without this answer the map still shows Wazuh's alerts.
    api('GET', '/findings/sources').then(function (src) {
      edgeReady = src.backends.some(function (b) { return b.id === 'graylog' && b.state === 'ready'; });
    }).catch(function () { edgeReady = false; }).then(function () {
      if (!canvas.isConnected) return;
      renderControls();
      start_();
    });
  }

  // ---- vulnerability trend: new vs resolved per day and per agent ----
  var trendDays = 30; // remembered across tab switches
  var TREND_WINDOWS = [7, 30, 90];

  function signed(n) { return n > 0 ? '+' + n : String(n); }

  /** "Worse", "Better" or "Steady" for a net change (more new than resolved is worse). */
  function trendWord(net) { return net > 0 ? 'Worse' : net < 0 ? 'Better' : 'Steady'; }
  function trendClass(net) { return net > 0 ? 'worse' : net < 0 ? 'better' : 'steady'; }

  function trendChip(net) {
    return h('span', { class: 'trend-chip ' + trendClass(net), title: signed(net) + ' net over the window' },
      h('span', { 'aria-hidden': 'true' }, net > 0 ? '▲' : net < 0 ? '▼' : '■'), ' ', trendWord(net), net ? ' ' + signed(net) : '');
  }

  /** Columns per day: new grows up from the middle line, resolved grows down. */
  function trendColumns(days, cls, label) {
    var max = 1;
    days.forEach(function (d) { max = Math.max(max, d.new, d.resolved); });
    return h('div', { class: cls, role: 'img', 'aria-label': label },
      days.map(function (d) {
        return h('div', { class: 'col', title: d.day + ': +' + d.new + ' new, −' + d.resolved + ' resolved' },
          h('div', { class: 'up' }, d.new ? h('span', { style: { height: Math.max(4, Math.round(100 * d.new / max)) + '%' } }) : null),
          h('div', { class: 'down' }, d.resolved ? h('span', { style: { height: Math.max(4, Math.round(100 * d.resolved / max)) + '%' } }) : null));
      }));
  }

  function trendPanel(onAgent) {
    var box = h('div', { class: 'panel trend' });
    function load() {
      var q = sevQuery();
      put(box, h('h2', null, 'Trend'), h('p', { class: 'muted' }, 'Loading trend…'));
      api('GET', '/findings/trend' + (q ? q + '&' : '?') + 'days=' + trendDays).then(function (t) { render(t); })
        .catch(function (e) { put(box, h('h2', null, 'Trend'), notice('error', e.message)); });
    }
    function windowToggle() {
      return h('div', { class: 'row trend-window', role: 'group', 'aria-label': 'Trend window' }, TREND_WINDOWS.map(function (d) {
        return h('button', {
          class: 'chip-toggle', 'aria-pressed': d === trendDays ? 'true' : 'false',
          onclick: function () { if (d !== trendDays) { trendDays = d; load(); } },
        }, d + ' days');
      }));
    }
    function stat(label, value, cls, hint) {
      return h('div', { class: 'trend-stat ' + cls }, h('div', { class: 'label' }, label), h('div', { class: 'count' }, value), hint ? h('div', { class: 'muted small' }, hint) : null);
    }
    function render(t) {
      var moving = t.agents.filter(function (a) { return a.new || a.resolved; });
      var noEvents = !t.new && !t.resolved;
      put(box,
        h('div', { class: 'page-head' }, h('h2', null, 'Trend · last ' + t.days + ' days'), windowToggle()),
        h('div', { class: 'trend-stats' },
          stat('New', '+' + t.new, 'worse', 'findings that appeared'),
          stat('Resolved', '−' + t.resolved, 'better', 'fixed or removed'),
          stat('Net change', signed(t.net), trendClass(t.net), trendWord(t.net) + ' overall'),
          stat('Open now', String(t.open), 'steady', 'current findings')),
        noEvents
          ? h('p', { class: 'muted small' }, 'No new or resolved findings in this window. ')
          : [trendColumns(t.by_day, 'trend-days', 'New and resolved findings per day'),
             h('div', { class: 'usage-days-axis help' }, h('span', null, t.by_day[0] ? t.by_day[0].day : ''),
               h('span', { class: 'trend-legend' }, h('span', { class: 'key worse' }), 'new ', h('span', { class: 'key better' }), 'resolved'),
               h('span', null, t.by_day.length ? t.by_day[t.by_day.length - 1].day : ''))],
        h('p', { class: 'muted small' }, t.snapshots_since
          ? (Date.parse(t.snapshots_since) > Date.now() - t.days * 86400000 ? 'From ' + new Date(t.snapshots_since).toLocaleString() + ' every change in the open findings is counted. Earlier days come from detector alerts and miss CVEs that appeared or disappeared through a feed update. ' : '') + 'Resolved findings are confirmed after 6 hours.'
          : 'Built from detector alerts only, which miss CVEs that appear or disappear through a feed update. SocBridge counts every change once it has taken its first snapshot.'),
        t.redetected ? h('p', { class: 'muted small' }, t.redetected + ' re-detected after a package update and not counted: the new version still has the same CVE.') : null,
        t.truncated ? h('p', { class: 'muted small' }, 'Too many detector alerts to read them all; the oldest days are incomplete.') : null,
        t.agents.length === 0 ? null : h('div', { class: 'table-wrap' }, h('table', { class: 'trend-agents' },
          h('thead', null, h('tr', null, h('th', null, 'Agent'), h('th', null, 'Trend'), h('th', null, 'Per day'),
            h('th', { class: 'num' }, 'New'), h('th', { class: 'num' }, 'Resolved'), h('th', { class: 'num' }, 'Open now'))),
          h('tbody', null, t.agents.map(function (a) {
            return h('tr', {
              class: 'clickable', tabindex: '0', title: 'Show the findings on ' + (a.agent_name || a.agent_id),
              onclick: function () { onAgent(a.agent_id, a.agent_name); },
              onkeydown: function (ev) { if (ev.key === 'Enter') onAgent(a.agent_id, a.agent_name); },
            },
              h('td', null, a.agent_name || '—', h('div', { class: 'data muted' }, a.agent_id)),
              h('td', null, trendChip(a.net)),
              h('td', null, a.days.length ? trendColumns(a.days, 'trend-spark', a.new + ' new and ' + a.resolved + ' resolved') : h('span', { class: 'muted small' }, 'no changes')),
              h('td', { class: 'num' }, a.new ? '+' + a.new : h('span', { class: 'muted' }, '0')),
              h('td', { class: 'num' }, a.resolved ? '−' + a.resolved : h('span', { class: 'muted' }, '0')),
              h('td', { class: 'num' }, String(a.open)));
          })))),
        moving.length < t.agents.length && moving.length ? h('p', { class: 'muted small' }, (t.agents.length - moving.length) + ' agent(s) had no changes in this window.') : null);
    }
    load();
    return box;
  }

  // Wazuh vulnerability detection: trend first, then agents by findings and one agent's findings.
  function wazuhFindings(pane, summary, src) {
    var selectedAgent = null;
    var agentsBox = h('div');
    var cvesBox = h('div');
    var tiles = h('div');
    var detail = h('div', { class: 'panel' }, h('p', { class: 'muted' }, 'Select an agent to see its findings.'));
    var trend = trendPanel(function (id, name) {
      loadAgent(id, name);
      detail.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
    put(pane, trend, tiles, h('div', { class: 'split' },
      h('div', null,
        h('div', { class: 'panel' }, h('h2', null, 'Most affected agents'), agentsBox),
        h('div', { class: 'panel' }, h('h2', null, 'Most widespread'), cvesBox)),
      detail));
    put(summary, 'Loading…');

    function loadAgent(agentId, agentName) {
      selectedAgent = agentId;
      Array.prototype.forEach.call(agentsBox.querySelectorAll('tr[data-agent]'), function (tr) {
        tr.classList.toggle('selected', tr.getAttribute('data-agent') === agentId);
      });
      put(detail, h('p', { class: 'muted' }, 'Loading findings…'));
      api('GET', '/findings/agents/' + encodeURIComponent(agentId) + sevQuery()).then(function (r) {
        var counts = SEV_ORDER.map(function (k) { return k + ' ' + (r.severity_counts[k] || 0); }).join(' · ');
        put(detail,
          h('div', { class: 'page-head' },
            h('h2', null, 'Agent ', h('span', { class: 'data' }, r.agent_id), agentName ? ' · ' + agentName : ''),
            h('span', { class: 'muted small' }, counts)),
          r.vulnerabilities.length === 0 ? h('p', { class: 'muted' }, 'No findings match the current filter.') :
          h('div', { class: 'table-wrap' }, h('table', null,
            h('thead', null, h('tr', null, h('th', null, 'Severity'), h('th', null, 'Vulnerability'), h('th', null, 'Package'), h('th', { class: 'num' }, 'CVSS'), h('th', null, 'Detected'))),
            h('tbody', null, r.vulnerabilities.map(function (v) {
              var vul = v.vulnerability || {};
              var pkg = v.package || {};
              var score = vul.score && vul.score.base;
              return h('tr', null,
                h('td', null, sevChip(vul.severity)),
                h('td', null, h('span', { class: 'data' }, vul.id || '—'),
                  vul.description ? h('div', { class: 'muted small' }, short(vul.description, 160)) : null),
                h('td', null, pkg.name || '—', pkg.version ? h('div', { class: 'data muted' }, pkg.version) : null),
                h('td', { class: 'num' }, score !== undefined && score !== null ? Number(score).toFixed(1) : '—'),
                h('td', null, fmt(vul.detected_at)));
            })))),
          r.matching > r.returned ? h('p', { class: 'muted small' }, 'Showing ' + r.returned + ' of ' + r.matching + ', highest CVSS first.') : null);
      }).catch(function (e) { put(detail, notice('error', e.message)); });
    }

    api('GET', '/findings/overview' + sevQuery()).then(function (o) {
      put(summary, 'Wazuh vulnerability detection · ', h('strong', null, String(o.total)), ' findings across ', String(o.top_agents.length), o.top_agents.length === 25 ? '+' : '', ' agents');
      put(tiles, sevTiles(o.by_severity));
      put(agentsBox, o.top_agents.length === 0 ? h('p', { class: 'muted' }, 'No findings.') :
        h('div', { class: 'table-wrap' }, h('table', null,
          h('thead', null, h('tr', null, h('th', null, 'Agent'), h('th', null, 'Name'), h('th', null, 'Spread'), h('th', { class: 'num' }, 'Findings'))),
          h('tbody', null, o.top_agents.map(function (a) {
            return h('tr', {
              class: 'clickable', 'data-agent': a.agent_id, tabindex: '0',
              onclick: function () { loadAgent(a.agent_id, a.agent_name); },
              onkeydown: function (ev) { if (ev.key === 'Enter') loadAgent(a.agent_id, a.agent_name); },
            },
              h('td', null, h('span', { class: 'data' }, a.agent_id)),
              h('td', null, a.agent_name || '—'),
              h('td', null, sevBar(a.by_severity, a.total)),
              h('td', { class: 'num' }, String(a.total)));
          })))));
      var cves = Object.keys(o.top_cves);
      put(cvesBox, cves.length === 0 ? h('p', { class: 'muted' }, 'None.') :
        h('table', null, h('tbody', null, cves.map(function (id) {
          return h('tr', null, h('td', null, h('span', { class: 'data' }, id)), h('td', { class: 'num' }, String(o.top_cves[id])));
        }))));
      if (o.top_agents[0]) loadAgent(o.top_agents[0].agent_id, o.top_agents[0].agent_name);
    }).catch(function (e) { put(summary); put(pane, sourceError(src.title, e)); });
  }

  // Trivy: scan reports (one per image or filesystem), then one report's vulnerabilities.
  function trivyFindings(pane, summary, src) {
    var upper = function (k) { return k.toUpperCase(); };
    var listBox = h('div');
    var tiles = h('div');
    var detail = h('div', { class: 'panel' }, h('p', { class: 'muted' }, 'Select a report to see its findings.'));
    put(pane, tiles, h('div', { class: 'split' }, h('div', { class: 'panel' }, h('h2', null, 'Scan reports'), listBox), detail));
    put(summary, 'Loading…');

    function loadReport(file) {
      Array.prototype.forEach.call(listBox.querySelectorAll('tr[data-report]'), function (tr) {
        tr.classList.toggle('selected', tr.getAttribute('data-report') === file);
      });
      put(detail, h('p', { class: 'muted' }, 'Loading findings…'));
      api('GET', '/findings/trivy/reports/' + encodeURIComponent(file) + sevQuery()).then(function (r) {
        var s = r.summary || {};
        put(detail,
          h('div', { class: 'page-head' },
            h('h2', null, h('span', { class: 'data' }, r.artifact)),
            h('span', { class: 'muted small' }, [r.os, r.created_at ? 'scanned ' + fmt(r.created_at) : null].filter(Boolean).join(' · '))),
          h('p', { class: 'muted small' }, s.vulnerabilities + ' vulnerabilities, ' + s.fixable + ' fixable',
            s.misconfigurations ? ' · ' + s.misconfigurations + ' misconfigurations' : '',
            s.secrets ? ' · ' + s.secrets + ' secrets' : '',
            ' (misconfigurations and secrets via trivy_report_findings)'),
          r.vulnerabilities.length === 0 ? h('p', { class: 'muted' }, 'No findings match the current filter.') :
          h('div', { class: 'table-wrap' }, h('table', null,
            h('thead', null, h('tr', null, h('th', null, 'Severity'), h('th', null, 'Vulnerability'), h('th', null, 'Package'), h('th', null, 'Fixed in'), h('th', { class: 'num' }, 'CVSS'))),
            h('tbody', null, r.vulnerabilities.map(function (v) {
              return h('tr', null,
                h('td', null, sevChip(v.severity)),
                h('td', null, h('span', { class: 'data' }, v.id), v.title ? h('div', { class: 'muted small' }, short(v.title, 160)) : null),
                h('td', null, v.pkg || '—', v.installed ? h('div', { class: 'data muted' }, v.installed) : null),
                h('td', null, v.fixed ? h('span', { class: 'data' }, v.fixed) : h('span', { class: 'muted' }, '—')),
                h('td', { class: 'num' }, typeof v.cvss === 'number' ? v.cvss.toFixed(1) : '—'));
            })))),
          r.matched > r.vulnerabilities.length ? h('p', { class: 'muted small' }, 'Showing ' + r.vulnerabilities.length + ' of ' + r.matched + ', most severe first.') : null);
      }).catch(function (e) { put(detail, notice('error', e.message)); });
    }

    api('GET', '/findings/trivy' + sevQuery()).then(function (o) {
      put(summary, 'Trivy scan reports · ', h('strong', null, String(o.total)), ' vulnerabilities across ', String(o.reports.length), ' reports',
        o.unreadable ? ' · ' + o.unreadable + ' unreadable file(s)' : '');
      put(tiles, sevTiles(o.by_severity, upper));
      put(listBox, o.reports.length === 0 ? h('p', { class: 'muted' }, 'No reports in the report directory yet.') :
        h('div', { class: 'table-wrap' }, h('table', null,
          h('thead', null, h('tr', null, h('th', null, 'Artifact'), h('th', null, 'Spread'), h('th', { class: 'num' }, 'Findings'))),
          h('tbody', null, o.reports.map(function (rep) {
            var shown = 0;
            findingsSeverity.forEach(function (k) { shown += rep.by_severity[upper(k)] || 0; });
            return h('tr', {
              class: 'clickable', 'data-report': rep.file, tabindex: '0',
              onclick: function () { loadReport(rep.file); },
              onkeydown: function (ev) { if (ev.key === 'Enter') loadReport(rep.file); },
            },
              h('td', null, h('span', { class: 'data' }, rep.artifact), h('div', { class: 'muted small' }, rep.created_at ? fmt(rep.created_at) : rep.file)),
              h('td', null, sevBar(rep.by_severity, rep.vulnerabilities, upper)),
              h('td', { class: 'num' }, String(shown)));
          })))));
      if (o.reports[0]) loadReport(o.reports[0].file);
    }).catch(function (e) { put(summary); put(pane, sourceError(src.title, e)); });
  }

  // DefectDojo: active findings (no duplicates or false positives), most severe first.
  function defectdojoFindings(pane, summary, src) {
    put(summary, 'Loading…');
    put(pane, h('p', { class: 'muted' }, 'Loading findings…'));
    api('GET', '/findings/defectdojo' + sevQuery()).then(function (o) {
      put(summary, 'DefectDojo active findings · ', h('strong', null, String(o.total)), ' open');
      var truncated = Object.keys(o.by_severity).some(function (k) { return o.by_severity[k] > o.per_severity_limit; });
      put(pane,
        sevTiles(o.by_severity),
        h('div', { class: 'panel' },
          o.findings.length === 0 ? h('p', { class: 'muted' }, 'No active findings match the current filter.') :
          h('div', { class: 'table-wrap' }, h('table', null,
            h('thead', null, h('tr', null, h('th', null, 'Severity'), h('th', null, 'Finding'), h('th', null, 'Product'), h('th', null, 'Verified'), h('th', null, 'Found'))),
            h('tbody', null, o.findings.map(function (f) {
              var ids = (f.vulnerability_ids || []).join(', ');
              return h('tr', null,
                h('td', null, sevChip(f.severity)),
                h('td', null, f.title || '—', h('div', { class: 'muted small' }, h('span', { class: 'data' }, '#' + f.id), ids ? ' · ' : '', ids ? h('span', { class: 'data' }, ids) : null)),
                h('td', null, f.product_name || '—', f.engagement_name ? h('div', { class: 'muted small' }, f.engagement_name) : null),
                h('td', null, f.verified ? 'Yes' : h('span', { class: 'muted' }, 'No')),
                h('td', null, f.date || '—'));
            })))),
          truncated ? h('p', { class: 'muted small' }, 'Showing at most ' + o.per_severity_limit + ' per severity, newest first. Ask the assistant or use defectdojo_list_findings for the rest.') : null));
    }).catch(function (e) { put(summary); put(pane, sourceError(src.title, e)); });
  }

  // Graylog: triggered events from Graylog's own alerting, then recent messages
  // at syslog level error or worse.
  var GRAYLOG_PRIORITY = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' };
  function graylogAlerts(ev) {
    if (!ev) return null;
    if (ev.error) return h('div', { class: 'panel' }, h('h3', null, 'Triggered events'),
      h('p', { class: 'muted' }, 'Could not read events: ', ev.error, '. The token needs permission to read events.'));
    return h('div', { class: 'panel' },
      h('h3', null, 'Triggered events'),
      h('p', { class: 'muted small' }, 'From Graylog event definitions, newest first, at most ' + ev.returned + (ev.more ? ' of ' + ev.total : '') + '. Use graylog_search_events for more.'),
      ev.events.length === 0 ? h('p', { class: 'muted' }, 'No events triggered in this window.') :
      h('div', { class: 'table-wrap' }, h('table', null,
        h('thead', null, h('tr', null, h('th', null, 'Priority'), h('th', null, 'Time'), h('th', null, 'Definition'), h('th', null, 'Message'))),
        h('tbody', null, ev.events.map(function (e) {
          var p = String(e.priority || '').toLowerCase();
          return h('tr', null,
            h('td', null, h('span', { class: sevClass(GRAYLOG_PRIORITY[p] || 'low') }, (e.priority || '—') + (e.alert ? ' · alert' : ''))),
            h('td', null, fmt(e.timestamp)),
            h('td', null, e.definition || '—'),
            h('td', null, short(e.message, 300)));
        })))));
  }

  function graylogEvents(pane, summary, src) {
    var LEVEL = ['Emergency', 'Alert', 'Critical', 'Error'];
    put(summary, 'Loading…');
    put(pane, h('p', { class: 'muted' }, 'Loading events…'));
    api('GET', '/findings/graylog').then(function (o) {
      var hours = Math.round(o.rule.range_seconds / 3600);
      var nEv = o.events && !o.events.error ? o.events.total : null;
      put(summary, 'Graylog · ', nEv !== null ? [h('strong', null, String(nEv)), ' triggered events, '] : null,
        h('strong', null, String(o.returned)), o.more ? '+' : '', ' messages at level error or worse, last ' + hours + ' h');
      put(pane, graylogAlerts(o.events), h('div', { class: 'panel' },
        h('h3', null, 'Error messages'),
        h('p', { class: 'muted small' }, 'Query ', h('span', { class: 'data' }, o.rule.query), ', newest first, at most ' + o.rule.limit + '. Use graylog_search for anything else.'),
        o.messages.length === 0 ? h('p', { class: 'muted' }, 'No events at level error or worse in the last ' + hours + ' h.') :
        h('div', { class: 'table-wrap' }, h('table', null,
          h('thead', null, h('tr', null, h('th', null, 'Level'), h('th', null, 'Time'), h('th', null, 'Source'), h('th', null, 'Message'))),
          h('tbody', null, o.messages.map(function (m) {
            var lvl = Number(m.level);
            var name = LEVEL[lvl] || (m.level !== undefined ? String(m.level) : '—');
            return h('tr', null,
              h('td', null, h('span', { class: sevClass(lvl <= 2 ? 'critical' : 'high') }, name)),
              h('td', null, fmt(m.timestamp)),
              h('td', null, h('span', { class: 'data' }, m.source || '—')),
              h('td', null, short(m.message, 300)));
          }))))));
    }).catch(function (e) { put(summary); put(pane, sourceError(src.title, e)); });
  }

  // ---- server: certificate ----
  function viewServer() {
    var panel = tlsPanel(api);
    var ai = aiPanel();
    var conn = connectorsPanel();
    mount(h('div', null, h('h1', null, 'Server'), h('h2', null, 'Certificate'), panel.node, h('h2', null, 'Assistant'), ai.node,
      h('h2', null, 'Connectors (OAuth)'), conn.node));
    panel.load();
    ai.load();
    conn.load();
  }

  // ---- server: OAuth for connectors ----
  function connectorsPanel() {
    var box = h('div', null, h('p', { class: 'muted' }, 'Loading…'));
    var enabled = h('input', { type: 'checkbox' });
    var statusBox = h('span');
    var out = h('div');
    function badge(v) { return v.enabled ? h('span', { class: 'badge on' }, 'enabled') : h('span', { class: 'badge' }, 'off'); }
    var save = h('button', {
      class: 'primary',
      onclick: function () {
        if (!enabled.checked && !confirm('Turn off connectors? Connected apps stop working until you turn them back on.')) return;
        busy(save, api('PUT', '/oauth/settings', { enabled: enabled.checked }).then(function (v) {
          state.me.oauthEnabled = v.enabled;
          enabled.checked = v.enabled;
          put(statusBox, badge(v));
          put(out, notice('success', v.enabled ? 'Connectors enabled.' : 'Connectors turned off.'));
        }), out);
      },
    }, 'Save');
    function load() {
      api('GET', '/oauth/settings').then(function (v) {
        enabled.checked = v.enabled;
        put(statusBox, badge(v));
        put(box,
          h('div', { class: 'row' }, h('p', { class: 'muted small grow' },
            'Lets apps that cannot use an access token, such as Claude custom connectors, sign in with OAuth. Each connection must be approved by a signed-in user with their passkey and acts as that user.'), statusBox),
          h('label', { class: 'inline' }, enabled, 'Enabled'),
          h('table', { class: 'kv' }, h('tbody', null,
            h('tr', null, h('th', null, 'MCP URL'), h('td', null, h('span', { class: 'data' }, v.mcpUrl))),
            h('tr', null, h('th', null, 'Redirects'), h('td', null, v.redirectHosts.join(', ') + ', and http://localhost (OAUTH_REDIRECT_HOSTS)')))),
          usesBuiltinCa(state.me) ? notice('warning', 'This server uses its built-in CA. Claude connectors are called from Anthropic\'s servers, which need a publicly trusted certificate and a URL reachable from the internet.') : null,
          h('div', { class: 'row' }, save), out);
      }).catch(function (e) { put(box, notice('error', e.message)); });
    }
    return { node: h('div', { class: 'panel' }, box), load: load };
  }

  // ---- server: assistant provider ----
  var PROVIDERS = [
    { id: 'anthropic', label: 'Claude (Anthropic API)', help: 'Uses the Claude API with your Anthropic API key.' },
    { id: 'openai', label: 'OpenAI', help: 'Uses the OpenAI chat completions API with an OpenAI API key.' },
    { id: 'local', label: 'Local model (OpenAI-compatible)', help: 'Ollama, LM Studio, vLLM, llama.cpp server… The model must support tool calling. Example base URL: http://ollama:11434/v1' },
  ];

  function aiPanel() {
    var box = h('div', null, h('p', { class: 'muted' }, 'Loading…'));
    var v = null;
    var enabled = h('input', { type: 'checkbox' });
    var provider = h('select', null, PROVIDERS.map(function (p) { return h('option', { value: p.id }, p.label); }));
    var providerHelp = h('div', { class: 'help' });
    // The model is picked from what the provider lists for this key; "Other…" reveals a free-text field.
    var CUSTOM = '__custom__';
    var modelSelect = h('select', { 'aria-label': 'Model' });
    var model = h('input', { type: 'text', 'aria-label': 'Model name', class: 'hidden' });
    var modelHelp = h('div', { class: 'help' });
    var modelList = [];
    var modelSeq = 0;
    var refreshModels = h('button', { type: 'button', onclick: function () { loadModels(); } }, 'Refresh');
    var baseUrl = h('input', { type: 'url' });
    var baseUrlRow = h('div', null, h('label', null, 'Base URL'), baseUrl, h('div', { class: 'help' }, 'The OpenAI-compatible API root, ending in /v1.'));
    var apiKey = h('input', { type: 'password', autocomplete: 'new-password' });
    var keyHelp = h('div', { class: 'help' });
    var out = h('div');
    var statusBox = h('span');

    function sync() {
      var p = provider.value;
      var meta = PROVIDERS.filter(function (x) { return x.id === p; })[0];
      providerHelp.textContent = meta.help;
      model.placeholder = (v && v.defaults.models[p]) || (p === 'local' ? 'e.g. qwen3:14b' : 'model name');
      renderModels();
      baseUrl.placeholder = (v && v.defaults.baseUrls[p]) || 'http://ollama:11434/v1';
      baseUrlRow.className = p === 'anthropic' ? 'hidden' : '';
      var stored = v && v.keysSet.indexOf(p) >= 0;
      apiKey.value = '';
      apiKey.placeholder = stored ? '•••••••• (stored — leave empty to keep)' : (p === 'local' ? 'optional' : '');
      keyHelp.textContent = p === 'local'
        ? 'Only if your model server requires one. Over plain http the key and all chat content cross the network unencrypted.'
        : 'Stored encrypted with the rest of the configuration and never shown again.';
    }
    /** The model name the form will save: the dropdown choice, or the free text under "Other…". */
    function modelValue() {
      return modelSelect.value === CUSTOM ? model.value.trim() : modelSelect.value;
    }
    function renderModels() {
      var cur = model.value.trim();
      var def = (v && v.defaults.models[provider.value]) || '';
      var ids = modelList.map(function (m) { return m.id; });
      var opts = [];
      opts.push(h('option', { value: '' }, def ? 'Default (' + def + ')' : 'Choose a model…'));
      modelList.forEach(function (m) { opts.push(h('option', { value: m.id }, m.label)); });
      opts.push(h('option', { value: CUSTOM }, 'Other…'));
      put(modelSelect, opts);
      // A saved model the provider does not list (or a list we could not load) stays visible as free text.
      var custom = cur !== '' && ids.indexOf(cur) < 0;
      modelSelect.value = custom ? CUSTOM : cur;
      model.className = modelSelect.value === CUSTOM ? '' : 'hidden';
    }
    function loadModels() {
      var seq = ++modelSeq;
      modelHelp.textContent = 'Loading models…';
      api('POST', '/ai/models', { provider: provider.value, baseUrl: baseUrl.value.trim(), apiKey: apiKey.value.trim() }).then(function (r) {
        if (seq !== modelSeq) return; // a newer request (provider changed) wins
        modelList = r.models || [];
        modelHelp.textContent = r.ok
          ? (r.message || modelList.length + ' model' + (modelList.length === 1 ? '' : 's') + ' available for this key.')
          : 'Could not list models: ' + r.message + ' Pick "Other…" to type a name.';
        renderModels();
      }).catch(function (e) {
        if (seq !== modelSeq) return;
        modelList = [];
        modelHelp.textContent = 'Could not list models: ' + e.message;
        renderModels();
      });
    }
    modelSelect.addEventListener('change', function () {
      if (modelSelect.value === CUSTOM) {
        model.className = '';
        model.focus();
      } else {
        model.value = modelSelect.value;
        model.className = 'hidden';
      }
    });
    baseUrl.addEventListener('change', loadModels);
    apiKey.addEventListener('change', function () { if (apiKey.value.trim()) loadModels(); });

    function badge(view) {
      if (!view.enabled) return h('span', { class: 'badge' }, 'off');
      return view.ready ? h('span', { class: 'badge on' }, 'enabled') : h('span', { class: 'badge error' }, 'incomplete');
    }
    function fill(view) {
      v = view;
      enabled.checked = view.enabled;
      provider.value = view.provider;
      model.value = view.model;
      baseUrl.value = view.baseUrl;
      put(statusBox, badge(view));
      sync();
    }
    function collect(extra) {
      return Object.assign({ enabled: enabled.checked, provider: provider.value, model: modelValue(), baseUrl: baseUrl.value.trim(), apiKey: apiKey.value.trim() }, extra || {});
    }
    provider.addEventListener('change', function () {
      // A model name belongs to one provider; do not carry it over.
      model.value = v && v.provider === provider.value ? v.model : '';
      modelList = [];
      sync();
      loadModels();
    });

    var save = h('button', {
      class: 'primary',
      onclick: function () {
        busy(save, api('PUT', '/ai/settings', collect()).then(function (view) {
          statusBar.refresh();
          fill(view);
          put(out, view.ready || !view.enabled ? notice('success', 'Saved.') : notice('error', 'Saved, but incomplete: ' + view.reason));
        }), out);
      },
    }, 'Save');
    var test = h('button', {
      onclick: function () {
        put(out, h('p', { class: 'muted small' }, 'Testing saved settings…'));
        busy(test, api('POST', '/ai/test', {}).then(function (r) { put(out, notice(r.ok ? 'success' : 'error', r.message)); }), out);
      },
    }, 'Test connection');
    var clear = h('button', {
      class: 'danger',
      onclick: function () {
        if (!confirm('Remove the stored API key for this provider?')) return;
        busy(clear, api('PUT', '/ai/settings', collect({ apiKey: '', clearKey: true })).then(function (view) { fill(view); put(out, notice('success', 'Key removed.')); }), out);
      },
    }, 'Remove key');

    function load() {
      api('GET', '/ai/settings').then(function (view) {
        put(box,
          h('div', { class: 'row' }, h('p', { class: 'muted small grow' },
            'A chat page for every signed-in user. Questions and the tool results the model reads are sent to the provider you choose here.'), statusBox),
          h('label', { class: 'inline' }, enabled, 'Enabled'),
          h('label', null, 'Provider'), provider, providerHelp,
          h('label', null, 'Model'), h('div', { class: 'row tight' }, h('div', { class: 'grow' }, modelSelect), refreshModels), model, modelHelp,
          baseUrlRow,
          h('label', null, 'API key'), apiKey, keyHelp,
          h('div', { class: 'row' }, save, test, clear), out);
        fill(view);
        loadModels();
      }).catch(function (e) { put(box, notice('error', e.message)); });
    }
    return { node: h('div', { class: 'panel' }, box), load: load };
  }

  // ---- assistant chat ----
  var SEVERITY_WORDS = { critical: 'critical', high: 'high', medium: 'medium', moderate: 'medium', low: 'low', info: 'info', informational: 'info', negligible: 'info' };

  /**
   * Small Markdown to DOM: headings, paragraphs, lists, fenced code, pipe
   * tables, blockquotes, rules, `code`, **bold**, *italic* and ~~strike~~.
   * Built with text nodes only, so model output can never inject markup, and
   * links/images are not rendered (nothing is fetched from what the model says).
   */
  function renderMarkdown(text) {
    var out = [];
    var lines = text.replace(/\r\n/g, '\n').split('\n');
    var i = 0;
    var ul = /^\s*[-*•+]\s+/, ol = /^\s*\d+[.)]\s+/, hdRe = /^(#{1,6})\s+(.*)$/;
    var tableSep = /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/;
    var hrRe = /^\s*([-*_])(\s*\1){2,}\s*$/;

    function inline(str) {
      var nodes = [];
      var re = /(`[^`]+`|\*\*[^*]+\*\*|__[^_]+__|~~[^~]+~~|\*[^*\s][^*]*\*|(?:^|(?=\W))_[^_\s][^_]*_(?=\W|$))/g;
      var last = 0, m;
      while ((m = re.exec(str))) {
        if (m.index > last) nodes.push(str.slice(last, m.index));
        var t = m[0];
        if (t[0] === '`') nodes.push(h('code', null, t.slice(1, -1)));
        else if (t.slice(0, 2) === '**' || t.slice(0, 2) === '__') nodes.push(h('strong', null, inline(t.slice(2, -2))));
        else if (t.slice(0, 2) === '~~') nodes.push(h('s', null, inline(t.slice(2, -2))));
        else nodes.push(h('em', null, inline(t.slice(1, -1))));
        last = m.index + t.length;
      }
      if (last < str.length) nodes.push(str.slice(last));
      return nodes;
    }
    function inlineLines(arr) {
      var nodes = [];
      arr.forEach(function (l, n) { if (n) nodes.push(h('br')); nodes.push(inline(l)); });
      return nodes;
    }
    function cells(row) {
      var s = row.trim();
      if (s[0] === '|') s = s.slice(1);
      if (s[s.length - 1] === '|' && s[s.length - 2] !== '\\') s = s.slice(0, -1);
      return s.split(/(?<!\\)\|/).map(function (c) { return c.trim().replace(/\\\|/g, '|'); });
    }
    function cell(tag, content, align) {
      var sev = SEVERITY_WORDS[content.replace(/[*_`]/g, '').trim().toLowerCase()];
      var attrs = { class: (align === 'right' ? 'num' : align === 'center' ? 'center' : '') || null };
      if (tag === 'td' && sev) return h('td', attrs, h('span', { class: 'sev sev-' + sev }, content.replace(/[*_`]/g, '').trim()));
      if (tag === 'td' && align !== 'right' && /^[\d\s.,%+-]+$/.test(content) && /\d/.test(content)) attrs.class = 'num';
      return h(tag, attrs, inline(content));
    }
    function isTableStart(n) {
      return n + 1 < lines.length && lines[n].indexOf('|') >= 0 && tableSep.test(lines[n + 1]);
    }
    function startsBlock(l, n) {
      return /^```/.test(l) || ul.test(l) || ol.test(l) || hdRe.test(l) || /^\s*>/.test(l) || hrRe.test(l) || isTableStart(n);
    }

    while (i < lines.length) {
      var line = lines[i];
      if (/^```/.test(line)) {
        var code = [];
        i++;
        while (i < lines.length && !/^```/.test(lines[i])) code.push(lines[i++]);
        i++;
        out.push(h('pre', null, h('code', null, code.join('\n'))));
        continue;
      }
      if (isTableStart(i)) {
        var head = cells(lines[i]);
        var aligns = cells(lines[i + 1]).map(function (c) {
          return /^:-+:$/.test(c) ? 'center' : /-:$/.test(c) ? 'right' : 'left';
        });
        i += 2;
        var rows = [];
        while (i < lines.length && lines[i].indexOf('|') >= 0 && lines[i].trim()) rows.push(cells(lines[i++]));
        // Columns where every body cell is numeric are right-aligned unless the model said otherwise.
        head.forEach(function (_, c) {
          if (aligns[c] !== 'left' || !rows.length) return;
          if (rows.every(function (r) { return /^[\d\s.,%+-]*\d[\d\s.,%+-]*$/.test(r[c] || ''); })) aligns[c] = 'right';
        });
        out.push(h('div', { class: 'md-table' }, h('table', null,
          h('thead', null, h('tr', null, head.map(function (c, n) { return cell('th', c, aligns[n]); }))),
          h('tbody', null, rows.map(function (r) {
            return h('tr', null, head.map(function (_, n) { return cell('td', r[n] || '', aligns[n]); }));
          })))));
        continue;
      }
      if (hrRe.test(line)) { out.push(h('hr')); i++; continue; }
      if (/^\s*>/.test(line)) {
        var quote = [];
        while (i < lines.length && /^\s*>/.test(lines[i])) quote.push(lines[i++].replace(/^\s*>\s?/, ''));
        out.push(h('blockquote', null, renderMarkdown(quote.join('\n'))));
        continue;
      }
      if (ul.test(line) || ol.test(line)) {
        var ordered = ol.test(line) && !ul.test(line);
        var re2 = ordered ? ol : ul;
        var items = [];
        var start = ordered ? parseInt(line, 10) : null;
        while (i < lines.length && re2.test(lines[i])) {
          var item = [lines[i++].replace(re2, '')];
          // Continuation lines indented under the item belong to it.
          while (i < lines.length && /^\s{2,}\S/.test(lines[i]) && !ul.test(lines[i]) && !ol.test(lines[i])) item.push(lines[i++].trim());
          items.push(h('li', null, inlineLines(item)));
        }
        out.push(h(ordered ? 'ol' : 'ul', ordered && start > 1 ? { start: start } : null, items));
        continue;
      }
      var hd = hdRe.exec(line);
      if (hd) { out.push(h('p', { class: 'md-h md-h' + Math.min(hd[1].length, 4) }, inline(hd[2]))); i++; continue; }
      if (!line.trim()) { i++; continue; }
      var para = [];
      while (i < lines.length && lines[i].trim() && !(para.length && startsBlock(lines[i], i))) para.push(lines[i++]);
      out.push(h('p', null, inlineLines(para)));
    }
    return out;
  }

  /** "wazuh_vulnerability_overview" → { backend: "wazuh", label: "Vulnerability overview" }. */
  function toolLabel(name) {
    var m = /^(wazuh|trivy|defectdojo|graylog|socbridge)_(.*)$/.exec(name);
    var backend = m ? (m[1] === 'socbridge' ? 'SocBridge' : m[1]) : '';
    var rest = (m ? m[2] : name).replace(/^mcp_/, '').replace(/_/g, ' ');
    return { backend: backend, label: rest.charAt(0).toUpperCase() + rest.slice(1) };
  }
  function argChips(input) {
    if (!input || typeof input !== 'object') return [];
    return Object.keys(input).map(function (k) {
      var v = input[k];
      var s;
      try { s = Array.isArray(v) ? v.join(', ') : typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v); } catch (e) { s = '…'; }
      if (s.length > 60) s = s.slice(0, 57) + '…';
      return h('span', { class: 'arg' }, h('span', { class: 'arg-k' }, k), s);
    });
  }
  function seconds(ms) { return ms < 1000 ? ms + ' ms' : (ms / 1000).toFixed(ms < 10000 ? 1 : 0) + ' s'; }

  function viewChat() {
    var log = h('div', { class: 'chat-log', 'aria-live': 'polite' });
    var input = h('textarea', { class: 'chat-input', rows: 1, placeholder: 'Ask about hosts, CVEs, alerts…', 'aria-label': 'Message' });
    var send = h('button', { class: 'primary' }, 'Send');
    var stopBtn = h('button', { class: 'hidden' }, 'Stop');
    var reset = h('button', { class: 'small' }, 'New conversation');
    var meta = h('span', { class: 'muted small' });
    var err = h('div');
    var controller = null;
    var running = false;

    function activity(group, live) {
      var done = group.items.filter(function (t) { return t.state !== 'running'; }).length;
      var failed = group.items.filter(function (t) { return t.state === 'error'; }).length;
      var busy = live && done < group.items.length;
      var first = group.items[0] && group.items[0].started;
      var end = group.items.reduce(function (a, t) { return Math.max(a, t.ended || 0); }, 0);
      var summary = busy ? 'Looking things up…'
        : 'Used ' + group.items.length + (group.items.length === 1 ? ' tool' : ' tools') +
          (failed ? ' · ' + failed + ' failed' : '') + (first && end ? ' · ' + seconds(end - first) : '');
      return h('div', { class: 'activity' + (busy ? ' busy' : '') },
        h('div', { class: 'activity-head' }, h('span', { class: 'activity-icon', 'aria-hidden': 'true' }), summary),
        h('ol', { class: 'steps' }, group.items.map(function (t) {
          var l = toolLabel(t.name);
          return h('li', { class: 'step ' + t.state, title: t.name },
            h('span', { class: 'step-state', 'aria-label': t.state === 'running' ? 'running' : t.state === 'ok' ? 'done' : 'failed' }),
            l.backend ? h('span', { class: 'step-backend' }, l.backend) : null,
            h('span', { class: 'step-name' }, l.label),
            h('span', { class: 'step-args' }, argChips(t.input)),
            h('span', { class: 'step-time' }, t.ended ? seconds(t.ended - t.started) : ''));
        })));
    }
    function bubble(turn, n) {
      var live = running && n === state.chat.length - 1;
      if (turn.role === 'user') {
        return h('div', { class: 'msg user' }, h('div', { class: 'msg-body' }, turn.text));
      }
      var parts = (turn.parts || []).map(function (p) {
        return p.kind === 'tools' ? activity(p, live) : h('div', { class: 'msg-body md' }, renderMarkdown(p.text));
      });
      var last = turn.parts && turn.parts[turn.parts.length - 1];
      var waiting = live && (!last || last.kind === 'text' || last.items.every(function (t) { return t.state !== 'running'; }));
      return h('div', { class: 'msg assistant' },
        h('div', { class: 'msg-avatar', 'aria-hidden': 'true' }, brandMarkSmall()),
        h('div', { class: 'msg-main' },
          parts,
          waiting ? h('div', { class: 'thinking muted small' }, h('span', { class: 'dots', 'aria-hidden': 'true' }, h('i'), h('i'), h('i')), 'Thinking…') : null,
          turn.notice ? h('div', { class: 'msg-notice small muted' }, turn.notice) : null));
    }
    function brandMarkSmall() { return aperture.mark(18); }
    function nearBottom() {
      var doc = document.scrollingElement || document.documentElement;
      return doc.scrollHeight - doc.scrollTop - window.innerHeight < 160;
    }
    function render() {
      var stick = nearBottom();
      if (!state.chat.length) {
        var examples = ['Which hosts have critical vulnerabilities?', 'Summarise the open findings in DefectDojo', 'What is CVE-2024-3094 and are we affected?', 'Any failed logins in Graylog the last 24 hours?'];
        put(log, h('div', { class: 'chat-empty' },
          h('p', { class: 'chat-empty-title' }, 'Ask about your security stack'),
          h('p', { class: 'muted' }, 'The assistant looks things up with the same read-only tools MCP clients get, and shows each call as it runs.'),
          h('div', { class: 'suggestions' }, examples.map(function (q) {
            return h('button', { class: 'suggestion', onclick: function () { input.value = q; ask(); } }, q);
          }))));
        return;
      }
      put(log, state.chat.map(bubble));
      if (stick) window.scrollTo(0, document.documentElement.scrollHeight);
    }
    function setRunning(on) {
      running = on;
      send.disabled = on;
      reset.disabled = on;
      input.disabled = on;
      send.className = on ? 'primary hidden' : 'primary';
      stopBtn.className = on ? '' : 'hidden';
    }
    function grow() {
      input.style.height = 'auto';
      input.style.height = Math.min(input.scrollHeight, 240) + 'px';
    }

    function ask() {
      var text = input.value.trim();
      if (!text || controller) return;
      put(err);
      state.chat.push({ role: 'user', text: text });
      var reply = { role: 'assistant', text: '', parts: [], notice: '' };
      state.chat.push(reply);
      input.value = '';
      grow();
      setRunning(true);
      render();
      window.scrollTo(0, document.documentElement.scrollHeight);
      controller = new AbortController();
      var history = state.chat.slice(0, -1).filter(function (t) { return t.text; }).map(function (t) { return { role: t.role, text: t.text }; });

      function onEvent(e) {
        var last = reply.parts[reply.parts.length - 1];
        if (e.type === 'text') {
          reply.text += (reply.text ? '\n\n' : '') + e.text;
          if (last && last.kind === 'text') last.text += '\n\n' + e.text;
          else reply.parts.push({ kind: 'text', text: e.text });
        } else if (e.type === 'tool') {
          if (!last || last.kind !== 'tools') reply.parts.push(last = { kind: 'tools', items: [] });
          last.items.push({ id: e.id, name: e.name, input: e.input, state: 'running', started: Date.now() });
        } else if (e.type === 'tool_done') {
          reply.parts.forEach(function (p) {
            if (p.kind === 'tools') p.items.forEach(function (t) { if (t.id === e.id) { t.state = e.ok ? 'ok' : 'error'; t.ended = Date.now(); } });
          });
        } else if (e.type === 'notice') reply.notice = (reply.notice ? reply.notice + ' ' : '') + e.text;
        else if (e.type === 'error') reply.notice = 'Error: ' + e.message;
        else if (e.type === 'done') meta.textContent = e.model;
        render();
      }

      fetch('/api/chat', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'x-socbridge': '1', 'content-type': 'application/json' },
        body: JSON.stringify({ messages: history }),
        signal: controller.signal,
      }).then(function (res) {
        if (!res.ok) {
          return res.text().then(function (t) {
            var msg = 'HTTP ' + res.status;
            try { msg = JSON.parse(t).error || msg; } catch (e) { /* keep */ }
            if (res.status === 401) { state.me.user = null; aperture.close(); route(); }
            throw new Error(msg);
          });
        }
        var reader = res.body.getReader();
        var decoder = new TextDecoder();
        var buf = '';
        function pump() {
          return reader.read().then(function (r) {
            buf += decoder.decode(r.value || new Uint8Array(), { stream: !r.done });
            var nl;
            while ((nl = buf.indexOf('\n')) >= 0) {
              var line = buf.slice(0, nl);
              buf = buf.slice(nl + 1);
              if (line.trim()) onEvent(JSON.parse(line));
            }
            if (!r.done) return pump();
          });
        }
        return pump();
      }).catch(function (e) {
        if (e.name === 'AbortError') reply.notice = 'Stopped.';
        else reply.notice = 'Error: ' + (e.message || String(e));
      }).finally(function () {
        controller = null;
        // Tools still marked running when the stream ended never reported back.
        reply.parts.forEach(function (p) {
          if (p.kind === 'tools') p.items.forEach(function (t) { if (t.state === 'running') { t.state = 'error'; t.ended = Date.now(); } });
        });
        if (!reply.text && !reply.parts.length && !reply.notice) reply.notice = 'No answer.';
        // A failed turn without text is dropped from the history sent next time (see `history`), which keeps user/assistant alternation.
        setRunning(false);
        render();
        input.focus();
      });
    }

    send.addEventListener('click', ask);
    stopBtn.addEventListener('click', function () { if (controller) controller.abort(); });
    reset.addEventListener('click', function () { state.chat = []; meta.textContent = meta.dataset.model || ''; render(); input.focus(); });
    input.addEventListener('input', grow);
    input.addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter' && !ev.shiftKey && !ev.isComposing) { ev.preventDefault(); ask(); }
    });

    var composer = h('div', { class: 'chat-composer' },
      err,
      h('div', { class: 'composer-box' }, input, h('div', { class: 'composer-actions' }, send, stopBtn)),
      h('div', { class: 'composer-meta small muted' },
        h('span', null, 'Enter to send · Shift+Enter for a new line'), h('span', { class: 'grow' }), meta, reset));
    mount(h('div', { class: 'chat' },
      h('div', { class: 'page-head' }, h('h1', null, 'Assistant'), h('span', { class: 'muted small' }, 'Read-only · conversation is not saved · questions and the data they look up are sent to the configured AI provider')),
      log,
      composer));
    render();

    api('GET', '/chat/status').then(function (s) {
      meta.textContent = s.enabled ? s.model : '';
      meta.dataset.model = meta.textContent;
      if (!s.enabled) {
        send.disabled = true;
        input.disabled = true;
        put(err, notice('error', (s.reason || 'The assistant is not configured.') +
          (state.me.user.role === 'admin' ? ' Configure it under Server.' : ' Ask an administrator to configure it.')));
      } else input.focus();
    }).catch(function (e) { put(err, notice('error', e.message)); });
  }

  /**
   * Certificate status + settings form. `call` is api() or a wrapper that adds
   * the setup token (first-time setup, before any admin exists). `onUpdate`
   * receives every fresh view.
   */
  function tlsPanel(call, onUpdate, opts) {
    opts = opts || {};
    var statusBox = h('div', null, h('p', { class: 'muted' }, 'Loading…'));
    var formBox = h('div');
    var jobBox = h('div');
    var pollTimer = 0;
    var formBuilt = false;
    var inputs = {};
    var renderToken = function () {};

    function stop() { clearTimeout(pollTimer); pollTimer = 0; }
    window.addEventListener('hashchange', stop, { once: true });

    function row(label, value) {
      return h('tr', null, h('th', null, label), h('td', null, value));
    }

    function renderStatus(v) {
      if (v.envMode === 'off') {
        put(statusBox, h('h2', null, 'Current certificate'),
          h('p', null, 'TLS is terminated by the reverse proxy in front of SocBridge (TLS_MODE=off), so the certificate is managed there.'));
        return;
      }
      var c = v.certificate;
      var servingLabel = {
        builtin: 'Built-in CA',
        acme: v.settings.acmeStaging ? "Let's Encrypt staging (untrusted)" : "Let's Encrypt",
        file: 'Certificate files',
        'env-acme': "Let's Encrypt (environment)",
      }[v.serving] || v.serving;
      put(statusBox, h('div', null,
        h('div', { class: 'page-head' },
          h('h2', null, 'Current certificate'),
          h('span', { class: 'badge on' }, servingLabel)),
        c ? h('div', { class: 'table-wrap' }, h('table', { class: 'kv' }, h('tbody', null,
          row('Names', h('span', { class: 'data' }, c.sans.join(', '))),
          row('Issuer', c.issuer),
          row('Expires', fmt(c.validTo) + ' (' + c.daysLeft + ' days)'),
          row('SHA-256', h('span', { class: 'data' }, c.fingerprint))))) : h('p', { class: 'muted' }, 'No certificate information.'),
        v.serving === 'builtin' && v.caAvailable
          ? h('p', { class: 'small muted' }, 'Clients must trust the built-in CA: ', h('a', { href: '/ca.crt' }, 'download ca.crt'), '.')
          : null,
        v.staging ? notice('error', "This is a Let's Encrypt STAGING certificate: browsers show a warning and passkeys do not work. " +
          "Untick “Use Let's Encrypt staging” and press “Save & apply”.") : null,
        v.lastError ? notice('error', 'Last attempt failed: ' + v.lastError) : null));
    }

    function renderJob(job) {
      if (!job) { put(jobBox); return; }
      var title = (job.kind === 'test' ? 'Staging test' : 'Certificate request') + ' · ' +
        (job.state === 'running' ? 'running…' : job.state === 'ok' ? 'succeeded' : 'failed');
      put(jobBox, h('div', { class: 'panel' },
        h('div', { class: 'page-head' }, h('h2', null, title),
          h('span', { class: 'badge' + (job.state === 'error' ? ' error' : job.state === 'ok' ? ' on' : '') }, job.state)),
        h('pre', { class: 'joblog' }, job.log.map(function (l) {
          return new Date(l.ts).toLocaleTimeString() + '  ' + l.msg;
        }).join('\n') || 'Starting…')));
    }

    function setBusy(running) {
      Object.keys(inputs).forEach(function (k) { if (inputs[k].tagName === 'BUTTON') inputs[k].disabled = running; });
    }

    function buildForm(v) {
      if (v.envMode === 'off') { put(formBox); return; }
      if (v.locked) {
        put(formBox, h('div', { class: 'panel' },
          h('h2', null, 'Settings'),
          h('p', null, 'Certificate settings are managed by the environment: ', h('code', null, v.lockedReason || ''), '.'),
          h('p', { class: 'muted small' }, 'Remove TLS_MODE from the service environment to manage the certificate here.')));
        return;
      }
      var st = v.settings;
      var acmeFirst = st.mode === 'acme' || !!opts.preferAcme;
      var modeBuiltin = h('input', { type: 'radio', name: 'mode', value: 'builtin', checked: !acmeFirst });
      var modeAcme = h('input', { type: 'radio', name: 'mode', value: 'acme', checked: acmeFirst });
      var token = h('input', { type: 'password', autocomplete: 'new-password' });
      var tokenLabel = h('label');
      var tokenStatus = h('div', { class: 'token-status' });
      var checkBox = h('div');
      renderToken = function (s2) {
        put(tokenLabel, s2.cloudflareTokenSet ? 'Replace Cloudflare API token' : 'Cloudflare API token');
        token.placeholder = s2.cloudflareTokenSet ? 'Leave empty to keep the stored token' : 'Paste the token value';
        put(tokenStatus, s2.cloudflareTokenSet
          ? h('p', { class: 'small' }, h('span', { class: 'badge on' }, 'Token stored'), ' ',
              h('span', { class: 'data' }, s2.cloudflareTokenHint || ''),
              s2.cloudflareTokenSavedAt ? ' · saved ' + fmt(s2.cloudflareTokenSavedAt) : '',
              h('span', { class: 'muted' }, ' — compare with the token list in Cloudflare.'))
          : h('p', { class: 'small' }, h('span', { class: 'badge error' }, 'No token stored'),
              h('span', { class: 'muted' }, ' Paste one below, check it, then save.')));
      };
      renderToken(st);
      function showCheck(r) {
        var who = r.source === 'entered' ? 'The token you typed (not saved yet)' : 'The stored token';
        put(checkBox, r.ok
          ? notice('success', who + ' works: ' + r.zones.map(function (z) { return z.domain + ' → zone ' + z.zone; }).join(', ') +
              '. Zone and DNS records are readable. DNS → Edit is only proven by creating a record: run "Test with staging".')
          : notice('error', who + ' failed: ' + r.error));
      }
      var zoneHint = v.domains.map(function (d) { var p = d.split('.'); return p.length > 2 ? p.slice(-2).join('.') : d; })
        .filter(function (z, i, a) { return a.indexOf(z) === i; }).join(', ');
      var requirements = h('details', { class: 'help', open: !st.cloudflareTokenSet },
        h('summary', null, 'What the Cloudflare API token needs'),
        h('ul', null,
          h('li', null, 'An ', h('strong', null, 'API token'), ' — not the Global API Key, the Origin CA key or the token ID. ',
            'Either kind works: My Profile → API Tokens (user token) or Manage Account → Account API Tokens (account token, starts with ',
            h('code', null, 'cfat_'), ').'),
          h('li', null, 'Permissions — both are required:',
            h('ul', null,
              h('li', null, h('code', null, 'Zone → Zone → Read'), ' — to find the zone'),
              h('li', null, h('code', null, 'Zone → DNS → Edit'), ' — to add and remove the temporary ', h('code', null, '_acme-challenge'), ' TXT record'))),
          h('li', null, 'Zone Resources: Include → Specific zone → ', h('span', { class: 'data' }, zoneHint || 'your zone'),
            ' (the zone that holds ', h('span', { class: 'data' }, v.domains.join(', ')), ').'),
          v.skippedNames && v.skippedNames.length
            ? h('li', null, 'Not in the certificate: ', h('span', { class: 'data' }, v.skippedNames.join(', ')),
                ' — not public DNS names (from TLS_EXTRA_SANS), so Let’s Encrypt cannot include them. Use the full name instead.')
            : null,
          h('li', null, "Cloudflare's token list should then show ", h('strong', null, 'Zone Read, DNS Write'),
            ' (or Zone Read, DNS Read, DNS Write). ', h('strong', null, 'DNS Read alone is not enough.')),
          h('li', null, 'No expiry, or renew it in time: certificates are renewed automatically about every 60 days. ',
            'If you use Client IP Address Filtering, include this server’s outbound address.')));
      var email = h('input', { type: 'text', value: st.acmeEmail || '', placeholder: 'ops@example.com (optional)' });
      var staging = h('input', { type: 'checkbox', checked: st.acmeStaging });
      var tos = h('input', { type: 'checkbox', checked: st.acmeAgreeTos });
      var err = h('div');
      var acmeFields = h('div', { class: acmeFirst ? '' : 'hidden' },
        requirements,
        tokenStatus,
        tokenLabel, token,
        h('div', { class: 'help' }, 'Stored encrypted and never shown again; only the first and last four characters are displayed.'),
        h('div', { class: 'row' }, inputs.check = h('button', {
          onclick: function () {
            put(checkBox);
            busy(inputs.check, call('POST', '/server/tls/check-token', { cloudflareToken: token.value.trim() || undefined }).then(showCheck), checkBox);
          },
        }, 'Check token')),
        checkBox,
        h('label', null, 'Contact e-mail'), email,
        h('div', { class: 'help' }, "Let's Encrypt uses it for account and expiry notices."),
        h('label', { class: 'inline' }, staging, "Use Let's Encrypt staging (untrusted test certificates)"),
        h('label', { class: 'inline' }, tos, "I accept the Let's Encrypt Subscriber Agreement"));
      function onMode() { acmeFields.className = modeAcme.checked ? '' : 'hidden'; }
      modeBuiltin.addEventListener('change', onMode);
      modeAcme.addEventListener('change', onMode);
      function collect() {
        return {
          mode: modeAcme.checked ? 'acme' : 'builtin',
          cloudflareToken: token.value.trim() || undefined,
          acmeEmail: email.value.trim() || undefined,
          acmeStaging: staging.checked,
          acmeAgreeTos: tos.checked,
        };
      }
      inputs.test = h('button', {
        onclick: function () {
          // The test does not store the token, so keep it in the field for "Save & apply".
          busy(inputs.test, call('POST', '/server/tls/test', collect()).then(update), err);
        },
      }, 'Test with staging');
      inputs.save = h('button', {
        class: 'primary',
        onclick: function () {
          busy(inputs.save, call('PUT', '/server/tls', collect()).then(function (v2) { token.value = ''; put(checkBox); update(v2); }), err);
        },
      }, 'Save & apply');
      put(formBox, h('div', { class: 'panel' },
        h('h2', null, 'Settings'),
        h('label', { class: 'inline' }, modeBuiltin, 'Built-in CA — works offline; clients must trust ca.crt'),
        h('label', { class: 'inline' }, modeAcme, "Let's Encrypt via Cloudflare DNS-01 — publicly trusted; the service stays internal"),
        acmeFields,
        h('div', { class: 'row' }, inputs.test, inputs.save), err,
        h('p', { class: 'muted small' },
          'Switching keeps the current certificate until the new one is issued. Issuance takes one to three minutes; ' +
          'the built-in CA keeps serving if it fails, and the request is retried every 30 minutes.')));
      formBuilt = true;
    }

    function update(v) {
      renderStatus(v);
      if (!formBuilt) buildForm(v);
      else if (v.settings) renderToken(v.settings);
      renderJob(v.job);
      var running = v.job && v.job.state === 'running';
      setBusy(!!running);
      stop();
      if (running) pollTimer = setTimeout(load, 2500);
      if (onUpdate) onUpdate(v);
    }

    function load() {
      call('GET', '/server/tls').then(update).catch(function (e) { put(statusBox, notice('error', e.message)); });
    }

    return {
      node: h('div', { class: 'split' },
        h('div', null, h('div', { class: 'panel' }, statusBox), jobBox),
        formBox),
      load: load,
      stop: stop,
    };
  }

  function viewPasskeys() {
    var listBox = h('div');
    var err = h('div');
    function load() {
      api('GET', '/passkeys').then(function (keys) {
        put(listBox, h('div', { class: 'table-wrap' }, h('table', null,
          h('thead', null, h('tr', null, h('th', null, 'Label'), h('th', null, 'Added'), h('th', null, 'Last used'), h('th'))),
          h('tbody', null, keys.map(function (k) {
            var b = h('button', {
              class: 'danger',
              disabled: keys.length <= 1,
              onclick: function () {
                if (!confirm('Remove passkey "' + k.label + '"?')) return;
                busy(b, api('DELETE', '/passkeys/' + encodeURIComponent(k.id)).then(load));
              },
            }, 'Remove');
            return h('tr', null, h('td', null, k.label), h('td', null, fmt(k.createdAt)), h('td', null, fmt(k.lastUsedAt)), h('td', null, b));
          })))));
      });
    }
    var label = h('input', { type: 'text', value: deviceLabel(), class: 'grow' });
    var add = h('button', {
      class: 'primary',
      onclick: function () { busy(add, register('/auth/add/options', {}, label.value).then(load), err); },
    }, 'Add passkey');
    var endOut = h('div');
    var endOthers = h('button', {
      onclick: function () {
        busy(endOthers, api('DELETE', '/sessions/others').then(function (r) { put(endOut, notice('success', 'Ended ' + r.ended + ' other session(s).')); }), endOut);
      },
    }, 'End other sessions');
    mount(h('div', null,
      h('h1', null, 'Passkeys'),
      h('div', { class: 'panel' },
        h('p', { class: 'muted small' }, 'Register a passkey on each device you sign in from, so losing one device does not lock you out.'),
        h('div', { class: 'row' }, label, add), err),
      h('div', { class: 'panel' }, listBox),
      h('div', { class: 'panel' },
        h('p', { class: 'muted small' }, 'Signed in somewhere you no longer use? End every session except this one. Removing a passkey also ends the sessions opened with it.'),
        endOthers, endOut)));
    load();
  }

  function viewUsers() {
    var me = state.me;
    var usersBox = h('div');
    var backendsP = api('GET', '/backends');
    var invitesBox = h('div');
    var inviteOut = h('div');
    var err = h('div');
    function load() {
      Promise.all([api('GET', '/users'), backendsP]).then(function (res) {
        var users = res[0];
        var allBackends = res[1];
        var backends = res[1].filter(function (b) { return b.tools.some(function (t) { return t.access === 'write'; }); });
        function grants(u) {
          return h('div', { class: 'badges' }, backends.map(function (b) {
            var cb = h('input', { type: 'checkbox', checked: u.writeBackends.indexOf(b.id) >= 0 });
            cb.addEventListener('change', function () {
              var next = u.writeBackends.filter(function (x) { return x !== b.id; });
              if (cb.checked) next.push(b.id);
              cb.disabled = true;
              api('PATCH', '/users/' + u.id, { writeBackends: next })
                .then(function () { u.writeBackends = next; })
                .catch(function (e) { cb.checked = !cb.checked; alert(e.message); })
                .then(function () { cb.disabled = false; });
            });
            return h('label', { class: 'inline small', title: 'Lets ' + u.name + ' create tokens that write to ' + b.title }, cb, b.title);
          }));
        }
        function reads(u) {
          return h('div', { class: 'badges' }, allBackends.map(function (b) {
            var cb = h('input', { type: 'checkbox', checked: !u.readBackends || u.readBackends.indexOf(b.id) >= 0 });
            cb.addEventListener('change', function () {
              var ids = allBackends.map(function (x) { return x.id; });
              var next = (u.readBackends || ids).filter(function (x) { return x !== b.id; });
              if (cb.checked) next.push(b.id);
              var value = ids.every(function (x) { return next.indexOf(x) >= 0; }) ? null : next;
              cb.disabled = true;
              api('PATCH', '/users/' + u.id, { readBackends: value })
                .then(function () { u.readBackends = value; })
                .catch(function (e) { cb.checked = !cb.checked; alert(e.message); })
                .then(function () { cb.disabled = false; });
            });
            return h('label', { class: 'inline small', title: 'Lets ' + u.name + ' read ' + b.title + ' in the console, the assistant and through tokens' }, cb, b.title);
          }));
        }
        put(usersBox, h('div', { class: 'table-wrap' }, h('table', null,
          h('thead', null, h('tr', null, h('th', null, 'Name'), h('th', null, 'Role'), h('th', null, 'Status'), h('th', null, 'Passkeys'), h('th', null, 'Read access'), h('th', null, 'Write grants'), h('th', null, 'Created'), h('th'))),
          h('tbody', null, users.map(function (u) {
            var self = u.id === me.user.id;
            var role = h('button', {
              disabled: self,
              onclick: function () { busy(role, api('PATCH', '/users/' + u.id, { role: u.role === 'admin' ? 'user' : 'admin' }).then(load)); },
            }, u.role === 'admin' ? 'Make user' : 'Make admin');
            var dis = h('button', {
              disabled: self,
              onclick: function () { busy(dis, api('PATCH', '/users/' + u.id, { disabled: !u.disabled }).then(load)); },
            }, u.disabled ? 'Enable' : 'Disable');
            var del = h('button', {
              class: 'danger',
              disabled: self,
              onclick: function () {
                if (!confirm('Delete ' + u.name + ' and revoke all their tokens?')) return;
                busy(del, api('DELETE', '/users/' + u.id).then(load));
              },
            }, 'Delete');
            return h('tr', null,
              h('td', null, u.name + (self ? ' (you)' : '')),
              h('td', null, u.role),
              h('td', null, u.disabled ? h('span', { class: 'badge error' }, 'disabled') : h('span', { class: 'badge on' }, 'active')),
              h('td', null, String(u.passkeys)),
              h('td', null, reads(u)),
              h('td', null, grants(u)),
              h('td', null, fmt(u.createdAt)),
              h('td', null, h('div', { class: 'row' }, role, dis, del)));
          })))));
      }).catch(function (e) { put(usersBox, notice('error', e.message)); });
      api('GET', '/invites').then(function (invites) {
        if (!invites.length) { put(invitesBox, h('p', { class: 'muted small' }, 'No open invites.')); return; }
        put(invitesBox, h('table', null,
          h('thead', null, h('tr', null, h('th', null, 'For'), h('th', null, 'Role'), h('th', null, 'Expires'), h('th'))),
          h('tbody', null, invites.map(function (i) {
            var b = h('button', { class: 'danger', onclick: function () { busy(b, api('DELETE', '/invites/' + i.id).then(load)); } }, 'Cancel');
            return h('tr', null, h('td', null, i.name || '—'), h('td', null, i.role), h('td', null, fmt(i.expiresAt)), h('td', null, b));
          }))));
      });
    }
    var forName = h('input', { type: 'text', placeholder: 'Who is this for? (optional)', class: 'grow' });
    var role = h('select', null, h('option', { value: 'user' }, 'User'), h('option', { value: 'admin' }, 'Admin'));
    var btn = h('button', {
      class: 'primary',
      onclick: function () {
        busy(btn, api('POST', '/invites', { role: role.value, name: forName.value }).then(function (inv) {
          forName.value = '';
          put(inviteOut, h('div', { class: 'notice success' },
            h('strong', null, 'Send this link privately. It works once and expires ' + fmt(inv.expiresAt) + '.'),
            h('div', { class: 'secret data' }, inv.url)));
          load();
        }), err);
      },
    }, 'Create invite');
    mount(h('div', null,
      h('h1', null, 'Users'),
      h('div', { class: 'panel' }, h('h2', null, 'Invite someone'),
        h('div', { class: 'row' }, forName, role, btn), err, inviteOut),
      h('div', { class: 'panel' }, h('h2', null, 'Open invites'), invitesBox),
      h('div', { class: 'panel' }, h('h2', null, 'All users'),
        h('p', { class: 'muted small' }, 'Write grants let a user create tokens that use a backend\'s write tools. Write also has to be allowed for the backend (Backends page) and chosen for the token.'),
        usersBox)));
    load();
  }

  /**
   * Usage overview built from the audit log: how much each backend is called,
   * which tools, by whom and through which client. Administrators only.
   */
  var BACKEND_TITLE = { wazuh: 'Wazuh', trivy: 'Trivy', defectdojo: 'DefectDojo', graylog: 'Graylog', core: 'SocBridge' };
  function backendTitle(id) { return BACKEND_TITLE[id] || id; }
  function viewUsage() {
    var box = h('div', null, h('p', { class: 'muted' }, 'Loading…'));
    var range = h('select', { 'aria-label': 'Period', onchange: load },
      h('option', { value: '1' }, 'Last 24 hours'), h('option', { value: '7' }, 'Last 7 days'),
      h('option', { value: '30', selected: true }, 'Last 30 days'), h('option', { value: '90' }, 'Last 90 days'),
      h('option', { value: '0' }, 'All recorded'));
    range.value = '30';
    var open = {};

    function pct(n, max) { return max ? Math.max(2, Math.round((n / max) * 100)) : 0; }
    function bar(n, max) {
      return h('div', { class: 'usage-bar', 'aria-hidden': 'true' }, h('span', { style: { width: pct(n, max) + '%' } }));
    }
    function avg(c) { return c.calls ? Math.round(c.totalMs / c.calls) + ' ms' : '—'; }
    function failed(c) {
      var n = c.errors + c.denied;
      if (!n) return h('span', { class: 'muted' }, '0');
      return h('span', { class: 'badge error', title: c.errors + ' errors, ' + c.denied + ' denied' }, String(n));
    }
    function kpi(label, value, sub) {
      return h('div', { class: 'kpi' }, h('div', { class: 'kpi-label' }, label), h('div', { class: 'kpi-value' }, value), sub ? h('div', { class: 'help' }, sub) : null);
    }
    function days(s) {
      // Fill gaps so quiet days show as empty columns.
      var map = {};
      s.byDay.forEach(function (d) { map[d.day] = d; });
      var n = Number(range.value);
      var end = new Date();
      var start = n ? new Date(end.getTime() - (n - 1) * 86400000) : (s.totals.first ? new Date(s.totals.first) : end);
      var out = [];
      for (var d = new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth(), start.getUTCDate())); d <= end && out.length < 400; d = new Date(d.getTime() + 86400000)) {
        var key = d.toISOString().slice(0, 10);
        out.push(map[key] || { day: key, calls: 0, errors: 0 });
      }
      return out;
    }
    function dayChart(s) {
      var list = days(s);
      if (list.length < 2) return null;
      var max = Math.max.apply(null, list.map(function (d) { return d.calls; }));
      return h('div', { class: 'panel' },
        h('h2', null, 'Calls per day'),
        h('div', { class: 'usage-days', role: 'img', 'aria-label': 'Calls per day, peak ' + max },
          list.map(function (d) {
            return h('div', { class: 'col', title: d.day + ': ' + d.calls + ' calls' + (d.errors ? ', ' + d.errors + ' failed' : '') },
              h('span', { class: 'fill', style: { height: (d.calls ? pct(d.calls, max) : 0) + '%' } },
                d.errors ? h('span', { class: 'err', style: { height: Math.round((d.errors / d.calls) * 100) + '%' } }) : null));
          })),
        h('div', { class: 'usage-days-axis help' }, h('span', null, list[0].day), h('span', null, list[list.length - 1].day)));
    }
    function backendTable(s) {
      var max = s.byBackend.length ? s.byBackend[0].calls : 0;
      return h('div', { class: 'panel' },
        h('h2', null, 'Per service'),
        h('div', { class: 'table-wrap' }, h('table', null,
          h('thead', null, h('tr', null, h('th', null, 'Service'), h('th', { class: 'num' }, 'Calls'), h('th', null, ''),
            h('th', { class: 'num' }, 'Writes'), h('th', { class: 'num' }, 'Failed'), h('th', { class: 'num' }, 'Avg time'))),
          h('tbody', null, s.byBackend.map(function (b) {
            return h('tr', null, h('td', null, backendTitle(b.backend)), h('td', { class: 'num' }, String(b.calls)),
              h('td', { class: 'bar-cell' }, bar(b.calls, max)), h('td', { class: 'num' }, String(b.writes)),
              h('td', { class: 'num' }, failed(b)), h('td', { class: 'num' }, avg(b)));
          })))));
    }
    function toolTable(s) {
      var list = s.byTool.slice(0, 15);
      var max = list.length ? list[0].calls : 0;
      return h('div', { class: 'panel' },
        h('h2', null, 'Most used tools'),
        s.byTool.length > list.length ? h('p', { class: 'muted small' }, 'Top ' + list.length + ' of ' + s.byTool.length + ' tools used.') : null,
        h('div', { class: 'table-wrap' }, h('table', null,
          h('thead', null, h('tr', null, h('th', null, 'Tool'), h('th', null, 'Service'), h('th', { class: 'num' }, 'Calls'), h('th', null, ''),
            h('th', { class: 'num' }, 'Failed'), h('th', { class: 'num' }, 'Avg time'))),
          h('tbody', null, list.map(function (t) {
            return h('tr', null, h('td', null, h('code', null, t.tool), t.writes ? [' ', h('span', { class: 'badge write' }, 'write')] : null),
              h('td', null, backendTitle(t.backend)), h('td', { class: 'num' }, String(t.calls)),
              h('td', { class: 'bar-cell' }, bar(t.calls, max)), h('td', { class: 'num' }, failed(t)), h('td', { class: 'num' }, avg(t)));
          })))));
    }
    function userDetail(u, backends) {
      var bmax = Math.max.apply(null, backends.map(function (b) { return u.backends[b] || 0; }).concat([1]));
      var tmax = u.tools.length ? u.tools[0].calls : 0;
      return h('tr', { class: 'usage-detail' }, h('td', { colspan: String(5 + backends.length) },
        h('div', { class: 'usage-detail-grid' },
          h('div', null, h('h3', null, 'Services'), h('table', null, h('tbody', null, backends.filter(function (b) { return u.backends[b]; }).map(function (b) {
            return h('tr', null, h('td', null, backendTitle(b)), h('td', { class: 'num' }, String(u.backends[b])), h('td', { class: 'bar-cell' }, bar(u.backends[b], bmax)));
          })))),
          h('div', null, h('h3', null, 'Top tools'), h('table', null, h('tbody', null, u.tools.map(function (t) {
            return h('tr', null, h('td', null, h('code', null, t.tool)), h('td', { class: 'num' }, String(t.calls)), h('td', { class: 'bar-cell' }, bar(t.calls, tmax)));
          })))),
          h('div', null, h('h3', null, 'Via'), h('table', null, h('tbody', null, u.credentials.map(function (c) {
            return h('tr', null, h('td', null, c.label, h('div', { class: 'help' }, c.credential)), h('td', { class: 'num' }, String(c.calls)));
          })))))));
    }
    function userTable(s) {
      var backends = s.byBackend.map(function (b) { return b.backend; });
      var max = s.byUser.length ? s.byUser[0].calls : 0;
      var rows = [];
      s.byUser.forEach(function (u) {
        var tr = h('tr', {
          class: 'clickable' + (open[u.user] ? ' selected' : ''), tabindex: '0', 'aria-expanded': open[u.user] ? 'true' : 'false',
          onclick: function () { open[u.user] = !open[u.user]; render(s); },
          onkeydown: function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open[u.user] = !open[u.user]; render(s); } },
        },
          h('td', null, u.user, h('div', { class: 'help' }, [u.sources.mcp ? u.sources.mcp + ' via MCP' : null, u.sources.chat ? u.sources.chat + ' via assistant' : null].filter(Boolean).join(' · '))),
          h('td', { class: 'num' }, String(u.calls), bar(u.calls, max)),
          backends.map(function (b) { return h('td', { class: 'num' }, u.backends[b] ? String(u.backends[b]) : h('span', { class: 'muted' }, '·')); }),
          h('td', { class: 'num' }, String(u.writes)),
          h('td', { class: 'num' }, failed(u)),
          h('td', { class: 'nowrap' }, fmt(u.lastAt)));
        rows.push(tr);
        if (open[u.user]) rows.push(userDetail(u, backends));
      });
      return h('div', { class: 'panel' },
        h('h2', null, 'Per user'),
        h('p', { class: 'muted small' }, 'Calls per service for each user. Select a user for their tools and the tokens or clients they used.'),
        h('div', { class: 'table-wrap' }, h('table', null,
          h('thead', null, h('tr', null, h('th', null, 'User'), h('th', { class: 'num' }, 'Calls'),
            backends.map(function (b) { return h('th', { class: 'num' }, backendTitle(b)); }),
            h('th', { class: 'num' }, 'Writes'), h('th', { class: 'num' }, 'Failed'), h('th', null, 'Last call'))),
          h('tbody', null, rows))));
    }
    function render(s) {
      var t = s.totals;
      if (!t.calls) { put(box, h('div', { class: 'panel' }, h('p', { class: 'muted' }, 'No tool calls in this period.'))); return; }
      var src = s.bySource;
      put(box,
        h('div', { class: 'kpis' },
          kpi('Tool calls', String(t.calls), [src.mcp ? src.mcp + ' from MCP clients' : null, src.chat ? src.chat + ' from the assistant' : null].filter(Boolean).join(', ')),
          kpi('Users', String(t.users)),
          kpi('Services used', String(s.byBackend.length), s.byTool.length + ' different tools'),
          kpi('Writes', String(t.writes)),
          kpi('Failed', String(t.errors + t.denied), t.errors + ' errors, ' + t.denied + ' denied'),
          kpi('Avg time', avg(t))),
        dayChart(s),
        backendTable(s),
        userTable(s),
        toolTable(s));
    }
    function load() {
      put(box, h('p', { class: 'muted' }, 'Loading…'));
      api('GET', '/audit/stats?days=' + range.value).then(render).catch(function (e) { put(box, notice('error', e.message)); });
    }
    mount(h('div', null,
      h('div', { class: 'page-head' }, h('h1', null, 'Usage'), range),
      h('p', { class: 'muted small' }, 'How MCP is used: tool calls to each service from MCP clients and the assistant, per user. Counted from the audit log; see the Audit page for single calls and their arguments.'),
      box));
    load();
  }

  /** Audit log of tool calls (MCP clients and the assistant), administrators only. */
  function viewAudit() {
    var box = h('div', null, h('p', { class: 'muted' }, 'Loading…'));
    var more = h('div');
    var status = h('div');
    var user = h('input', { type: 'text', placeholder: 'User', 'aria-label': 'User' });
    var tool = h('input', { type: 'text', placeholder: 'Tool (part of the name)', 'aria-label': 'Tool' });
    var outcome = h('select', { 'aria-label': 'Outcome' },
      h('option', { value: '' }, 'Any outcome'), h('option', { value: 'ok' }, 'OK'),
      h('option', { value: 'error' }, 'Error'), h('option', { value: 'denied' }, 'Denied'), h('option', { value: 'started' }, 'Started'));
    var access = h('select', { 'aria-label': 'Access' },
      h('option', { value: '' }, 'Read and write'), h('option', { value: 'write' }, 'Write only'), h('option', { value: 'read' }, 'Read only'));
    var rows = [];

    function query(before) {
      var q = new URLSearchParams({ limit: '100' });
      if (user.value.trim()) q.set('user', user.value.trim());
      if (tool.value.trim()) q.set('tool', tool.value.trim());
      if (outcome.value) q.set('outcome', outcome.value);
      if (access.value) q.set('access', access.value);
      if (before) q.set('before', before);
      return api('GET', '/audit?' + q.toString());
    }
    function row(r) {
      var badge = r.outcome === 'ok' ? h('span', { class: 'badge on' }, 'ok') : r.outcome === 'started' ? h('span', { class: 'badge' }, 'started') : h('span', { class: 'badge error' }, r.outcome);
      var args = JSON.stringify(r.args);
      return h('tr', null,
        h('td', { class: 'nowrap' }, fmt(r.at)),
        h('td', null, r.user, h('div', { class: 'help' }, (r.source === 'chat' ? 'assistant' : (r.source === 'admin' || r.source === 'web') ? 'console' : (r.credentialLabel || r.credential)))),
        h('td', null, h('code', null, r.tool)),
        h('td', null, r.access === 'write' ? h('span', { class: 'badge write' }, 'write') : h('span', { class: 'badge' }, 'read')),
        h('td', null, badge, r.message ? h('div', { class: 'help' }, r.message) : null),
        h('td', { class: 'nowrap' }, r.source === 'admin' ? '' : r.durationMs + ' ms'),
        h('td', null, h('code', { class: 'args', title: args }, args.length > 160 ? args.slice(0, 160) + '…' : args)));
    }
    function render(next) {
      if (!rows.length) { put(box, h('p', { class: 'muted' }, 'Nothing recorded yet.')); put(more); return; }
      put(box, h('div', { class: 'table-wrap' }, h('table', null,
        h('thead', null, h('tr', null, h('th', null, 'Time'), h('th', null, 'User'), h('th', null, 'Tool'), h('th', null, 'Access'),
          h('th', null, 'Outcome'), h('th', null, 'Duration'), h('th', null, 'Arguments'))),
        h('tbody', null, rows.map(row)))));
      var btn = next ? h('button', { onclick: function () { busy(btn, query(next).then(function (r) { rows = rows.concat(r.records); render(r.next); })); } }, 'Older') : null;
      put(more, btn);
    }
    function load() {
      query().then(function (r) {
        rows = r.records;
        put(status, r.writable ? null : notice('error', 'The audit log cannot be written right now. Write tools are refused until it can.'));
        render(r.next);
      }).catch(function (e) { put(box, notice('error', e.message)); });
    }
    var apply = h('button', { class: 'primary', onclick: load }, 'Apply');
    var verifyOut = h('div');
    var verify = h('button', {
      onclick: function () {
        busy(verify, api('GET', '/audit/verify').then(function (v) {
          put(verifyOut, notice(v.ok ? 'success' : 'error', v.ok
            ? v.records + ' records; every line decrypts and the hash chains are unbroken.' + (v.dropped ? ' Rotation has dropped ' + v.dropped + ' older records.' : '')
            : 'Problems found: ' + v.problems.slice(0, 10).join('; ')));
        }), verifyOut);
      },
    }, 'Verify integrity');

    var gelf = h('input', { type: 'url', placeholder: 'http://graylog:12201/gelf', class: 'grow' });
    var gelfOut = h('div');
    api('GET', '/audit/settings').then(function (s) { gelf.value = s.gelfUrl; });
    var gelfSave = h('button', {
      onclick: function () {
        busy(gelfSave, api('PUT', '/audit/settings', { gelfUrl: gelf.value.trim() }).then(function () {
          put(gelfOut, notice('success', gelf.value.trim() ? 'Saved. New records are forwarded.' : 'Saved. Forwarding is off.'));
        }), gelfOut);
      },
    }, 'Save');

    mount(h('div', null,
      h('h1', null, 'Audit log'),
      h('p', { class: 'muted small' }, 'Every tool call from MCP clients and the assistant: who, with which credential, which tool and arguments (secrets redacted), the outcome and how long it took. Sign-ins and changes to users, tokens and settings are recorded too, as auth.* and admin.*. Results are not stored, only their size and a hash. The log is append-only and encrypted at rest.'),
      status,
      h('div', { class: 'panel' },
        h('div', { class: 'row' }, user, tool, outcome, access, apply, verify),
        verifyOut, box, more),
      h('div', { class: 'panel' },
        h('h2', null, 'Forward to Graylog'),
        h('p', { class: 'muted small' }, 'Optional. Sends each record to a Graylog GELF HTTP input as well (System → Inputs → GELF HTTP). Leave empty to keep the log here only.'),
        h('div', { class: 'row' }, gelf, gelfSave), gelfOut)));
    load();
  }

  function viewBackends() {
    var box = h('div', null, h('p', { class: 'muted' }, 'Loading…'));
    mount(h('div', null, h('h1', null, 'Backends'),
      h('p', { class: 'muted small' }, 'Settings are stored encrypted. Secret fields are write-only: leave them empty to keep the current value.'),
      box));
    api('GET', '/backends').then(function (list) {
      put(box, ...list.map(backendPanel));
    }).catch(function (e) { put(box, notice('error', e.message)); });
  }

  /**
   * Setup guide for one backend: what to collect, where to find it, and which
   * field it goes into (the chips jump to that field).
   */
  function backendGuide(g, b, inputs) {
    var labelOf = {};
    b.fields.forEach(function (f) { labelOf[f.key] = f.label; });
    function chip(key) {
      return h('button', {
        class: 'chip',
        title: 'Go to this field',
        onclick: function () {
          var el = inputs[key];
          if (!el) return;
          el.scrollIntoView({ behavior: 'smooth', block: 'center' });
          el.focus();
        },
      }, '→ ' + (labelOf[key] || key));
    }
    return h('div', { class: 'guide' },
      h('p', null, g.intro),
      g.before && g.before.length ? h('div', null, h('h3', null, 'Before you start'), h('ul', null, g.before.map(function (t) { return h('li', null, t); }))) : null,
      h('h3', null, 'What you need and where to find it'),
      h('ol', { class: 'guide-items' }, g.items.map(function (it) {
        return h('li', null,
          h('div', { class: 'guide-item-head' }, h('strong', null, it.title), (it.fields || []).map(chip)),
          h('ul', null, it.steps.map(function (t) { return h('li', null, t); })),
          it.code ? h('pre', { class: 'small' }, it.code) : null);
      })),
      h('h3', null, 'Check that it works'),
      h('ul', null, g.verify.map(function (t) { return h('li', null, t); })),
      g.docs && g.docs.length
        ? h('p', { class: 'small' }, 'Documentation: ', g.docs.map(function (d, i) {
            return [i ? ' · ' : '', h('a', { href: d.url, target: '_blank', rel: 'noopener noreferrer' }, d.label)];
          }))
        : null);
  }

  // What the backend's tools can do: read always; write if it has write
  // tools, shown as off until this installation allows them.
  function accessBadges(b) {
    if (b.maturity !== 'ready') return null;
    var write = b.tools.some(function (t) { return t.access === 'write'; });
    var out = [h('span', { class: 'badge on', title: 'Has read-only tools' }, 'Read')];
    if (write) {
      out.push(b.allowWrite
        ? h('span', { class: 'badge write', title: 'Write tools are allowed on this installation. Users still need a write grant and a write-scoped token.' }, 'Write')
        : h('span', { class: 'badge muted-write', title: 'This backend has write tools, but they are off. Turn on "Allow write tools" under Tools.' }, 'Write · off'));
    } else if (b.dynamicToolPattern) {
      out.push(h('span', { class: 'badge muted-write', title: 'No write tools of its own; forwarded tools you allowlist may write.' }, 'Write · via passthrough'));
    } else {
      out.push(h('span', { class: 'badge', title: 'This backend has no write tools.' }, 'Read only'));
      out.shift();
    }
    return out;
  }

  function backendPanel(b) {
    var inputs = {};
    var enabled = h('input', { type: 'checkbox', checked: b.enabled });
    var out = h('div');
    // Connection state from the status bar's last check: online (and how
    // the connection is protected), degraded, down, or why it is off.
    var connBadge = function (s, svc) {
      if (!s.configured) return h('span', { class: 'badge' }, 'not configured');
      if (!s.enabled) return h('span', { class: 'badge' }, 'disabled');
      if (!svc) return h('span', { class: 'badge' }, 'checking…');
      var t = svc.transport || b.transport;
      var tip = [svc.summary, svc.health !== 'off' && t ? TRANSPORT_TIP[t] : null].concat(svc.connections || b.connections || []).filter(Boolean).join('\n');
      var cls = svc.health === 'up' ? (t === 'tls' || t === 'local' ? 'badge on online' : 'badge warn online')
        : svc.health === 'degraded' ? 'badge warn' : svc.health === 'down' ? 'badge error' : 'badge';
      return h('span', { class: cls, title: tip }, svc.health !== 'off' && t ? transportIcon(t) : null, svc.summary);
    };
    var conn = h('span');
    var current = { configured: b.configured, enabled: b.enabled };
    function showConn(last) {
      var svc = last && last.services ? last.services.filter(function (x) { return x.id === b.id; })[0] : null;
      put(conn, connBadge(current, svc));
    }
    var accessBox = h('span', { class: 'badges' }, accessBadges(b));
    var badges = h('span', { class: 'badges' }, accessBox, conn);
    statusBar.watch(conn, showConn);
    var fields = b.fields.map(function (f) {
      var v = b.values[f.key];
      var el;
      if (f.type === 'boolean') {
        el = h('input', { type: 'checkbox', checked: v === undefined ? f.key === 'tlsVerify' : !!v });
        inputs[f.key] = el;
        return h('div', null, h('label', { class: 'inline' }, el, f.label), f.help ? h('div', { class: 'help' }, f.help) : null);
      }
      if (f.type === 'pem') el = h('textarea', { placeholder: '-----BEGIN CERTIFICATE-----' }, v || '');
      else if (f.type === 'secret') {
        el = h('input', { type: 'password', autocomplete: 'new-password', placeholder: b.secretsSet.indexOf(f.key) >= 0 ? '•••••••• (stored — leave empty to keep)' : '' });
      } else el = h('input', { type: f.type === 'url' ? 'url' : 'text', value: v === undefined ? '' : String(v), placeholder: f.placeholder || '' });
      inputs[f.key] = el;
      return h('div', null, h('label', null, f.label + (f.required ? ' *' : '')), el, f.help ? h('div', { class: 'help' }, f.help) : null);
    });
    var tools = toolsSection(b);
    function collect() {
      var values = {};
      b.fields.forEach(function (f) {
        var el = inputs[f.key];
        if (f.type === 'boolean') values[f.key] = el.checked;
        else values[f.key] = el.value.trim();
      });
      var body = { enabled: enabled.checked, values: values };
      var t = tools.collect();
      if (t.allowWrite !== undefined) body.allowWrite = t.allowWrite;
      if (t.allowlist !== undefined) body.allowlist = t.allowlist;
      return body;
    }
    var save = h('button', {
      class: 'primary',
      onclick: function () {
        var body = collect();
        busy(save, api('PUT', '/backends/' + b.id, body).then(function (s) {
          if (body.allowWrite !== undefined) { b.allowWrite = body.allowWrite; put(accessBox, accessBadges(b)); }
          current = { configured: s.configured, enabled: s.enabled };
          showConn(null);
          statusBar.refresh();
          put(out, s.configured
            ? notice('success', 'Saved.')
            : notice('error', 'Saved, but settings are incomplete: ' + s.issues.join('; ')));
        }), out);
      },
    }, 'Save');
    var test = h('button', {
      onclick: function () {
        put(out, h('p', { class: 'muted small' }, 'Testing the settings in the form (not saved)…'));
        busy(test, api('POST', '/backends/' + b.id + '/test', { values: collect().values }).then(function (r) {
          put(out, notice(r.ok ? 'success' : 'error', r.message));
        }), out);
      },
    }, 'Test connection');
    var guideBox = h('div', { class: 'hidden' });
    var guideBtn = b.guide ? h('button', {
      class: 'small',
      'aria-expanded': 'false',
      onclick: function () {
        var open = guideBox.classList.contains('hidden');
        if (open && !guideBox.firstChild) put(guideBox, backendGuide(b.guide, b, inputs));
        guideBox.classList.toggle('hidden', !open);
        guideBtn.setAttribute('aria-expanded', String(open));
        put(guideBtn, open ? 'Hide setup guide' : 'Setup guide');
      },
    }, 'Setup guide') : null;
    // Collapsed by default: the header keeps the name and state in view.
    var bodyId = 'backend-' + b.id;
    var body = h('div', { class: 'backend-body hidden', id: bodyId },
      h('p', { class: 'muted small' }, b.description),
      guideBtn ? h('div', { class: 'row' }, guideBtn) : null,
      guideBox,
      b.maturity === 'stub' && b.plannedTools.length
        ? h('p', { class: 'small muted' }, 'Planned tools: ', h('code', null, b.plannedTools.join(', ')))
        : null,
      h('label', { class: 'inline' }, enabled, 'Enabled'),
      fields,
      tools.node,
      h('div', { class: 'row' }, save, test),
      out);
    var toggle = h('button', {
      class: 'backend-toggle',
      'aria-expanded': 'false',
      'aria-controls': bodyId,
      onclick: function () {
        var open = body.classList.contains('hidden');
        body.classList.toggle('hidden', !open);
        toggle.setAttribute('aria-expanded', String(open));
      },
    }, b.title);
    return h('div', { class: 'panel backend-panel' },
      h('div', { class: 'row backend-head' },
        h('h2', { class: 'grow' }, toggle),
        b.maturity === 'stub' ? h('span', { class: 'badge' }, 'tools not implemented yet') : null,
        badges),
      b.issues.length && b.enabled ? notice('error', b.issues.join('; ')) : null,
      body);
  }

  /**
   * Which tools this installation offers (the allowlist, DESIGN §4) and the
   * installation-level switch for write tools (§6). Until edited, the
   * module's defaults apply: its read tools; write tools are never default.
   */
  function toolsSection(b) {
    if (b.maturity !== 'ready' || !b.tools.length) return { node: null, collect: function () { return {}; } };
    var allowWrite = h('input', { type: 'checkbox', checked: b.allowWrite });
    var writeDirty = false, listDirty = false, reset = false;
    function matches(p, name) { return p.slice(-1) === '*' ? name.indexOf(p.slice(0, -1)) === 0 : p === name; }
    function on(name, dflt) { return b.allowlist ? b.allowlist.some(function (p) { return matches(p, name); }) : dflt; }
    var entries = b.tools.map(function (t) { return { name: t.name, access: t.access, title: t.title, dflt: t.default, destructive: t.destructive }; });
    if (b.dynamicToolPattern) entries.push({ name: b.dynamicToolPattern, access: 'mixed', title: 'Tools forwarded from the backend\'s own MCP server (read-only ones by default; others count as write)', dflt: true });
    var boxes = entries.map(function (e) {
      var cb = h('input', { type: 'checkbox', checked: on(e.name, e.dflt) });
      cb.addEventListener('change', function () { listDirty = true; reset = false; });
      e.cb = cb;
      return h('label', { class: 'inline tool' + (e.access === 'write' ? ' write' : ''), title: e.title }, cb,
        h('code', null, e.name),
        e.access === 'write' ? h('span', { class: 'badge write' }, e.destructive ? 'write, destructive' : 'write') : null);
    });
    function syncWrite() {
      entries.forEach(function (e) { if (e.access === 'write') e.cb.disabled = !allowWrite.checked; });
    }
    allowWrite.addEventListener('change', function () { writeDirty = true; syncWrite(); });
    syncWrite();
    var resetBtn = h('button', {
      class: 'small',
      onclick: function () {
        entries.forEach(function (e) { e.cb.checked = e.dflt; });
        reset = true; listDirty = false;
      },
    }, 'Reset to defaults');
    var hasWrite = entries.some(function (e) { return e.access === 'write'; });
    return {
      node: h('details', { class: 'help tools-section' },
        h('summary', null, 'Tools' + (b.allowlist ? ' (customised)' : '') + (b.allowWrite ? ' · write allowed' : '')),
        hasWrite ? h('div', null,
          h('label', { class: 'inline' }, allowWrite, 'Allow write tools'),
          h('div', { class: 'help' }, 'Off by default. Write tools change ' + b.title + '. A user also needs a write grant (Users page) and a token with write on this backend; then tick the write tools below. Every call is in the audit log.')) : null,
        h('div', { class: 'tool-list' }, boxes),
        h('div', { class: 'row' }, resetBtn, h('span', { class: 'help' }, 'Unticked tools are not offered to any client.'))),
      collect: function () {
        var out = {};
        if (writeDirty) out.allowWrite = allowWrite.checked;
        if (reset) out.allowlist = null;
        else if (listDirty) out.allowlist = entries.filter(function (e) { return e.cb.checked; }).map(function (e) { return e.name; });
        return out;
      },
    };
  }

  function start() {
    return refreshMe().then(function (me) {
      if (me.user) aperture.open(); else aperture.close();
      route();
    }).catch(function (e) {
      mount(notice('error', 'Could not reach the server: ' + e.message));
    });
  }

  // Re-read /me on each navigation: TLS can switch to Let's Encrypt (or back)
  // after sign-in, and the pages decide from tlsServing whether to talk about
  // the built-in CA. If the request fails, route on what we have.
  window.addEventListener('hashchange', function () {
    if (!state.me) return;
    refreshMe().then(route, route);
  });
  if (!window.PublicKeyCredential) {
    mount(notice('error', 'This browser does not support passkeys (WebAuthn).'));
  } else {
    start();
  }
})();
