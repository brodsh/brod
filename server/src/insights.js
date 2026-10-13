// Brod insights: what the browser alone can tell about a visit, sent to the app's own /_brod/insights.
// No cookies and no storage: the platform counts the visitor the same way it counts page views.
// Reports Core Web Vitals (LCP, INP, CLS, FCP, TTFB), time on page, screen class, JavaScript errors, clicks to other
// sites, navigations inside single-page apps, and custom events: window.brod.track('signup', { value: 1, label: 'pro' }).
(function () {
  'use strict';
  if (window.__brodInsights || navigator.webdriver) return;
  window.__brodInsights = true;
  var q = [], sent = 0, path = location.pathname;
  function push(k, n, v, l) {
    if (sent > 300) return;
    q.push({ k: k, n: String(n == null ? '' : n).slice(0, 100), v: typeof v === 'number' && isFinite(v) ? v : null,
      l: l == null ? '' : String(l).slice(0, 200), p: path });
    if (q.length >= 20) send();
  }
  function send() {
    if (!q.length) return;
    sent += q.length;
    var body = JSON.stringify(q.splice(0, 30));
    try {
      if (navigator.sendBeacon && navigator.sendBeacon('/_brod/insights', new Blob([body], { type: 'text/plain' }))) return;
    } catch (e) {}
    try { fetch('/_brod/insights', { method: 'POST', body: body, keepalive: true, credentials: 'same-origin' }).catch(function () {}); } catch (e) {}
  }

  // Screen class and size.
  var w = screen.width || innerWidth;
  push('screen', w < 768 ? 'Mobile' : w < 1100 ? 'Tablet' : 'Desktop', w, (screen.width || 0) + '×' + (screen.height || 0));

  // Core Web Vitals, reported once when the page is first hidden.
  var vitals = {}, reported = false;
  function observe(type, fn, opts) {
    try {
      var o = new PerformanceObserver(function (l) { l.getEntries().forEach(fn); });
      o.observe(Object.assign({ type: type, buffered: true }, opts || {}));
    } catch (e) {}
  }
  observe('largest-contentful-paint', function (e) { vitals.LCP = e.startTime; });
  observe('paint', function (e) { if (e.name === 'first-contentful-paint') vitals.FCP = e.startTime; });
  var cls = 0, win = 0, winStart = 0, winLast = 0;
  observe('layout-shift', function (e) {
    if (e.hadRecentInput) return;
    if (win && e.startTime - winLast < 1000 && e.startTime - winStart < 5000) win += e.value;
    else { win = e.value; winStart = e.startTime; }
    winLast = e.startTime;
    if (win > cls) { cls = win; vitals.CLS = cls; }
  });
  observe('event', function (e) { if (e.interactionId && (!vitals.INP || e.duration > vitals.INP)) vitals.INP = e.duration; }, { durationThreshold: 40 });
  observe('first-input', function (e) { var d = e.processingStart - e.startTime; if (!vitals.INP || d > vitals.INP) vitals.INP = d; });
  try {
    var nav = performance.getEntriesByType('navigation')[0];
    if (nav && nav.responseStart > 0) vitals.TTFB = nav.responseStart;
  } catch (e) {}
  function reportVitals() {
    if (reported) return;
    reported = true;
    for (var k in vitals) push('vital', k, k === 'CLS' ? Math.round(vitals[k] * 1000) / 1000 : Math.round(vitals[k]));
  }

  // Time on page: only while it is visible.
  var shown = document.visibilityState === 'visible' ? Date.now() : 0, spent = 0;
  function engaged() {
    if (shown) { spent += Date.now() - shown; shown = 0; }
    if (spent >= 1000) push('engage', 'time', Math.round(spent / 100) / 10);
    spent = 0;
  }
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'hidden') { engaged(); reportVitals(); send(); }
    else shown = Date.now();
  });
  addEventListener('pagehide', function () { engaged(); reportVitals(); send(); });

  // Navigations inside a single-page app count as page views.
  function moved() {
    if (location.pathname === path) return;
    engaged();
    if (document.visibilityState === 'visible') shown = Date.now();
    path = location.pathname;
    push('nav', '', null, '');
    send();
  }
  ['pushState', 'replaceState'].forEach(function (m) {
    var orig = history[m];
    if (typeof orig !== 'function') return;
    history[m] = function () { var r = orig.apply(this, arguments); setTimeout(moved, 0); return r; };
  });
  addEventListener('popstate', moved);

  // JavaScript errors and unhandled promise rejections.
  var errs = 0;
  addEventListener('error', function (e) {
    if (!e || !e.message || errs++ > 20) return;
    push('error', e.message, null, (e.filename ? e.filename.replace(location.origin, '') : '') + ':' + (e.lineno || 0));
  });
  addEventListener('unhandledrejection', function (e) {
    if (errs++ > 20) return;
    var r = e && e.reason;
    push('error', (r && r.message) || String(r), null, 'unhandled promise');
  });

  // Clicks to other sites.
  document.addEventListener('click', function (e) {
    var a = e.target && e.target.closest && e.target.closest('a[href]');
    if (a && a.host && a.host !== location.host && /^https?:$/.test(a.protocol)) push('outbound', a.host.replace(/^www\./, ''));
  }, true);

  // Custom events.
  window.brod = window.brod || {};
  window.brod.track = function (name, opts) {
    opts = opts || {};
    push('event', name, typeof opts.value === 'number' ? opts.value : null, opts.label);
  };

  setInterval(send, 15000);
})();
