/**
 * honeypot-advanced.js
 * Shadow Node — Advanced Behavioral Fingerprinting Engine
 * Collects mouse, keystroke, paste, focus, canvas, and automation signals.
 */

(function () {
  'use strict';

  const API_URL = 'https://honeypot-backend-9c81.onrender.com/api/track';
  const ADMIN_CREDENTIALS = { email: 'admin@gmail.com', password: 'admin' };
  const USER_CREDENTIALS = { email: 'user@gmail.com', password: 'user' };
  const ROUTES = {
    admin: 'admin/dashboard.html',
    user: 'security-lab.html'
  };

  /* ── Session state ─────────────────────────────────────────────────── */
  const session = {
    id: (typeof crypto !== 'undefined' && crypto.randomUUID)
          ? crypto.randomUUID()
          : Math.random().toString(36).slice(2) + Date.now().toString(36),
    startTime: Date.now(),

    // Basic
    mouse_movements:  0,
    keystrokes:       0,
    focus_events:     0,
    paste_events:     0,

    // Advanced behavioral
    inter_keystroke_timings: [],
    last_keydown_time:       null,
    mouse_positions:         [],
    mouse_velocity_samples:  [],
    field_focus_times:       {},
    field_focus_start:       {},

    // Paste analysis
    total_chars_typed:  0,
    total_chars_pasted: 0,
    paste_ratio:        0,

    // Honeypot
    honeypot_filled:       0,
    honeypot_total_length: 0,

    // Browser automation
    browser_automation: false,

    // Canvas fingerprint
    canvas_fingerprint: '',

    // Tab / window
    tab_switches:     0,
    total_focus_time: 0,
    _focus_start:     Date.now(),

    // Form interaction
    field_interaction_order: [],
    double_clicks:           0,
    right_clicks:            0,

    cookies_enabled: navigator.cookieEnabled,
  };

  /* ── Mouse movement tracking ───────────────────────────────────────── */
  function trackMouseMovements() {
    let lastSampleTime = 0;

    document.addEventListener('mousemove', function (e) {
      session.mouse_movements++;

      const now = Date.now();
      if (now - lastSampleTime >= 100) {
        const prev = session.mouse_positions[session.mouse_positions.length - 1];
        if (prev) {
          const dt = (now - prev.t) / 1000; // seconds
          if (dt > 0) {
            const dx = e.clientX - prev.x;
            const dy = e.clientY - prev.y;
            const dist = Math.sqrt(dx * dx + dy * dy);
            const velocity = dist / dt; // px/s → store as px/ms for spec compliance
            session.mouse_velocity_samples.push(velocity / 1000);
          }
        }
        session.mouse_positions.push({ x: e.clientX, y: e.clientY, t: now });
        lastSampleTime = now;
      }
    });
  }

  /* ── Keystroke tracking ────────────────────────────────────────────── */
  function trackKeystrokes(field) {
    field.addEventListener('keydown', function () {
      const now = Date.now();
      session.keystrokes++;

      if (session.last_keydown_time !== null) {
        const gap = now - session.last_keydown_time;
        session.inter_keystroke_timings.push(gap);
      }
      session.last_keydown_time = now;
    });

    // Count typed chars (not pasted) via input event delta
    let prevLength = 0;
    field.addEventListener('input', function (e) {
      const curr = field.value.length;
      const delta = curr - prevLength;
      if (delta > 0 && !field._justPasted) {
        session.total_chars_typed += delta;
      }
      field._justPasted = false;
      prevLength = curr;
    });
  }

  /* ── Paste tracking ────────────────────────────────────────────────── */
  function trackPaste(field) {
    field.addEventListener('paste', function (e) {
      session.paste_events++;
      field._justPasted = true;
      try {
        const text = (e.clipboardData || window.clipboardData).getData('text');
        const len  = text ? text.length : 0;
        session.total_chars_pasted += len;
      } catch (_) {
        session.total_chars_pasted += 1; // unable to read — still flag
      }
    });
  }

  /* ── Focus / time-in-field tracking ───────────────────────────────── */
  function trackFocus(field) {
    const name = field.name || field.id || 'unknown';

    field.addEventListener('focusin', function () {
      session.focus_events++;
      session.field_focus_start[name] = Date.now();

      // Track interaction order (unique entries only)
      if (!session.field_interaction_order.includes(name)) {
        session.field_interaction_order.push(name);
      }
    });

    field.addEventListener('focusout', function () {
      if (session.field_focus_start[name]) {
        const elapsed = Date.now() - session.field_focus_start[name];
        session.field_focus_times[name] = (session.field_focus_times[name] || 0) + elapsed;
        delete session.field_focus_start[name];
      }
    });
  }

  /* ── Honeypot field watcher ────────────────────────────────────────── */
  function trackHoneypot() {
    const hp = document.getElementById('honeypot-field');
    if (!hp) return;

    function checkHoneypot() {
      if (hp.value && hp.value.length > 0) {
        session.honeypot_filled       = 1;
        session.honeypot_total_length = hp.value.length;
      }
    }

    hp.addEventListener('input',  checkHoneypot);
    hp.addEventListener('change', checkHoneypot);
    hp.addEventListener('paste',  function (e) {
      session.honeypot_filled = 1;
      try {
        const text = (e.clipboardData || window.clipboardData).getData('text');
        session.honeypot_total_length = text ? text.length : 1;
      } catch (_) {
        session.honeypot_total_length = 1;
      }
    });
  }

  /* ── Browser automation detection ─────────────────────────────────── */
  function detectBrowserAutomation() {
    const checks = [
      navigator.webdriver === true,
      typeof window.callPhantom  !== 'undefined',
      typeof window._phantom     !== 'undefined',
      typeof window.__nightmare  !== 'undefined',
      typeof window.domAutomation !== 'undefined',
      typeof window.domAutomationController !== 'undefined',
      typeof window.__selenium_unwrapped !== 'undefined',
      typeof window.__webdriver_script_fn !== 'undefined',
      navigator.plugins.length === 0,
      window.outerHeight === 0,
      (function () {
        try {
          // Headless Chrome has no notification permission dialog
          return /HeadlessChrome/.test(navigator.userAgent);
        } catch (_) { return false; }
      })(),
    ];
    return checks.some(Boolean);
  }

  /* ── Canvas fingerprint ────────────────────────────────────────────── */
  function generateCanvasFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      canvas.width  = 240;
      canvas.height = 60;
      const ctx = canvas.getContext('2d');

      // Background
      ctx.fillStyle = '#0a0a0f';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      // Text
      ctx.font         = '14px "Courier New", monospace';
      ctx.fillStyle    = '#00ff88';
      ctx.textBaseline = 'top';
      ctx.fillText('ShadowNode\u2603\u00e9\u0105', 2, 2);

      // Rectangles
      ctx.fillStyle = 'rgba(0,255,204,0.5)';
      ctx.fillRect(100, 5, 80, 20);

      // Gradient
      const grad = ctx.createLinearGradient(0, 0, 240, 0);
      grad.addColorStop(0, '#00ff88');
      grad.addColorStop(1, '#ff4444');
      ctx.fillStyle = grad;
      ctx.fillRect(0, 40, 240, 12);

      // Arc
      ctx.beginPath();
      ctx.arc(200, 30, 15, 0, Math.PI * 2, true);
      ctx.fillStyle = 'rgba(255,136,0,0.6)';
      ctx.fill();

      const dataURL = canvas.toDataURL('image/png');
      return dataURL.slice(-50);
    } catch (err) {
      // Canvas blocked (e.g. privacy browser) — fall back to UA hash
      let hash = 0;
      const s   = navigator.userAgent + navigator.language + screen.colorDepth;
      for (let i = 0; i < s.length; i++) {
        hash = ((hash << 5) - hash) + s.charCodeAt(i);
        hash |= 0;
      }
      return 'ua:' + Math.abs(hash).toString(36);
    }
  }

  /* ── Visibility / tab-switch tracking ─────────────────────────────── */
  function trackVisibilityChanges() {
    document.addEventListener('visibilitychange', function () {
      if (document.hidden) {
        session.tab_switches++;
      }
    });

    // Track total focus time on the page
    window.addEventListener('blur',  function () {
      session.total_focus_time += Date.now() - session._focus_start;
    });
    window.addEventListener('focus', function () {
      session._focus_start = Date.now();
    });
  }

  /* ── Double / right-click tracking ────────────────────────────────── */
  function trackClickBehavior() {
    document.addEventListener('dblclick',    function () { session.double_clicks++; });
    document.addEventListener('contextmenu', function () { session.right_clicks++;  });
  }

  /* ── Computed helpers ──────────────────────────────────────────────── */
  function computeMouseVelocityAvg() {
    const s = session.mouse_velocity_samples;
    if (!s.length) return 0;
    return s.reduce(function (a, b) { return a + b; }, 0) / s.length;
  }

  function computePasteRatio() {
    const total = session.total_chars_typed + session.total_chars_pasted;
    if (total === 0) return 0;
    return session.total_chars_pasted / total;
  }

  /* ── Result display ────────────────────────────────────────────────── */
  function displayResult(result) {
    const panel = document.getElementById('result-panel');
    if (!panel) return;

    panel.style.display = 'block';
    panel.className      = '';

    if (result && result.error) {
      panel.classList.add('err');
      panel.innerHTML = `
        <div class="result-label">// CONNECTION ERROR</div>
        <div class="result-value">${escHtml(String(result.error))}</div>`;
      return;
    }

    if (result && result.is_attack) {
      panel.classList.add('attack');
      panel.innerHTML = `
        <div class="result-label">// THREAT DETECTED</div>
        <div class="result-value">ATTACK: ${escHtml(result.attack_type || 'UNKNOWN')}</div>
        <div style="margin-top:6px;font-size:11px;opacity:0.8;">
          Severity: ${escHtml(result.severity || '—')} &nbsp;|&nbsp;
          CVSS: ${result.cvss_score != null ? Number(result.cvss_score).toFixed(1) : '—'}
        </div>
        <div style="margin-top:4px;font-size:10px;opacity:0.6;">Your session has been logged and reported.</div>`;
      return;
    }

    if (result && result.is_bot) {
      panel.classList.add('bot');
      panel.innerHTML = `
        <div class="result-label">// AUTOMATED AGENT DETECTED</div>
        <div class="result-value">Bot signature identified. Access denied.</div>`;
      return;
    }

    // Default: fake "access granted"
    panel.classList.add('ok');
    panel.innerHTML = `
      <div class="result-label">// AUTHENTICATION RESULT</div>
      <div class="result-value">▶ ACCESS GRANTED — Welcome, Operator.</div>
      <div style="margin-top:6px;font-size:10px;opacity:0.6;">Initializing secure session…</div>`;
  }

  function escHtml(str) {
    return String(str)
      .replace(/&/g,  '&amp;')
      .replace(/</g,  '&lt;')
      .replace(/>/g,  '&gt;')
      .replace(/"/g,  '&quot;')
      .replace(/'/g,  '&#39;');
  }

  function persistSession(role, email) {
    try {
      if (window.ShadowNodeAuth && typeof window.ShadowNodeAuth.saveSession === 'function') {
        window.ShadowNodeAuth.saveSession(role, email);
        return;
      }
    } catch (err) {
      // Fall back to direct session storage below.
    }

    sessionStorage.setItem('shadow_node_session', JSON.stringify({
      role: role,
      email: email,
      createdAt: Date.now()
    }));
  }

  function clearSession() {
    try {
      if (window.ShadowNodeAuth && typeof window.ShadowNodeAuth.clearSession === 'function') {
        window.ShadowNodeAuth.clearSession();
        return;
      }
    } catch (_) {
      // Fall back to direct session storage below.
    }

    sessionStorage.removeItem('shadow_node_session');
  }

  function routeTo(path) {
    window.setTimeout(function () {
      window.location.href = path;
    }, 700);
  }

  /* ── Form submit handler ───────────────────────────────────────────── */
  async function submitAndAnalyze(e) {
    e.preventDefault();

    const submitBtn  = document.getElementById('submit-btn');
    const emailField = document.getElementById('email');
    const pwField    = document.getElementById('password');
    const rawEmail = emailField ? emailField.value : '';
    const rawPassword = pwField ? pwField.value : '';
    const normalizedEmail = rawEmail.trim().toLowerCase();
    const normalizedPassword = rawPassword.trim();
    const isAdmin = normalizedEmail === ADMIN_CREDENTIALS.email && normalizedPassword === ADMIN_CREDENTIALS.password;
    const isUser = normalizedEmail === USER_CREDENTIALS.email && normalizedPassword === USER_CREDENTIALS.password;

    if (submitBtn) submitBtn.classList.add('loading');

    // Flush any open field-focus timers
    Object.keys(session.field_focus_start).forEach(function (name) {
      session.field_focus_times[name] =
        (session.field_focus_times[name] || 0) + (Date.now() - session.field_focus_start[name]);
    });

    const timeToSubmit = (Date.now() - session.startTime) / 1000;
    session.paste_ratio = computePasteRatio();
    const mouseVelocityAvg = computeMouseVelocityAvg();

    const payload = {
      session_id:    session.id,
      email:         rawEmail,
      password:      rawPassword,

      // Basic
      mouse_movements: session.mouse_movements,
      keystrokes:      session.keystrokes,
      focus_events:    session.focus_events,
      paste_events:    session.paste_events,
      time_to_submit:  timeToSubmit,
      rapid_submission: timeToSubmit < 3 ? 1 : 0,

      // Honeypot
      honeypot_filled:       session.honeypot_filled,
      honeypot_total_length: session.honeypot_total_length,

      // Field lengths
      email_length:    emailField ? emailField.value.length : 0,
      password_length: pwField    ? pwField.value.length    : 0,

      // Browser
      cookies_enabled: session.cookies_enabled ? 1 : 0,

      // Advanced
      inter_keystroke_timings: session.inter_keystroke_timings.slice(-20),
      mouse_velocity_avg:      mouseVelocityAvg,
      paste_ratio:             session.paste_ratio,
      browser_automation:      session.browser_automation,
      canvas_fingerprint:      session.canvas_fingerprint,
      field_timings:           session.field_focus_times,
      tab_switches:            session.tab_switches,
      field_interaction_order: session.field_interaction_order,
      double_clicks:           session.double_clicks,
      right_clicks:            session.right_clicks,
      total_focus_time:        session.total_focus_time + (Date.now() - session._focus_start),
    };

    let result = null;

    try {
      const res = await fetch(API_URL, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(payload),
      });
      result = await res.json();
    } catch (err) {
      displayResult({ error: 'Connection failed — ' + err.message });
    } finally {
      if (submitBtn) submitBtn.classList.remove('loading');
    }

    if (result && (result.is_attack || result.is_bot || result.error)) {
      clearSession();
      displayResult(result);
      return;
    }

    if (isAdmin) {
      persistSession('admin', normalizedEmail);
      displayResult({});
      routeTo(ROUTES.admin);
      return;
    }

    if (isUser) {
      persistSession('user', normalizedEmail);
      const panel = document.getElementById('result-panel');
      if (panel) {
        panel.style.display = 'block';
        panel.className = 'ok';
        panel.innerHTML = `
      <div class="result-label">// AUTHENTICATION RESULT</div>
      <div class="result-value">â–¶ ACCESS GRANTED â€” Loading user workspace.</div>
      <div style="margin-top:6px;font-size:10px;opacity:0.6;">Routing to security testing studioâ€¦</div>`;
      }
      routeTo(ROUTES.user);
      return;
    }

    clearSession();
    const panel = document.getElementById('result-panel');
    if (panel) {
      panel.style.display = 'block';
      panel.className = 'err';
      panel.innerHTML = `
      <div class="result-label">// ACCESS DENIED</div>
      <div class="result-value">Invalid credentials. Access is limited to authorized demo accounts.</div>`;
    }
  }

  /* ── Initialisation ────────────────────────────────────────────────── */
  document.addEventListener('DOMContentLoaded', function () {
    const form       = document.getElementById('login-form');
    const emailField = document.getElementById('email');
    const pwField    = document.getElementById('password');

    if (!form) return;

    // One-time setup
    session.browser_automation = detectBrowserAutomation();
    session.canvas_fingerprint  = generateCanvasFingerprint();

    // Global listeners
    trackMouseMovements();
    trackVisibilityChanges();
    trackClickBehavior();
    trackHoneypot();

    // Per-field listeners
    [emailField, pwField].forEach(function (field) {
      if (!field) return;
      trackKeystrokes(field);
      trackPaste(field);
      trackFocus(field);
    });

    // Form submit
    form.addEventListener('submit', submitAndAnalyze);
  });

})();
