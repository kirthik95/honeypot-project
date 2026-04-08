/* =========================================================
   Auth + Honeypot Gate
   Logs every attempt, but only exact demo credentials route.
   ========================================================= */

(() => {
    'use strict';

    const API_URL = 'https://honeypot-backend-9c81.onrender.com/api/track';
    const ADMIN_CREDENTIALS = { email: 'admin@gmail.com', password: 'admin' };
    const USER_CREDENTIALS = { email: 'user@gmail.com', password: 'user' };
    const ROUTES = {
        admin: 'admin/dashboard.html',
        user: 'security-lab.html'
    };
    const SUSPICIOUS_PATTERN = /(?:'|--|;|\/\*|\*\/|<script|\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bALTER\b|\bOR\b\s+['"\d]|xp_cmdshell|\.\.\/|%27|%3C|alert\s*\()/i;

    const sessionId = crypto.randomUUID
        ? crypto.randomUUID()
        : 'session_' + Date.now() + '_' + Math.random().toString(36).slice(2, 11);

    const session = {
        start: Date.now(),
        mouse: 0,
        keys: 0,
        focus: 0,
        paste: 0
    };

    const form = document.getElementById('loginForm');
    const emailInput = document.getElementById('email');
    const passwordInput = document.getElementById('password');
    const submitBtn = document.getElementById('submitBtn');
    const feedbackEl = document.getElementById('authFeedback');

    if (!form || !emailInput || !passwordInput || !submitBtn) {
        console.error('Auth gate: required login elements not found');
        return;
    }

    document.addEventListener('mousemove', () => session.mouse++);
    document.addEventListener('keydown', () => session.keys++);

    document.querySelectorAll('input').forEach((input) => {
        input.addEventListener('focus', () => session.focus++);
        input.addEventListener('paste', () => session.paste++);
    });

    function resolveSiblingPage(filename) {
        if (window.ShadowNodeAuth && typeof window.ShadowNodeAuth.resolvePage === 'function') {
            return window.ShadowNodeAuth.resolvePage(filename);
        }

        try {
            return new URL(filename, window.location.href).toString();
        } catch (_) {
            return filename;
        }
    }

    function setSubmitState(isLoading, label) {
        submitBtn.classList.toggle('loading', isLoading);
        const btnText = submitBtn.querySelector('.btn-text');
        if (btnText) {
            btnText.textContent = label;
        }
    }

    function clearFieldState() {
        emailInput.classList.remove('input-error', 'input-success');
        passwordInput.classList.remove('input-error', 'input-success');
    }

    function setFieldState(type) {
        clearFieldState();
        if (!type) {
            return;
        }

        emailInput.classList.add(type === 'error' ? 'input-error' : 'input-success');
        passwordInput.classList.add(type === 'error' ? 'input-error' : 'input-success');
    }

    function setFeedback(type, message) {
        if (!feedbackEl) {
            if (typeof window.showToast === 'function') {
                window.showToast(message, type === 'error' ? 'error' : 'info');
            }
            return;
        }

        feedbackEl.textContent = message;
        feedbackEl.className = 'auth-feedback is-visible';
        feedbackEl.classList.add(type === 'error' ? 'is-error' : 'is-success');

        if (typeof window.showToast === 'function' && type === 'error') {
            window.showToast(message, 'error');
        }
    }

    function clearFeedback() {
        if (!feedbackEl) {
            return;
        }

        feedbackEl.textContent = '';
        feedbackEl.className = 'auth-feedback';
    }

    function persistSession(role, email) {
        if (window.ShadowNodeAuth && typeof window.ShadowNodeAuth.saveSession === 'function') {
            window.ShadowNodeAuth.saveSession(role, email);
            return;
        }

        sessionStorage.setItem('shadow_node_session', JSON.stringify({
            role,
            email,
            createdAt: Date.now()
        }));
    }

    function clearSession() {
        if (window.ShadowNodeAuth && typeof window.ShadowNodeAuth.clearSession === 'function') {
            window.ShadowNodeAuth.clearSession();
            return;
        }

        sessionStorage.removeItem('shadow_node_session');
    }

    function routeTo(path) {
        document.body.classList.add('route-pending');
        setTimeout(() => {
            window.location.href = resolveSiblingPage(path);
        }, 360);
    }

    function detectSuspiciousInput(email, password) {
        return SUSPICIOUS_PATTERN.test(email + '\n' + password);
    }

    function resolveClientAttackType(email, password) {
        const sample = email + '\n' + password;

        if (/<script|alert\s*\(|onerror\s*=|javascript:/i.test(sample)) {
            return 'xss';
        }

        if (/\.\.\/|%2e%2e%2f|%2e%2e\\|%252e%252e/i.test(sample)) {
            return 'path_traversal';
        }

        if (/\bunion\b|\bselect\b|\bdrop\b|\binsert\b|\bupdate\b|\bdelete\b|\balter\b|(?:'|")\s*or\s*(?:'|"|\d)|--/i.test(sample)) {
            return 'sql_injection';
        }

        if (/\bxp_cmdshell\b|;|\|\||&&|`/i.test(sample)) {
            return 'command_injection';
        }

        return 'credential_payload_probe';
    }

    function resolveClientOwasp(attackType) {
        switch (attackType) {
        case 'path_traversal':
            return 'A01:2021 Broken Access Control';
        case 'xss':
        case 'sql_injection':
        case 'command_injection':
        case 'credential_payload_probe':
            return 'A03:2021 Injection';
        default:
            return 'A03:2021 Injection';
        }
    }

    function wait(ms) {
        return new Promise((resolve) => {
            window.setTimeout(resolve, ms);
        });
    }

    async function flushLoggedAttempt(request, timeoutMs) {
        try {
            await Promise.race([request, wait(timeoutMs)]);
        } catch (_) {
            // Keep auth flow resilient even if telemetry fails.
        }
    }

    async function sendAttemptToBackend(payload) {
        const body = JSON.stringify(payload);

        try {
            const response = await fetch(API_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body,
                keepalive: true
            });

            if (!response.ok) {
                throw new Error('HTTP ' + response.status);
            }

            try {
                return await response.json();
            } catch (_) {
                return null;
            }
        } catch (error) {
            console.warn('Auth gate: could not log attempt to backend', error);
            return null;
        }
    }

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        e.stopImmediatePropagation();

        clearFeedback();
        clearFieldState();

        const rawEmail = emailInput.value || '';
        const rawPassword = passwordInput.value || '';
        const normalizedEmail = rawEmail.trim().toLowerCase();
        const normalizedPassword = rawPassword.trim();
        const elapsedSeconds = (Date.now() - session.start) / 1000;
        const isAdmin = normalizedEmail === ADMIN_CREDENTIALS.email && normalizedPassword === ADMIN_CREDENTIALS.password;
        const isUser = normalizedEmail === USER_CREDENTIALS.email && normalizedPassword === USER_CREDENTIALS.password;
        const isSuspicious = detectSuspiciousInput(rawEmail, rawPassword);
        const clientAttackType = isSuspicious ? resolveClientAttackType(rawEmail, rawPassword) : '';

        const payload = {
            session_id: sessionId,
            email: rawEmail,
            password: rawPassword,
            mouse_movements: session.mouse,
            keystrokes: session.keys,
            focus_events: session.focus,
            paste_events: session.paste,
            time_to_submit: elapsedSeconds,
            rapid_submission: elapsedSeconds < 3 ? 1 : 0,
            honeypot_filled: 0,
            honeypot_total_length: 0,
            email_length: rawEmail.length,
            password_length: rawPassword.length,
            cookies_enabled: navigator.cookieEnabled ? 1 : 0
        };

        if (isSuspicious) {
            payload.client_detected_attack = true;
            payload.client_attack_type = clientAttackType;
            payload.client_severity = 'MEDIUM';
            payload.client_signal = 'blocked_login_payload';
            payload.credential_target = normalizedEmail === ADMIN_CREDENTIALS.email
                ? 'admin'
                : normalizedEmail === USER_CREDENTIALS.email
                    ? 'user'
                    : 'unknown';

            if (window.ShadowNodeAuth && typeof window.ShadowNodeAuth.pushLocalAttackEvent === 'function') {
                window.ShadowNodeAuth.pushLocalAttackEvent({
                    session_id: sessionId,
                    severity: 'MEDIUM',
                    cvss_score: 0,
                    attack_type: clientAttackType,
                    cve: null,
                    owasp: resolveClientOwasp(clientAttackType)
                });
            }
        }

        const attemptRequest = sendAttemptToBackend(payload);
        setSubmitState(true, 'Authorizing...');

        if (isAdmin) {
            persistSession('admin', normalizedEmail);
            setFieldState('success');
            setFeedback('success', 'Admin access verified. Opening command dashboard...');
            routeTo(ROUTES.admin);
            return;
        }

        if (isUser) {
            persistSession('user', normalizedEmail);
            setFieldState('success');
            setFeedback('success', 'User workspace verified. Loading security testing studio...');
            routeTo(ROUTES.user);
            return;
        }

        clearSession();
        setFieldState('error');

        if (isSuspicious) {
            await flushLoggedAttempt(attemptRequest, 1200);
            setSubmitState(false, 'Sign In');
            setFeedback('error', 'Invalid credentials. Suspicious payload blocked and logged.');
            return;
        }

        setSubmitState(false, 'Sign In');
        setFeedback('error', 'Invalid credentials. Access is limited to authorized demo accounts.');
    }, true);
})();
