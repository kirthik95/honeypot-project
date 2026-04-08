(function attachShadowNodeAuth(global) {
    'use strict';

    const SESSION_KEY = 'shadow_node_session';
    const LOCAL_ATTACKS_KEY = 'shadow_node_local_attacks';

    function resolvePage(relativePath) {
        try {
            return new URL(relativePath, global.location.href).toString();
        } catch (_) {
            return relativePath;
        }
    }

    function saveSession(role, email) {
        const session = {
            role,
            email,
            createdAt: Date.now()
        };

        try {
            global.sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
        } catch (_) {
            return null;
        }

        return session;
    }

    function getSession() {
        try {
            const raw = global.sessionStorage.getItem(SESSION_KEY);
            return raw ? JSON.parse(raw) : null;
        } catch (_) {
            return null;
        }
    }

    function clearSession() {
        try {
            global.sessionStorage.removeItem(SESSION_KEY);
        } catch (_) {
            // Ignore storage failures in static demo mode.
        }
    }

    function getLocalAttackEvents() {
        try {
            const raw = global.localStorage.getItem(LOCAL_ATTACKS_KEY);
            const parsed = raw ? JSON.parse(raw) : [];
            return Array.isArray(parsed) ? parsed.filter((entry) => entry && typeof entry === 'object') : [];
        } catch (_) {
            return [];
        }
    }

    function saveLocalAttackEvents(events) {
        try {
            global.localStorage.setItem(LOCAL_ATTACKS_KEY, JSON.stringify(events));
            return true;
        } catch (_) {
            return false;
        }
    }

    function pushLocalAttackEvent(event) {
        const nextEvent = Object.assign({
            timestamp: new Date().toISOString(),
            severity: 'MEDIUM',
            cvss_score: 0,
            cve: null,
            source: 'local-demo'
        }, event || {});

        const current = getLocalAttackEvents();
        current.unshift(nextEvent);
        saveLocalAttackEvents(current.slice(0, 50));
        return nextEvent;
    }

    function clearLocalAttackEvents() {
        try {
            global.localStorage.removeItem(LOCAL_ATTACKS_KEY);
        } catch (_) {
            // Ignore storage failures in static demo mode.
        }
    }

    function requireRole(roles, redirectPath) {
        const allowedRoles = Array.isArray(roles) ? roles : [roles];
        const session = getSession();

        if (!session || !allowedRoles.includes(session.role)) {
            clearSession();
            global.location.replace(resolvePage(redirectPath || '../index.html'));
            return null;
        }

        return session;
    }

    function logout(redirectPath) {
        clearSession();
        global.location.replace(resolvePage(redirectPath || '../index.html'));
    }

    global.ShadowNodeAuth = {
        SESSION_KEY,
        LOCAL_ATTACKS_KEY,
        resolvePage,
        saveSession,
        getSession,
        clearSession,
        getLocalAttackEvents,
        pushLocalAttackEvent,
        clearLocalAttackEvents,
        requireRole,
        logout
    };
})(window);
