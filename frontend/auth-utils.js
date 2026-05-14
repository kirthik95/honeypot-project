(function attachShadowNodeAuth(global) {
    'use strict';

    const SESSION_KEY = 'shadow_node_session';
    const LOCAL_ATTACKS_KEY = 'shadow_node_local_attacks';

    const CVSS_BASE_SCORES = {
        sql_injection: {
            score: 7.1,
            vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
        },
        xss: {
            score: 6.1,
            vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
        },
        command_injection: {
            score: 9.8,
            vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        },
        path_traversal: {
            score: 6.5,
            vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
        },
        ssrf: {
            score: 8.2,
            vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
        },
        credential_payload_probe: {
            score: 5.0,
            vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
        },
        bot: {
            score: 0.0,
            vector: 'N/A',
        },
        legitimate: {
            score: 0.0,
            vector: 'N/A',
        },
        unknown: {
            score: 5.0,
            vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
        },
    };

    const ATTACK_TYPE_ALIASES = {
        sqli: 'sql_injection',
        sql: 'sql_injection',
        os_command: 'command_injection',
        cmd: 'command_injection',
        path: 'path_traversal',
        traversal: 'path_traversal',
        bot_attack: 'bot',
        normal: 'legitimate',
    };

    function asText(value) {
        return String(value == null ? '' : value).trim();
    }

    function normalizeAttackType(attackType) {
        const raw = asText(attackType).toLowerCase();
        return ATTACK_TYPE_ALIASES[raw] || raw || 'unknown';
    }

    function resolvePage(relativePath) {
        try {
            return new URL(relativePath, global.location.href).toString();
        } catch (_) {
            return relativePath;
        }
    }

    function severityFromCvss(score) {
        const value = Number(score) || 0;
        if (value >= 9.0) return 'CRITICAL';
        if (value >= 7.0) return 'HIGH';
        if (value >= 4.0) return 'MEDIUM';
        if (value > 0.0) return 'LOW';
        return 'INFO';
    }

    function buildAttackPayloadText(event) {
        if (!event || typeof event !== 'object') {
            return '';
        }

        return [
            event.payload,
            event.sample,
            event.raw_payload,
            event.threat_payload,
            event.query,
            event.input,
            event.comment,
            event.filename,
            event.path,
            event.url,
            event.endpoint,
            event.evidence && event.evidence.match,
            event.evidence && event.evidence.value,
        ]
            .map(asText)
            .filter(Boolean)
            .join(' ');
    }

    function normalizeCveReferences(value) {
        if (Array.isArray(value)) {
            return value
                .map(asText)
                .filter((item) => item && item.startsWith('CVE-'));
        }

        const single = asText(value);
        return single && single.startsWith('CVE-') ? [single] : [];
    }

    function calculateAttackCvss(attackType, payload, context) {
        const type = normalizeAttackType(attackType);
        const fallback = CVSS_BASE_SCORES[type] || CVSS_BASE_SCORES.unknown;
        const sample = asText(payload || buildAttackPayloadText(context && context.event ? context.event : context)).toLowerCase();

        if (type === 'legitimate' || type === 'bot') {
            return {
                cvss_score: fallback.score,
                cvss_vector: fallback.vector,
                severity: severityFromCvss(fallback.score),
            };
        }

        let score = fallback.score;
        let vector = fallback.vector;

        if (type === 'sql_injection') {
            if (/(xp_cmdshell|exec\s+master|sp_executesql|load_file|into\s+outfile|into\s+dumpfile|waitfor\s+delay|benchmark\s*\()/i.test(sample)) {
                score = 9.8;
                vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H';
            } else if (/\bunion\b.*\bselect\b|\bor\s+1\s*=\s*1\b/i.test(sample)) {
                score = 8.8;
                vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L';
            } else if (/\b(drop\s+table|delete\s+from|truncate)\b/i.test(sample)) {
                score = 8.1;
                vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:H';
            }
        } else if (type === 'xss') {
            if (/(document\.cookie|localStorage|sessionStorage)/i.test(sample)) {
                score = 7.4;
                vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N';
            } else if (/(<script|onerror\s*=|onload\s*=|javascript:)/i.test(sample)) {
                score = 6.1;
                vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N';
            } else if (/(innerHTML\s*=|document\.write|eval\()/i.test(sample)) {
                score = 6.5;
                vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N';
            }
        } else if (type === 'command_injection') {
            if (/(\/bin\/(bash|sh)|nc\s+-e|mkfifo|bash\s+-i|\/dev\/tcp)/i.test(sample)) {
                score = 9.8;
                vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H';
            } else if (/(curl.*http|wget.*http|ftp\s+|base64|cat\s+\/etc\/)/i.test(sample)) {
                score = 8.8;
                vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L';
            } else {
                score = 9.1;
                vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H';
            }
        } else if (type === 'path_traversal') {
            if (/(\.\.\/){5,}|(\.\.\\){5,}/i.test(sample)) {
                score = 7.5;
            } else if (/(\.\.\/){3,4}|(\.\.\\){3,4}/i.test(sample)) {
                score = 7.0;
            } else {
                score = 6.5;
            }
            vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N';
        } else if (type === 'ssrf') {
            if (/169\.254\.169\.254/i.test(sample)) {
                score = 9.1;
                vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N';
            } else if (/(localhost|127\.0\.0\.1|192\.168\.|10\.)/i.test(sample)) {
                score = 8.2;
                vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N';
            } else {
                score = 6.5;
                vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N';
            }
        } else if (type === 'credential_payload_probe') {
            if (/(<script|onerror\s*=|onload\s*=|javascript:)/i.test(sample)) {
                score = 6.1;
                vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N';
            } else if (/(union\b.*select\b|\bor\s+1\s*=\s*1\b|xp_cmdshell|load_file|into\s+outfile|into\s+dumpfile)/i.test(sample)) {
                score = 7.1;
                vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N';
            } else {
                score = fallback.score;
                vector = fallback.vector;
            }
        }

        const rounded = Math.round(score * 10) / 10;
        return {
            cvss_score: rounded,
            cvss_vector: vector,
            severity: severityFromCvss(rounded),
        };
    }

    function normalizeAttackEvent(event) {
        const base = Object.assign({}, event || {});
        const attackType = normalizeAttackType(base.attack_type || base.client_attack_type || base.attack || base.type);
        const existingScore = Number(base.cvss_score);
        const hasExistingScore = Number.isFinite(existingScore) && existingScore > 0;
        const calculated = calculateAttackCvss(attackType, buildAttackPayloadText(base), {
            event: base,
            field: base.field,
            stored: base.stored,
        });

        base.attack_type = attackType || base.attack_type || 'unknown';

        if (hasExistingScore) {
            base.cvss_score = existingScore;
            base.cvss_vector = asText(base.cvss_vector) || calculated.cvss_vector;
            if (!base.severity) {
                base.severity = severityFromCvss(existingScore);
            } else {
                base.severity = String(base.severity).toUpperCase();
            }
        } else {
            base.cvss_score = calculated.cvss_score;
            base.cvss_vector = calculated.cvss_vector;
            base.severity = calculated.severity;
        }

        if (!base.cve) {
            const cveReferences = normalizeCveReferences(base.cve_references || base.cves || base.cve);
            base.cve_references = cveReferences;
            base.cve = cveReferences.length ? cveReferences[0] : null;
        } else {
            base.cve_references = normalizeCveReferences(base.cve_references || base.cves || base.cve);
            if (!base.cve_references.length) {
                base.cve_references = [asText(base.cve)].filter(Boolean);
            }
        }

        return base;
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
            if (!Array.isArray(parsed)) {
                return [];
            }

            let changed = false;
            const normalized = parsed
                .filter((entry) => entry && typeof entry === 'object')
                .map((entry) => {
                    const next = normalizeAttackEvent(entry);
                    if (
                        String(next.cvss_score || 0) !== String(entry.cvss_score || 0) ||
                        String(next.cvss_vector || '') !== String(entry.cvss_vector || '') ||
                        String(next.severity || '') !== String(entry.severity || '') ||
                        String(next.attack_type || '') !== String(entry.attack_type || '')
                    ) {
                        changed = true;
                    }
                    return next;
                });

            if (changed) {
                saveLocalAttackEvents(normalized.slice(0, 50));
            }

            return normalized;
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

    function updateLocalAttackEvent(sessionId, patch) {
        const targetSessionId = asText(sessionId);
        if (!targetSessionId) {
            return null;
        }

        const current = getLocalAttackEvents();
        let updated = null;
        const next = current.map((entry) => {
            if (asText(entry.session_id) !== targetSessionId) {
                return entry;
            }

            const merged = normalizeAttackEvent(Object.assign({}, entry, patch || {}));
            updated = merged;
            return merged;
        });

        if (updated) {
            saveLocalAttackEvents(next.slice(0, 50));
        }

        return updated;
    }

    function pushLocalAttackEvent(event) {
        const nextEvent = normalizeAttackEvent(Object.assign({
            timestamp: new Date().toISOString(),
            severity: 'MEDIUM',
            cvss_score: 0,
            cvss_vector: 'N/A',
            cve: null,
            source: 'local-demo'
        }, event || {}));

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
        calculateAttackCvss,
        getLocalAttackEvents,
        pushLocalAttackEvent,
        updateLocalAttackEvent,
        clearLocalAttackEvents,
        normalizeAttackType,
        normalizeAttackEvent,
        normalizeCveReferences,
        severityFromCvss,
        requireRole,
        logout
    };
})(window);
