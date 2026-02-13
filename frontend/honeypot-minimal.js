/* =========================================================
   AI-POWERED HONEYPOT TRACKER
   Sends Real Data to AI-Enhanced Backend
   ========================================================= */

(() => {
    'use strict';

    // 🎯 UPDATE THIS WITH YOUR RENDER URL
    const API_URL = 'https://honeypot-backend-9c81.onrender.com/api/track';

    function resolveSiblingPage(filename) {
        try {
            return new URL(filename, window.location.href).toString();
        } catch (_) {
            return filename;
        }
    }
    
    // Generate unique session ID
    const sessionId = crypto.randomUUID ? crypto.randomUUID() : 
                      'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);

    // Session tracking
    const session = {
        start: Date.now(),
        mouse: 0,
        keys: 0,
        focus: 0,
        paste: 0
    };

    // Track user behavior
    document.addEventListener('mousemove', () => session.mouse++);
    document.addEventListener('keydown', () => session.keys++);

    document.querySelectorAll('input').forEach(input => {
        input.addEventListener('focus', () => session.focus++);
        input.addEventListener('paste', () => session.paste++);
    });

    // Get the form
    const form = document.getElementById('loginForm');
    if (!form) {
        console.error('Honeypot: Login form not found');
        return;
    }

    // Intercept form submission BEFORE script.js handles it
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        e.stopImmediatePropagation(); // Prevent script.js from handling

        console.log('🔍 Honeypot: Capturing form data...');

        // Get form values
        const email = document.getElementById('email')?.value || '';
        const password = document.getElementById('password')?.value || '';
        const time = (Date.now() - session.start) / 1000;

        // Build payload
        const payload = {
            session_id: sessionId,
            
            // 🔴 CRITICAL: Send actual credentials
            email: email,
            password: password,
            
            // Behavioral features for XGBoost
            mouse_movements: session.mouse,
            keystrokes: session.keys,
            focus_events: session.focus,
            paste_events: session.paste,
            time_to_submit: time,
            rapid_submission: time < 3 ? 1 : 0,
            honeypot_filled: 0,
            honeypot_total_length: 0,
            email_length: email.length,
            password_length: password.length,
            cookies_enabled: navigator.cookieEnabled ? 1 : 0
        };

        console.log('📤 Honeypot: Sending to AI backend...', {
            email: email.substring(0, 10) + '...',
            password_length: password.length,
            session_id: sessionId
        });

        // Show loading state
        const submitBtn = document.getElementById('submitBtn');
        if (submitBtn) {
            submitBtn.classList.add('loading');
            const btnText = submitBtn.querySelector('.btn-text');
            if (btnText) btnText.textContent = 'Analyzing...';
        }

        try {
            const response = await fetch(API_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });

            const result = await response.json();
            console.log('✅ Honeypot: AI Backend Response:', result);

            if (submitBtn) {
                submitBtn.classList.remove('loading');
                const btnText = submitBtn.querySelector('.btn-text');
                if (btnText) btnText.textContent = 'Sign In';
            }

            if (result.success && result.is_attack) {
                // 🚨 ATTACK DETECTED BY AI - Show detailed info
                console.warn('🚨 AI DETECTED ATTACK!');
                console.log('═══════════════════════════════════════');
                console.log('Attack Type:', result.attack_type);
                console.log('Severity:', result.severity);
                console.log('CVSS Score:', result.cvss_score);
                console.log('CVSS Vector:', result.cvss_vector);
                console.log('CVE References:', result.cve_references);
                console.log('Remediation:', result.remediation);
                console.log('Is Bot:', result.is_bot);
                console.log('═══════════════════════════════════════');
                
                // Store attack details for downstream dashboard context
                sessionStorage.setItem('attack_details', JSON.stringify({
                    attack_type: result.attack_type,
                    severity: result.severity,
                    cvss_score: result.cvss_score,
                    cvss_vector: result.cvss_vector,
                    cve_references: result.cve_references,
                    analyzed_by: result.analyzed_by || 'AI'
                }));
                
                // Redirect directly to the interactive admin dashboard.
                window.location.href = resolveSiblingPage('admin/dashboard.html');
            } else {
                // Clean input - show demo message
                console.log('✅ Clean input detected');
                console.log('Analysis:', {
                    is_bot: result.is_bot,
                    risk_level: result.risk_level
                });
                
                alert('✅ Login successful (demo mode)\n\nNo malicious patterns detected.');
            }

        } catch (error) {
            console.error('❌ Honeypot: Error communicating with AI backend:', error);
            
            if (submitBtn) {
                submitBtn.classList.remove('loading');
                const btnText = submitBtn.querySelector('.btn-text');
                if (btnText) btnText.textContent = 'Sign In';
            }
            
            alert('Network error. Please try again.\n\nIf this persists, the backend may be starting up (Render free tier cold start).');
        }
    }, true); // Use capture phase to run before script.js

    console.log('✅ AI-Powered Honeypot initialized successfully');
    console.log('🎯 Backend URL:', API_URL);
    console.log('🤖 AI Analysis: Enabled');
    console.log('🔒 Session ID:', sessionId);
})();
