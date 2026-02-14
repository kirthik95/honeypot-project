(function () {
    'use strict';

    var palettes = {
        zeus: { a: '#d7e9ff', b: '#2f6dff', c: '#79b2ff', g: 'rgba(79,142,255,0.56)', scan: 'rgba(211,232,255,0.74)', ddos: 'rgba(72,132,255,0.86)', atk: 'rgba(121,178,255,0.84)' },
        helios: { a: '#ffe5bd', b: '#ff8737', c: '#ff452d', g: 'rgba(255,118,42,0.50)', scan: 'rgba(255,229,189,0.70)', ddos: 'rgba(255,135,55,0.80)', atk: 'rgba(255,69,45,0.82)' },
        hades: { a: '#f8e8d2', b: '#ff8f34', c: '#cf39ff', g: 'rgba(255,108,46,0.56)', scan: 'rgba(248,232,210,0.74)', ddos: 'rgba(255,143,52,0.86)', atk: 'rgba(207,57,255,0.84)' }
    };

    var countries = [
        { n: 'USA', la: 38, lo: -97 }, { n: 'Canada', la: 56, lo: -106 }, { n: 'Brazil', la: -14, lo: -52 },
        { n: 'UK', la: 55, lo: -3 }, { n: 'Germany', la: 51, lo: 10 }, { n: 'France', la: 46, lo: 2 },
        { n: 'Nigeria', la: 9, lo: 8 }, { n: 'South Africa', la: -30, lo: 22 }, { n: 'Egypt', la: 26, lo: 30 },
        { n: 'India', la: 20, lo: 78 }, { n: 'UAE', la: 23, lo: 53 }, { n: 'Russia', la: 61, lo: 105 },
        { n: 'China', la: 35, lo: 104 }, { n: 'Japan', la: 36, lo: 138 }, { n: 'Korea', la: 35, lo: 127 },
        { n: 'Singapore', la: 1, lo: 103 }, { n: 'Indonesia', la: -2, lo: 118 }, { n: 'Australia', la: -25, lo: 133 }
    ];
    var cores = [{ n: 'Core US', la: 39, lo: -77 }, { n: 'Core EU', la: 50, lo: 8 }, { n: 'Core APAC', la: 1.3, lo: 103.8 }];

    var state = { mode: 'hades', reduced: false, charts: null, globe: null, pluginOn: false };

    function clamp(n, min, max) { return Math.min(max, Math.max(min, n)); }
    function rad(d) { return d * Math.PI / 180; }
    function pick(mode) { return palettes[mode] || palettes.hades; }
    function hash(s) { s = String(s || ''); var h = 2166136261; for (var i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h += (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24); } return Math.abs(h >>> 0); }

    function ensureGaugeLabel(canvas) {
        if (!canvas) return null;
        var box = canvas.closest('.cvss-gauge-container');
        if (!box) return null;
        var o = box.querySelector('.cvss-gauge-overlay');
        if (!o) {
            o = document.createElement('div');
            o.className = 'cvss-gauge-overlay';
            o.innerHTML = '<div style="display:flex;flex-direction:column;align-items:center;"><div class="cvss-gauge-value">0.0</div><div class="cvss-gauge-sub">AVG CVSS</div></div>';
            box.appendChild(o);
        }
        return o.querySelector('.cvss-gauge-value');
    }

    function createLiquidCvssGauge(canvas, options) {
        var reduced = !!(options && options.prefersReducedMotion);
        var ctx = canvas && canvas.getContext ? canvas.getContext('2d') : null;
        if (!ctx) return { setValue: function () {} };
        var label = ensureGaugeLabel(canvas);
        var target = 0, cur = 0, phase = Math.random() * Math.PI * 2, last = performance.now(), bubbles = [];

        function resize() {
            var dpr = Math.max(1, Math.min(2.2, window.devicePixelRatio || 1));
            var r = canvas.getBoundingClientRect(), w = Math.max(1, Math.floor(r.width * dpr)), h = Math.max(1, Math.floor(r.height * dpr));
            if (canvas.width !== w || canvas.height !== h) { canvas.width = w; canvas.height = h; bubbles = []; }
        }
        function bub(R) { return { x: (Math.random() * 2 - 1) * R * 0.78, y: Math.random() * R * 1.6, r: 1 + Math.random() * 3.4, vy: 12 + Math.random() * 22, vx: (Math.random() * 2 - 1) * 8, a: 0.14 + Math.random() * 0.34 }; }

        function draw(now) {
            resize();
            var dt = Math.min(0.05, Math.max(0, (now - last) / 1000)); last = now;
            var w = canvas.width, h = canvas.height, cx = w * 0.5, cy = h * 0.53, R = Math.min(w, h) * 0.33, lv = clamp(cur / 10, 0, 1), top = cy + R - 2 * R * lv, p = pick(state.mode);
            var follow = reduced ? 1 : (1 - Math.pow(0.0013, dt)); cur += (target - cur) * follow; phase += dt * (reduced ? 0 : (2.2 + lv));
            ctx.clearRect(0, 0, w, h);
            ctx.lineWidth = Math.max(12, R * 0.17); ctx.strokeStyle = 'rgba(242,236,221,0.13)'; ctx.beginPath(); ctx.arc(cx, cy, R, 0, Math.PI * 2); ctx.stroke();
            ctx.save(); ctx.beginPath(); ctx.arc(cx, cy, R, 0, Math.PI * 2); ctx.clip();
            var g = ctx.createLinearGradient(0, cy - R, 0, cy + R); g.addColorStop(0, p.a); g.addColorStop(0.5, p.b); g.addColorStop(1, p.c); ctx.globalAlpha = 0.88; ctx.fillStyle = g; ctx.fillRect(cx - R, top, 2 * R, cy + R - top + 2); ctx.globalAlpha = 1;
            var a1 = R * (0.055 + (1 - lv) * 0.015), l1 = R * 0.95; ctx.beginPath(); ctx.moveTo(cx - R, top); for (var x = -R; x <= R; x += 3) ctx.lineTo(cx + x, top + Math.sin((x / l1) * Math.PI * 2 + phase) * a1); ctx.lineTo(cx + R, cy + R + 2); ctx.lineTo(cx - R, cy + R + 2); ctx.closePath(); ctx.fillStyle = 'rgba(242,236,221,0.24)'; ctx.fill();
            var wave2 = state.mode === 'hades' ? 'rgba(255,136,48,0.26)' : state.mode === 'zeus' ? 'rgba(96,162,255,0.24)' : 'rgba(255,146,86,0.24)';
            var a2 = R * (0.035 + lv * 0.01), l2 = R * 1.2; ctx.beginPath(); ctx.moveTo(cx - R, top); for (var x2 = -R; x2 <= R; x2 += 3) ctx.lineTo(cx + x2, top + Math.sin((x2 / l2) * Math.PI * 2 - phase * 1.4) * a2); ctx.lineTo(cx + R, cy + R + 2); ctx.lineTo(cx - R, cy + R + 2); ctx.closePath(); ctx.fillStyle = wave2; ctx.fill();
            if (!reduced) {
                if (bubbles.length < 24) bubbles.push(bub(R));
                bubbles = bubbles.filter(function (b) {
                    b.y -= b.vy * dt; b.x += b.vx * dt; if (b.y < -R * 2 || Math.abs(b.x) > R * 0.95) return false; var py = cy + R - b.y; if (py < top + 1) return false;
                    ctx.beginPath(); ctx.arc(cx + b.x, py, b.r, 0, Math.PI * 2); ctx.fillStyle = 'rgba(226,255,248,' + b.a.toFixed(3) + ')'; ctx.fill(); return true;
                });
            }
            ctx.restore();
            ctx.lineCap = 'round'; ctx.lineWidth = Math.max(10, R * 0.14);
            var rg = ctx.createLinearGradient(cx - R, cy - R, cx + R, cy + R); rg.addColorStop(0, p.a); rg.addColorStop(0.58, p.b); rg.addColorStop(1, p.c); ctx.strokeStyle = rg; ctx.shadowBlur = 22; ctx.shadowColor = p.g; ctx.beginPath(); ctx.arc(cx, cy, R, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * lv, false); ctx.stroke(); ctx.shadowBlur = 0;
            ctx.lineCap = 'butt'; ctx.lineWidth = 1.2; ctx.strokeStyle = 'rgba(242,236,221,0.26)'; ctx.beginPath(); ctx.arc(cx, cy, R + 10, 0, Math.PI * 2); ctx.stroke();
            requestAnimationFrame(draw);
        }
        if (label) label.textContent = '0.0';
        window.addEventListener('resize', resize, { passive: true });
        requestAnimationFrame(draw);
        return { setValue: function (v) { var c = clamp(Number(v) || 0, 0, 10); if (label) label.textContent = c.toFixed(1); target = c; } };
    }

    function bootSnow(reduced) {
        if (reduced || document.querySelector('.fx-ambient-canvas')) return;
        var c = document.createElement('canvas'); c.className = 'fx-ambient-canvas'; document.body.appendChild(c);
        var x = c.getContext('2d'); if (!x) return;
        var flakes = [], sparks = [], pt = { x: -9999, y: -9999 }, last = performance.now(), wind = 0;
        function mkFlake(w, h, top) { return { x: Math.random() * w, y: top ? -Math.random() * h * 0.2 : Math.random() * h, vx: (Math.random() - 0.5) * 10, vy: 14 + Math.random() * 28, r: 0.7 + Math.random() * 2.2, a: 0.22 + Math.random() * 0.56, d: Math.random() * Math.PI * 2 }; }
        function mkSpark(w, h) { return { x: Math.random() * w, y: Math.random() * h, vx: (Math.random() - 0.5) * 8, vy: 6 + Math.random() * 12, r: 0.5 + Math.random() * 1.2, a: 0.08 + Math.random() * 0.18 }; }
        function rebuild() {
            var w = window.innerWidth, h = window.innerHeight, n = Math.max(110, Math.min(320, Math.floor(w / 4.4))), m = Math.max(24, Math.min(80, Math.floor(w / 22)));
            flakes = []; sparks = []; for (var i = 0; i < n; i++) flakes.push(mkFlake(w, h, false)); for (var j = 0; j < m; j++) sparks.push(mkSpark(w, h));
        }
        function resize() {
            var dpr = Math.max(1, Math.min(2, window.devicePixelRatio || 1));
            c.width = Math.floor(window.innerWidth * dpr); c.height = Math.floor(window.innerHeight * dpr);
            c.style.width = window.innerWidth + 'px'; c.style.height = window.innerHeight + 'px';
            x.setTransform(1, 0, 0, 1, 0, 0); x.scale(dpr, dpr); rebuild();
        }
        function frame(now) {
            var dt = Math.min(0.05, Math.max(0, (now - last) / 1000)); last = now; var w = window.innerWidth, h = window.innerHeight, p = pick(state.mode); wind = Math.sin(now * 0.00025) * 10;
            x.clearRect(0, 0, w, h);
            for (var i = 0; i < flakes.length; i++) {
                var f = flakes[i]; f.d += dt * 1.6; f.x += (f.vx + Math.sin(f.d) * 8 + wind) * dt; f.y += f.vy * dt;
                var dx = pt.x - f.x, dy = pt.y - f.y, d2 = dx * dx + dy * dy; if (d2 < 12000) { var pull = (1 - d2 / 12000) * 40; f.x -= (dx / (Math.sqrt(d2) + 0.1)) * pull * dt; }
                if (f.y > h + 8 || f.x < -12 || f.x > w + 12) { flakes[i] = mkFlake(w, h, true); flakes[i].x = Math.random() * w; continue; }
                var tw = (Math.sin(now * 0.002 + f.d * 3.7) + 1) * 0.5; x.beginPath(); x.arc(f.x, f.y, f.r, 0, Math.PI * 2); x.fillStyle = 'rgba(242,236,221,' + (f.a * (0.72 + tw * 0.28)).toFixed(3) + ')'; x.fill();
            }
            for (var s = 0; s < sparks.length; s++) {
                var k = sparks[s]; k.x += (k.vx + wind * 0.4) * dt; k.y += k.vy * dt;
                if (k.y > h + 4 || k.x < -8 || k.x > w + 8) { sparks[s] = mkSpark(w, h); sparks[s].y = -Math.random() * 20; continue; }
                x.beginPath(); x.arc(k.x, k.y, k.r, 0, Math.PI * 2); x.fillStyle = p.b.replace('#', 'rgba(').replace(/(..)(..)(..)/, function (_, r, g, b) { return parseInt(r, 16) + ',' + parseInt(g, 16) + ',' + parseInt(b, 16) + ',' + k.a.toFixed(2) + ')'; }); x.fill();
            }
            requestAnimationFrame(frame);
        }
        window.addEventListener('pointermove', function (e) { pt.x = e.clientX; pt.y = e.clientY; }, { passive: true });
        window.addEventListener('pointerleave', function () { pt.x = -9999; pt.y = -9999; }, { passive: true });
        window.addEventListener('resize', resize, { passive: true });
        resize(); requestAnimationFrame(frame);
    }

    function bootRowSpotlight() {
        var body = document.getElementById('recentAttacksBody'); if (!body) return;
        body.addEventListener('pointermove', function (e) { var r = e.target && e.target.closest ? e.target.closest('tr') : null; if (!r) return; var b = r.getBoundingClientRect(); r.style.setProperty('--rowx', (((e.clientX - b.left) / b.width) * 100).toFixed(2) + '%'); }, { passive: true });
    }

    function bootValuePulse() {
        var targets = document.querySelectorAll('.stat-value, .behavioral-metric-value'); if (!targets.length) return;
        var bag = new WeakMap();
        var obs = new MutationObserver(function (list) {
            list.forEach(function (m) {
                var card = m.target.closest('.stat-card, .behavioral-metric'); if (!card) return;
                card.classList.remove('value-pulse'); void card.offsetWidth; card.classList.add('value-pulse');
                if (bag.has(card)) clearTimeout(bag.get(card));
                bag.set(card, setTimeout(function () { card.classList.remove('value-pulse'); bag.delete(card); }, 560));
            });
        });
        targets.forEach(function (el) { obs.observe(el, { characterData: true, childList: true, subtree: true }); });
    }

    function v(lat, lon) { lat = rad(lat); lon = rad(lon); return { x: Math.cos(lat) * Math.cos(lon), y: Math.sin(lat), z: Math.cos(lat) * Math.sin(lon) }; }
    function norm(a) { var l = Math.sqrt(a.x * a.x + a.y * a.y + a.z * a.z) || 1; return { x: a.x / l, y: a.y / l, z: a.z / l }; }
    function slerp(a, b, t) { var d = clamp(a.x * b.x + a.y * b.y + a.z * b.z, -1, 1), th = Math.acos(d) * t, r = norm({ x: b.x - a.x * d, y: b.y - a.y * d, z: b.z - a.z * d }); return norm({ x: a.x * Math.cos(th) + r.x * Math.sin(th), y: a.y * Math.cos(th) + r.y * Math.sin(th), z: a.z * Math.cos(th) + r.z * Math.sin(th) }); }
    function proj(p, ry, rx, R, cx, cy) { var sy = Math.sin(ry), cyy = Math.cos(ry), sx = Math.sin(rx), cxx = Math.cos(rx); var x1 = p.x * cyy - p.z * sy, z1 = p.x * sy + p.z * cyy, y1 = p.y; var y2 = y1 * cxx - z1 * sx, z2 = y1 * sx + z1 * cxx; return { x: cx + x1 * R, y: cy - y2 * R, z: z2 }; }

    function createGlobe(canvas, opts) {
        if (!canvas) return null;
        var ctx = canvas.getContext('2d'); if (!ctx) return null;

        var hubs = [
            { n: 'NYC', la: 40.71, lo: -74.00 }, { n: 'SFO', la: 37.77, lo: -122.42 }, { n: 'TOR', la: 43.65, lo: -79.38 },
            { n: 'MEX', la: 19.43, lo: -99.13 }, { n: 'SAO', la: -23.55, lo: -46.63 }, { n: 'BUE', la: -34.60, lo: -58.38 },
            { n: 'LON', la: 51.50, lo: -0.12 }, { n: 'PAR', la: 48.85, lo: 2.35 }, { n: 'BER', la: 52.52, lo: 13.40 },
            { n: 'MAD', la: 40.41, lo: -3.70 }, { n: 'LAG', la: 6.52, lo: 3.38 }, { n: 'CAI', la: 30.04, lo: 31.24 },
            { n: 'JNB', la: -26.20, lo: 28.04 }, { n: 'DXB', la: 25.20, lo: 55.27 }, { n: 'IST', la: 41.00, lo: 28.97 },
            { n: 'DEL', la: 28.61, lo: 77.20 }, { n: 'BOM', la: 19.07, lo: 72.87 }, { n: 'SIN', la: 1.35, lo: 103.82 },
            { n: 'HKG', la: 22.32, lo: 114.17 }, { n: 'SEO', la: 37.57, lo: 126.98 }, { n: 'TYO', la: 35.68, lo: 139.69 },
            { n: 'SYD', la: -33.86, lo: 151.21 }, { n: 'JKT', la: -6.20, lo: 106.85 }, { n: 'MOW', la: 55.76, lo: 37.62 }
        ];
        for (var hi = 0; hi < hubs.length; hi++) hubs[hi].p = v(hubs[hi].la, hubs[hi].lo);

        var lanes = ['OAS', 'ODS', 'MAV', 'WAV', 'IDS', 'VUL', 'KAS', 'RMN'];

        var g = {
            mode: (opts && opts.mode) || state.mode,
            ry: 0.28,
            rx: -0.19,
            dY: 0,
            dX: 0,
            links: [],
            stars: [],
            glyphs: [],
            last: performance.now(),
            lastDraw: 0,
            fpsCap: state.reduced ? 18 : 28,
            lowPower: state.reduced || (typeof navigator !== 'undefined' && typeof navigator.hardwareConcurrency === 'number' && navigator.hardwareConcurrency > 0 && navigator.hardwareConcurrency <= 8),
            rewireAt: 0,
            hover: false,
            drag: false,
            running: false,
            raf: 0,
            px: 0,
            py: 0
        };

        function hexToRgba(hex, alpha) {
            var s = String(hex || '#ffffff').replace('#', '');
            if (s.length === 3) s = s[0] + s[0] + s[1] + s[1] + s[2] + s[2];
            var r = parseInt(s.slice(0, 2), 16), g2 = parseInt(s.slice(2, 4), 16), b = parseInt(s.slice(4, 6), 16);
            return 'rgba(' + r + ',' + g2 + ',' + b + ',' + alpha + ')';
        }

        function lanePalette(mode) {
            if (mode === 'hades') {
                return { OAS: '#f8e7cf', ODS: '#ff8f34', MAV: '#f14bff', WAV: '#b34dff', IDS: '#ffb45c', VUL: '#d94a2f', KAS: '#ff733f', RMN: '#8d45ff' };
            }
            if (mode === 'helios') {
                return { OAS: '#ffcc78', ODS: '#ff6045', MAV: '#ff9954', WAV: '#ffd58e', IDS: '#ff5d3a', VUL: '#ffe77a', KAS: '#ff8755', RMN: '#ffb16d' };
            }
            return { OAS: '#b2d6ff', ODS: '#4584ff', MAV: '#8ec0ff', WAV: '#2b67f4', IDS: '#9bc9ff', VUL: '#6f9cff', KAS: '#5e90ff', RMN: '#7bb2ff' };
        }

        function laneColor(lane, mode) {
            var t = lanePalette(mode);
            return t[lane] || t.OAS;
        }

        function resize() {
            var dpr = Math.max(1, Math.min(g.lowPower ? 1.2 : 1.5, window.devicePixelRatio || 1)), r = canvas.getBoundingClientRect();
            canvas.width = Math.max(1, Math.floor(r.width * dpr));
            canvas.height = Math.max(1, Math.floor(r.height * dpr));
            ctx.setTransform(1, 0, 0, 1, 0, 0);
            ctx.scale(dpr, dpr);
            buildStars(r.width || 600, r.height || 420);
            buildGlyphs();
            if (!g.links.length) buildShowcaseLinks(g.lowPower ? 16 : 24);
        }

        function buildStars(w, h) {
            var total = g.lowPower
                ? Math.max(30, Math.min(80, Math.floor((w + h) / 14)))
                : Math.max(56, Math.min(120, Math.floor((w + h) / 9)));
            g.stars = [];
            for (var i = 0; i < total; i++) {
                var hs = hash('star|' + i), x = ((hs % 10000) / 10000) * w, y = (((hs >>> 4) % 10000) / 10000) * h;
                g.stars.push({
                    x: x,
                    y: y,
                    r: 0.4 + ((hs >>> 8) % 28) / 28,
                    a: 0.14 + ((hs >>> 12) % 70) / 240,
                    t: 0.6 + ((hs >>> 17) % 120) / 100,
                    p: (hs % 628) / 100
                });
            }
        }

        function buildGlyphs() {
            g.glyphs = [];
            var glyphTotal = g.lowPower ? 34 : 72;
            for (var i = 0; i < glyphTotal; i++) {
                var hg = hash('glyph|' + i);
                g.glyphs.push({
                    a: ((hg % 3600) / 3600) * Math.PI * 2,
                    r: (hg >>> 9) % 20,
                    v: (((hg >>> 5) % 2) ? 1 : -1) * (0.30 + ((hg >>> 13) % 100) / 170),
                    lane: (hg >>> 2) % lanes.length,
                    shape: (hg >>> 7) % 3,
                    s: 0.7 + ((hg >>> 16) % 26) / 16
                });
            }
        }

        function buildShowcaseLinks(count) {
            var total = Math.max(0, Math.min(50, Math.floor(Number(count) || 0))), out = [];
            for (var i = 0; i < total; i++) {
                var src = hubs[(i * 7 + 3) % hubs.length], dst = hubs[(i * 11 + 17 + Math.floor(i / 5)) % hubs.length];
                if (src === dst) dst = hubs[(i * 13 + 9) % hubs.length];
                var dot = src.p.x * dst.p.x + src.p.y * dst.p.y + src.p.z * dst.p.z;
                if (dot > 0.84) dst = hubs[(i * 9 + 27) % hubs.length];
                var lane = lanes[(i + (i % 3)) % lanes.length], hl = hash(src.n + '|' + dst.n + '|' + lane + '|' + i);
                out.push({
                    src: src,
                    dst: dst,
                    lane: lane,
                    p: (hl % 1000) / 1000,
                    sp: 0.10 + ((hl >>> 4) % 100) / 450,
                    w: 1.0 + ((hl >>> 10) % 55) / 50,
                    lift: 0.14 + ((hl >>> 14) % 90) / 340,
                    phase: (hl % 628) / 100,
                    packetCount: g.lowPower ? 1 : (1 + ((hl >>> 3) % 2)),
                    dash: ((hl >>> 2) % 2) === 0
                });
            }
            g.links = out;
        }

        function setLinkDensityFromFeed(attacks, summary) {
            var total = Number((summary && summary.total_attacks) || (Array.isArray(attacks) ? attacks.length : 0) || 0);
            var target = 8 + Math.min(42, Math.floor(total / 4));
            if (g.lowPower) target = Math.min(30, target);
            buildShowcaseLinks(target);
        }

        function drawStars(now, w, h) {
            ctx.save();
            for (var i = 0; i < g.stars.length; i++) {
                var s = g.stars[i], tw = 0.4 + 0.6 * (0.5 + 0.5 * Math.sin(now * 0.001 * s.t + s.p));
                var sx = s.x + Math.sin(now * 0.00006 + s.p) * 1.8, sy = s.y + Math.cos(now * 0.00005 + s.p * 0.7) * 1.4;
                ctx.beginPath();
                ctx.arc(sx, sy, s.r, 0, Math.PI * 2);
                ctx.fillStyle = 'rgba(235,233,255,' + (s.a * tw).toFixed(3) + ')';
                ctx.fill();
            }
            ctx.restore();
        }

        function drawTelemetryRing(now, cx, cy, R, mode) {
            var lp = lanePalette(mode);
            for (var i = 0; i < g.glyphs.length; i++) {
                var gy = g.glyphs[i], lane = lanes[gy.lane], col = laneColor(lane, mode), ang = gy.a + now * 0.00008 * gy.v;
                var rr = R + 14 + gy.r, x = cx + Math.cos(ang) * rr, y = cy + Math.sin(ang) * rr;
                ctx.save();
                ctx.strokeStyle = hexToRgba(col, 0.48);
                ctx.fillStyle = hexToRgba(col, 0.62);
                ctx.lineWidth = 1;
                if (gy.shape === 0) {
                    ctx.fillRect(x - gy.s * 0.5, y - gy.s * 0.5, gy.s, gy.s);
                } else if (gy.shape === 1) {
                    ctx.beginPath(); ctx.arc(x, y, gy.s * 0.55, 0, Math.PI * 2); ctx.stroke();
                } else {
                    ctx.beginPath(); ctx.moveTo(x - gy.s * 0.7, y + gy.s * 0.5); ctx.lineTo(x, y - gy.s * 0.7); ctx.lineTo(x + gy.s * 0.7, y + gy.s * 0.5); ctx.stroke();
                }
                ctx.restore();
            }

            ctx.font = '11px "JetBrains Mono", monospace';
            ctx.textAlign = 'center';
            var baseX = cx - ((lanes.length - 1) * 44), y2 = cy + R + 36;
            for (var l = 0; l < lanes.length; l++) {
                var laneName = lanes[l], laneCol = lp[laneName] || '#9dc0ff', x2 = baseX + l * 88;
                ctx.fillStyle = hexToRgba(laneCol, 0.92);
                ctx.fillText(laneName, x2, y2);
            }
        }

        function drawGrid(cx, cy, R, mode) {
            var latCol = mode === 'hades' ? 'rgba(255,214,168,0.12)' : mode === 'helios' ? 'rgba(255,192,136,0.09)' : 'rgba(192,224,255,0.10)';
            var lonCol = mode === 'hades' ? 'rgba(214,64,255,0.10)' : mode === 'helios' ? 'rgba(255,120,80,0.08)' : 'rgba(91,153,255,0.09)';

            ctx.lineWidth = 1;
            for (var la = -60; la <= 60; la += 15) {
                ctx.beginPath();
                var started = false;
                for (var lo = -180; lo <= 180; lo += 6) {
                    var pp = proj(v(la, lo), g.ry, g.rx, R, cx, cy);
                    if (!started) { ctx.moveTo(pp.x, pp.y); started = true; } else ctx.lineTo(pp.x, pp.y);
                }
                ctx.strokeStyle = latCol;
                ctx.stroke();
            }
            for (var me = -180; me < 180; me += 15) {
                ctx.beginPath();
                var started2 = false;
                for (var la2 = -85; la2 <= 85; la2 += 5) {
                    var pm = proj(v(la2, me), g.ry, g.rx, R, cx, cy);
                    if (!started2) { ctx.moveTo(pm.x, pm.y); started2 = true; } else ctx.lineTo(pm.x, pm.y);
                }
                ctx.strokeStyle = lonCol;
                ctx.stroke();
            }
        }

        function drawLink(link, now, dt, cx, cy, R, mode) {
            var pts = [], N = g.lowPower ? 20 : 28;
            for (var i = 0; i <= N; i++) {
                var t = i / N, s = slerp(link.src.p, link.dst.p, t);
                var lift = 1 + Math.sin(t * Math.PI) * (link.lift + 0.03 * Math.sin(now * 0.0012 + link.phase));
                pts.push(proj({ x: s.x * lift, y: s.y * lift, z: s.z * lift }, g.ry, g.rx, R, cx, cy));
            }

            var col = laneColor(link.lane, mode);
            ctx.save();
            ctx.lineWidth = link.w;
            ctx.strokeStyle = hexToRgba(col, mode === 'hades' ? 0.72 : 0.64);
            ctx.shadowBlur = mode === 'hades' ? 15 : 11;
            ctx.shadowColor = hexToRgba(col, 0.66);
            ctx.setLineDash(link.dash ? [2.5, 5.5] : []);
            ctx.beginPath();
            for (var q = 0; q < pts.length; q++) { if (!q) ctx.moveTo(pts[q].x, pts[q].y); else ctx.lineTo(pts[q].x, pts[q].y); }
            ctx.stroke();
            ctx.restore();

            link.p += dt * link.sp * (state.reduced ? 0.35 : 1);
            if (link.p > 1) link.p -= 1;
            for (var k = 0; k < link.packetCount; k++) {
                var tp = (link.p + k * (1 / link.packetCount) + link.phase * 0.017) % 1;
                var id = Math.floor(tp * (pts.length - 1)), f = pts[id];
                if (!f || f.z < -0.08) continue;
                var rr = 1.9 + (k % 2) * 0.6;
                ctx.beginPath();
                ctx.arc(f.x, f.y, rr, 0, Math.PI * 2);
                ctx.fillStyle = hexToRgba(col, 0.90);
                ctx.shadowBlur = 12;
                ctx.shadowColor = hexToRgba(col, 0.90);
                ctx.fill();
                ctx.shadowBlur = 0;
                ctx.beginPath();
                ctx.arc(f.x, f.y, rr + 2.8, 0, Math.PI * 2);
                ctx.strokeStyle = hexToRgba(col, 0.35);
                ctx.lineWidth = 1;
                ctx.stroke();
            }
        }

        function drawHub(node, idx, active, now, cx, cy, R, mode) {
            var pr = proj(node.p, g.ry, g.rx, R, cx, cy);
            if (pr.z < -0.13) return;

            var col = laneColor(lanes[idx % lanes.length], mode);
            ctx.beginPath();
            ctx.arc(pr.x, pr.y, active ? 2.2 : 1.4, 0, Math.PI * 2);
            ctx.fillStyle = hexToRgba(col, active ? 0.95 : 0.50);
            ctx.fill();

            if (!state.reduced && active) {
                var pulse = 4.2 + Math.sin(now * 0.004 + idx) * 1.6;
                ctx.beginPath();
                ctx.arc(pr.x, pr.y, pulse, 0, Math.PI * 2);
                ctx.strokeStyle = hexToRgba(col, 0.40);
                ctx.lineWidth = 1;
                ctx.stroke();
            }

            if (pr.z > 0.08 && (active || idx % 3 === 0)) {
                ctx.font = '9px Orbitron, monospace';
                ctx.fillStyle = hexToRgba(mode === 'hades' ? '#ffe7c8' : '#cfdfff', active ? 0.82 : 0.40);
                ctx.fillText(node.n, pr.x + 5, pr.y - 4);
            }
        }

        function drawGlobe(now, animate) {
            var dt = animate ? Math.min(0.05, Math.max(0, (now - g.last) / 1000)) : 0;
            g.last = now;

            var w = canvas.clientWidth || 600, h = canvas.clientHeight || 420, cx = w * 0.5, cy = h * 0.51;
            var R = Math.min(w, h) * 0.37, p = pick(state.mode);
            ctx.clearRect(0, 0, w, h);
            drawStars(now, w, h);

            if (animate && !g.drag && !state.reduced) { g.ry += dt * (g.mode === 'hades' ? 0.15 : 0.20); g.dY *= 0.92; g.dX *= 0.92; }
            g.ry += g.dY * dt;
            g.rx = clamp(g.rx + g.dX * dt, -0.48, 0.46);
            if (animate && !g.lowPower && now > g.rewireAt && !g.drag) {
                var target = 12 + Math.floor((Math.sin(now * 0.00046) + 1) * 19);
                buildShowcaseLinks(target);
                g.rewireAt = now + 8000 + Math.random() * 2600;
            }

            var halo = ctx.createRadialGradient(cx, cy, R * 0.32, cx, cy, R * 1.58);
            halo.addColorStop(0, p.g.replace('0.52', '0.34').replace('0.50', '0.34'));
            halo.addColorStop(1, 'rgba(0,0,0,0)');
            ctx.fillStyle = halo;
            ctx.beginPath();
            ctx.arc(cx, cy, R * 1.62, 0, Math.PI * 2);
            ctx.fill();

            var sph = ctx.createRadialGradient(cx - R * 0.30, cy - R * 0.34, R * 0.20, cx, cy, R);
            if (g.mode === 'hades') {
                sph.addColorStop(0, 'rgba(255,214,168,0.22)');
                sph.addColorStop(0.45, 'rgba(74,14,58,0.88)');
                sph.addColorStop(1, 'rgba(10,4,14,0.98)');
            } else if (g.mode === 'helios') {
                sph.addColorStop(0, 'rgba(255,231,196,0.16)');
                sph.addColorStop(0.45, 'rgba(46,20,12,0.86)');
                sph.addColorStop(1, 'rgba(8,3,2,0.98)');
            } else {
                sph.addColorStop(0, 'rgba(226,238,255,0.18)');
                sph.addColorStop(0.45, 'rgba(12,23,46,0.86)');
                sph.addColorStop(1, 'rgba(3,6,14,0.98)');
            }
            ctx.fillStyle = sph;
            ctx.beginPath();
            ctx.arc(cx, cy, R, 0, Math.PI * 2);
            ctx.fill();

            ctx.save();
            ctx.beginPath();
            ctx.arc(cx, cy, R, 0, Math.PI * 2);
            ctx.clip();

            ctx.fillStyle = g.mode === 'hades' ? 'rgba(255,132,56,0.06)' : g.mode === 'helios' ? 'rgba(255,120,60,0.05)' : 'rgba(130,172,255,0.05)';
            for (var yy = cy - R; yy <= cy + R; yy += 4) ctx.fillRect(cx - R, yy, R * 2, 1);

            drawGrid(cx, cy, R, g.mode);

            var active = {};
            for (var l = 0; l < g.links.length; l++) {
                active[g.links[l].src.n] = true;
                active[g.links[l].dst.n] = true;
                drawLink(g.links[l], now, dt, cx, cy, R, g.mode);
            }
            for (var n = 0; n < hubs.length; n++) drawHub(hubs[n], n, !!active[hubs[n].n], now, cx, cy, R, g.mode);

            ctx.restore();

            ctx.lineWidth = 1.8;
            ctx.strokeStyle = g.mode === 'hades' ? 'rgba(255,195,132,0.36)' : 'rgba(232,238,255,0.30)';
            ctx.beginPath();
            ctx.arc(cx, cy, R, 0, Math.PI * 2);
            ctx.stroke();

            ctx.lineWidth = 1.2;
            ctx.strokeStyle = g.mode === 'hades' ? 'rgba(214,76,255,0.34)' : hexToRgba(p.b, 0.30);
            ctx.beginPath();
            ctx.arc(cx, cy, R + 10, 0, Math.PI * 2);
            ctx.stroke();

            if (!g.lowPower) drawTelemetryRing(now, cx, cy, R, g.mode);
        }

        function scheduleFrame() {
            if (!g.running || g.raf) return;
            g.raf = requestAnimationFrame(frame);
        }

        function startLoop() {
            if (g.running) return;
            g.running = true;
            g.last = performance.now();
            g.lastDraw = 0;
            scheduleFrame();
        }

        function stopLoop() {
            g.running = false;
            if (g.raf) {
                cancelAnimationFrame(g.raf);
                g.raf = 0;
            }
        }

        function drawStatic() {
            drawGlobe(performance.now(), false);
        }

        function frame(now) {
            g.raf = 0;
            if (!g.running) return;
            if (document.hidden) {
                g.last = now;
                scheduleFrame();
                return;
            }
            if (g.lastDraw > 0 && now - g.lastDraw < (1000 / g.fpsCap)) {
                scheduleFrame();
                return;
            }
            g.lastDraw = now;
            drawGlobe(now, true);
            scheduleFrame();
        }

        canvas.addEventListener('pointerenter', function () {
            g.hover = true;
            startLoop();
        });
        canvas.addEventListener('pointerleave', function () {
            g.hover = false;
            if (!g.drag) stopLoop();
        });
        canvas.addEventListener('pointerdown', function (e) {
            g.drag = true;
            g.hover = true;
            g.px = e.clientX;
            g.py = e.clientY;
            canvas.setPointerCapture && canvas.setPointerCapture(e.pointerId);
            startLoop();
        });
        canvas.addEventListener('pointermove', function (e) {
            if (!g.drag) return;
            var dx = e.clientX - g.px, dy = e.clientY - g.py;
            g.px = e.clientX;
            g.py = e.clientY;
            g.dY = dx * 0.066;
            g.dX = -dy * 0.052;
        });
        function end() {
            g.drag = false;
            if (canvas.matches) {
                try { g.hover = canvas.matches(':hover'); } catch (_) {}
            }
            if (!g.hover) stopLoop();
        }
        canvas.addEventListener('pointerup', end);
        canvas.addEventListener('pointercancel', end);

        function onResize() {
            resize();
            if (!g.running) drawStatic();
        }

        window.addEventListener('resize', onResize, { passive: true });

        resize();
        buildShowcaseLinks(g.lowPower ? 16 : 24);
        drawStatic();
        return {
            setMode: function (m) {
                g.mode = m;
                if (!g.running) drawStatic();
            },
            setLinksFromAttacks: function (attacks, summary) {
                setLinkDensityFromFeed(attacks, summary);
                if (!g.running) drawStatic();
            }
        };
        }

    function registerChartPlugin() {
        if (state.pluginOn || typeof window.Chart === 'undefined' || !window.Chart.register) return;
        try {
            window.Chart.register({
                id: 'dashboardGlow',
                beforeDatasetDraw: function (chart) {
                    if (state.reduced) return;
                    var x = chart.ctx;
                    x.save();
                    x.shadowBlur = state.mode === 'hades' ? 20 : 14;
                    x.shadowColor = pick(state.mode).g;
                },
                afterDatasetDraw: function (chart) { chart.ctx.restore(); }
            });
            state.pluginOn = true;
        } catch (_) {}
    }

    function chartColors(n, p, mode) {
        var out = [];
        if (mode === 'hades') {
            var hadesSet = ['rgba(255,143,52,0.88)', 'rgba(207,57,255,0.84)', 'rgba(248,232,210,0.80)', 'rgba(216,74,44,0.86)'];
            for (var h = 0; h < n; h++) out.push(hadesSet[h % hadesSet.length]);
            return out;
        }
        for (var i = 0; i < n; i++) out.push(i % 3 === 0 ? p.b : i % 3 === 1 ? p.a : p.c);
        return out;
    }

    function applyChartTheme(refs, mode) {
        if (refs) state.charts = refs;
        if (mode) state.mode = mode;
        var c = state.charts; if (!c) return;
        registerChartPlugin();
        var p = pick(state.mode);
        var updateMode = state.reduced ? 'none' : undefined;
        if (c.vulnChart) {
            var labels = (c.vulnChart.data && c.vulnChart.data.labels) || [];
            c.vulnChart.data.datasets[0].backgroundColor = chartColors(Math.max(1, labels.length), p, state.mode);
            c.vulnChart.data.datasets[0].borderColor = state.mode === 'hades' ? 'rgba(247,221,197,0.86)' : p.a; c.vulnChart.data.datasets[0].borderWidth = 1.2;
            c.vulnChart.data.datasets[0].borderRadius = 10; c.vulnChart.data.datasets[0].borderSkipped = false;
            c.vulnChart.options.animation = state.reduced ? false : { duration: 620, easing: 'easeOutQuart' };
            c.vulnChart.options.interaction = { mode: 'nearest', intersect: false };
            c.vulnChart.update(updateMode);
        }
        if (c.severityChart) {
            c.severityChart.data.datasets[0].backgroundColor = state.mode === 'hades'
                ? ['rgba(199,52,36,0.92)', 'rgba(255,143,52,0.88)', 'rgba(207,57,255,0.84)', 'rgba(248,232,210,0.80)']
                : [p.c, p.b, p.a, 'rgba(30,168,150,0.86)'];
            c.severityChart.data.datasets[0].hoverOffset = 16; c.severityChart.data.datasets[0].borderColor = 'rgba(8,8,10,0.4)'; c.severityChart.data.datasets[0].borderWidth = 2;
            c.severityChart.options.cutout = '58%'; c.severityChart.options.animation = state.reduced ? false : { duration: 680, easing: 'easeOutCubic' };
            c.severityChart.update(updateMode);
        }
        if (c.cveChart) {
            var labels2 = (c.cveChart.data && c.cveChart.data.labels) || [];
            c.cveChart.data.datasets[0].backgroundColor = chartColors(Math.max(1, labels2.length), p, state.mode).reverse();
            c.cveChart.data.datasets[0].borderColor = state.mode === 'hades' ? 'rgba(246,217,190,0.82)' : p.b; c.cveChart.data.datasets[0].borderWidth = 1;
            c.cveChart.data.datasets[0].borderRadius = 8; c.cveChart.data.datasets[0].barPercentage = 0.74;
            c.cveChart.options.animation = state.reduced ? false : { duration: 640, easing: 'easeOutQuart' };
            c.cveChart.options.interaction = { mode: 'nearest', intersect: false };
            c.cveChart.update(updateMode);
        }
    }

    function updateThreatFeed(attacks, summary) {
        if (state.globe && state.globe.setLinksFromAttacks) {
            state.globe.setLinksFromAttacks(attacks, summary);
        }
    }

    function setMode(mode) {
        var m = String(mode || '').toLowerCase();
        if (m === 'gaia') m = 'hades';
        if (!palettes[m]) m = 'hades';
        state.mode = m; if (document.body) document.body.setAttribute('data-fx-mode', m);
        if (state.globe && state.globe.setMode) state.globe.setMode(m);
        applyChartTheme(null, m);
    }

    function initThreatGlobe(canvas, opts) {
        state.globe = createGlobe(canvas, opts || {});
        return state.globe;
    }

    function boot(options) {
        var o = options || {};
        state.reduced = typeof o.prefersReducedMotion === 'boolean' ? o.prefersReducedMotion : !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
        setMode(o.mode || state.mode);
        bootSnow(state.reduced);
        bootRowSpotlight();
        bootValuePulse();
    }

    window.DashboardEffects = {
        boot: boot,
        setMode: setMode,
        applyChartTheme: applyChartTheme,
        initThreatGlobe: initThreatGlobe,
        updateThreatFeed: updateThreatFeed,
        createLiquidCvssGauge: createLiquidCvssGauge,
        getPalette: function (m) { return pick(m || state.mode); }
    };
})();
