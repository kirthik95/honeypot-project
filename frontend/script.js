/* =========================================================
   Interactive UI Layer (safe, no tracking)
   Features:
   1) Card tilt + parallax glow
   2) Magnetic/elastic button
   3) Ambient particles (canvas)
   4) Title glitch/scramble
   5) Scanline shimmer
   6) Respects prefers-reduced-motion
   ========================================================= */

const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const COLOR_SILVER = '242, 236, 221';
const COLOR_GOLD = '199, 150, 28';
const COLOR_RED = '177, 18, 18';
const COLOR_BLACK = '5,5,5';
const enableDragonCursor = false;

// Elements
const card = document.querySelector('.login-card');
const submitBtn = document.querySelector('.submit-btn');
const title = document.querySelector('.card-title');
const canvas = document.getElementById('webgl-canvas');

// Guard
if (!card || !submitBtn || !title || !canvas) {
    console.warn('Interactive layer: required elements not found.');
}

// -----------------------------------------
// Dragon cursor follower (original glyph)
// -----------------------------------------
let dragonFollower = null;
const DRAGON_SIZE = 96;
const DRAGON_MOUTH_OFFSET = { x: DRAGON_SIZE * 0.45, y: DRAGON_SIZE * 0.02 };
let dragonPos = { x: window.innerWidth / 2, y: window.innerHeight / 2 };
let dragonTarget = { x: window.innerWidth / 2, y: window.innerHeight / 2 };
let dragonAngle = 0;
if (!prefersReducedMotion && enableDragonCursor) {
    dragonFollower = document.createElement('div');
    dragonFollower.className = 'dragon-follower';
    dragonFollower.innerHTML = `
        <svg viewBox="0 0 260 180" aria-hidden="true">
            <path class="dragon-body" d="M20 132 C34 70 92 36 150 40 C182 42 206 30 230 6 C230 42 214 70 192 84 C220 84 244 100 252 122 C228 110 200 110 178 124 C148 142 120 160 86 152 C60 146 40 142 28 128 Z" />
            <path class="dragon-head" d="M182 70 L242 92 L190 118 L166 100 Z" />
            <path class="dragon-jaw" d="M188 112 L242 92 L232 130 L188 130 Z" />
            <path class="dragon-horn" d="M194 56 L220 26 L214 60" />
            <path class="dragon-whisker" d="M170 88 L130 76 L154 102" />
            <path class="dragon-whisker" d="M170 104 L126 120 L158 122" />
            <path class="dragon-spine" d="M92 72 L106 48 L116 76 L130 52 L140 80 L156 60" />
            <path class="dragon-tail" d="M26 138 L6 150 L26 158" />
            <circle class="dragon-eye" cx="204" cy="92" r="3.6" />
        </svg>
    `;
    document.body.appendChild(dragonFollower);

    const dragonStyle = document.createElement('style');
    dragonStyle.textContent = `
        .dragon-follower {
            position: fixed;
            width: ${DRAGON_SIZE}px;
            height: ${DRAGON_SIZE}px;
            top: 0;
            left: 0;
            pointer-events: none;
            z-index: 3;
            mix-blend-mode: screen;
            filter: drop-shadow(0 0 20px rgba(242, 236, 221,0.6));
            transition: opacity 200ms ease;
            opacity: 0.95;
            animation: dragonPulse 3.6s ease-in-out infinite;
        }
        .dragon-follower svg {
            width: 100%;
            height: 100%;
        }
        .dragon-follower .dragon-body,
        .dragon-follower .dragon-horn,
        .dragon-follower .dragon-tail,
        .dragon-follower .dragon-spine,
        .dragon-follower .dragon-whisker {
            fill: none;
            stroke: rgba(242, 236, 221,0.9);
            stroke-width: 2.6;
            stroke-linecap: round;
            stroke-linejoin: round;
        }
        .dragon-follower .dragon-head,
        .dragon-follower .dragon-jaw {
            fill: rgba(5,5,5,0.88);
            stroke: rgba(177,18,18,0.95);
            stroke-width: 2.4;
            stroke-linejoin: round;
        }
        .dragon-follower .dragon-eye {
            fill: rgba(177,18,18,1);
        }
        @keyframes dragonPulse {
            0%, 100% { filter: drop-shadow(0 0 18px rgba(242, 236, 221,0.55)); }
            50% { filter: drop-shadow(0 0 28px rgba(177,18,18,0.65)); }
        }
    `;
    document.head.appendChild(dragonStyle);
}

// -----------------------------------------
// 1) Card tilt + parallax glow
// -----------------------------------------
if (!prefersReducedMotion && card) {
    const maxTilt = 8;
    const glow = document.createElement('div');
    glow.style.cssText = `
        position:absolute;
        inset:-40%;
        background: radial-gradient(600px circle at var(--gx, 50%) var(--gy, 50%),
            rgba(242, 236, 221,0.24), transparent 50%);
        opacity: 0;
        transition: opacity 200ms ease;
        pointer-events:none;
        mix-blend-mode: screen;
    `;
    card.appendChild(glow);

    const handleMove = (e) => {
        const rect = card.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        const px = x / rect.width;
        const py = y / rect.height;
        const tiltX = (py - 0.5) * -maxTilt;
        const tiltY = (px - 0.5) * maxTilt;

        card.style.transform = `perspective(900px) rotateX(${tiltX}deg) rotateY(${tiltY}deg)`;
        card.style.setProperty('--gx', `${px * 100}%`);
        card.style.setProperty('--gy', `${py * 100}%`);
        glow.style.opacity = '1';
    };

    const handleLeave = () => {
        card.style.transform = 'perspective(900px) rotateX(0deg) rotateY(0deg)';
        glow.style.opacity = '0';
    };

    card.addEventListener('mousemove', handleMove);
    card.addEventListener('mouseleave', handleLeave);
}

// -----------------------------------------
// 2) Magnetic/elastic button
// -----------------------------------------
if (!prefersReducedMotion && submitBtn) {
    const strength = 18;
    const reset = () => {
        submitBtn.style.transform = 'translate3d(0,0,0)';
    };

    submitBtn.addEventListener('mousemove', (e) => {
        const rect = submitBtn.getBoundingClientRect();
        const x = e.clientX - rect.left - rect.width / 2;
        const y = e.clientY - rect.top - rect.height / 2;
        const dx = (x / rect.width) * strength;
        const dy = (y / rect.height) * strength;
        submitBtn.style.transform = `translate3d(${dx}px, ${dy}px, 0)`;
    });

    submitBtn.addEventListener('mouseleave', reset);
    submitBtn.addEventListener('blur', reset);
}

// -----------------------------------------
// 3) Ambient particles (canvas)
// -----------------------------------------
const ctx = canvas ? canvas.getContext('2d') : null;
let particles = [];
let snowParticles = [];
let fireParticles = [];
let codeBolts = [];
let codeBursts = [];
let mouse = { x: -9999, y: -9999 };
let lastFrameTime = performance.now();

const MAX_FIRE = 280;
const MAX_CODE_BOLTS = 40;
const MAX_CODE_BURSTS = 160;
const MAX_SNOW = 280;

const CODE_LINES = [
    'const veil = sync(node);',
    'if (auth) { grant(); }',
    'trace("edge");',
    'for (let i=0;i<3;i++) pulse();',
    'node.link("core");',
    'while (signal) { sweep(); }',
    'return hash(key);',
    'deploy("silver");',
    'ping(mesh);',
    'stack.push("redline");'
];

function resizeCanvas() {
    if (!canvas) return;
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
}

function createParticles(count = 50) {
    if (!canvas) return [];
    const list = [];
    for (let i = 0; i < count; i += 1) {
        list.push({
            x: Math.random() * canvas.width,
            y: Math.random() * canvas.height,
            vx: (Math.random() - 0.5) * 0.4,
            vy: (Math.random() - 0.5) * 0.4,
            r: 0.6 + Math.random() * 1.8,
            a: 0.05 + Math.random() * 0.12,
            color: COLOR_SILVER
        });
    }
    return list;
}

function createSnow(count = 200) {
    if (!canvas) return [];
    const list = [];
    for (let i = 0; i < count; i += 1) {
        const roll = Math.random();
        const color = roll > 0.96 ? COLOR_RED : (roll > 0.8 ? COLOR_GOLD : COLOR_SILVER);
        list.push({
            x: Math.random() * canvas.width,
            y: Math.random() * canvas.height,
            r: 1.1 + Math.random() * 2.6,
            vy: 0.35 + Math.random() * 1.2,
            vx: (Math.random() - 0.5) * 0.2,
            a: 0.08 + Math.random() * 0.2,
            phase: Math.random() * Math.PI * 2,
            color
        });
    }
    return list;
}

function spawnCodeBolt(x, y, targetX, targetY) {
    const angle = Math.atan2(targetY - y, targetX - x);
    const speed = 7 + Math.random() * 2.5;
    const text = CODE_LINES[Math.floor(Math.random() * CODE_LINES.length)];
    codeBolts.push({
        x,
        y,
        vx: Math.cos(angle) * speed,
        vy: Math.sin(angle) * speed,
        life: 0,
        ttl: 220 + Math.random() * 140,
        text
    });

    if (codeBolts.length > MAX_CODE_BOLTS) {
        codeBolts.splice(0, codeBolts.length - MAX_CODE_BOLTS);
    }
}

function spawnFire(x, y, vx, vy) {
    const count = 3 + Math.floor(Math.random() * 2);
    for (let i = 0; i < count; i += 1) {
        fireParticles.push({
            x: x + (Math.random() - 0.5) * 6,
            y: y + (Math.random() - 0.5) * 6,
            vx: -vx * 0.05 + (Math.random() - 0.5) * 0.6,
            vy: 0.6 + Math.random() * 1.2,
            life: 0,
            ttl: 420 + Math.random() * 280,
            size: 2 + Math.random() * 3.2
        });
    }

    if (fireParticles.length > MAX_FIRE) {
        fireParticles.splice(0, fireParticles.length - MAX_FIRE);
    }
}

function drawFire(p, alpha) {
    ctx.beginPath();
    ctx.fillStyle = `rgba(${COLOR_RED},${alpha})`;
    ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
    ctx.fill();

    ctx.beginPath();
    ctx.fillStyle = `rgba(${COLOR_BLACK},${alpha * 0.8})`;
    ctx.arc(p.x, p.y, p.size * 0.45, 0, Math.PI * 2);
    ctx.fill();
}

function drawCodeBolt(bolt, alpha) {
    const tailX = bolt.x - bolt.vx * 2.5;
    const tailY = bolt.y - bolt.vy * 2.5;
    ctx.lineCap = 'round';
    ctx.beginPath();
    ctx.strokeStyle = `rgba(${COLOR_BLACK},${alpha * 0.7})`;
    ctx.lineWidth = 4;
    ctx.moveTo(tailX, tailY);
    ctx.lineTo(bolt.x, bolt.y);
    ctx.stroke();

    ctx.beginPath();
    ctx.strokeStyle = `rgba(${COLOR_RED},${alpha})`;
    ctx.lineWidth = 2;
    ctx.moveTo(tailX, tailY);
    ctx.lineTo(bolt.x, bolt.y);
    ctx.stroke();

    // draw the code string as the bolt payload
    ctx.save();
    ctx.translate(bolt.x, bolt.y);
    ctx.rotate(Math.atan2(bolt.vy, bolt.vx));
    ctx.font = '13px "Space Grotesk", monospace';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = `rgba(${COLOR_BLACK},${alpha})`;
    ctx.fillText(bolt.text, 6, 0);
    ctx.fillStyle = `rgba(${COLOR_RED},${alpha})`;
    ctx.fillText(bolt.text, 5, -1);
    ctx.restore();
}

function drawParticles(now) {
    if (!ctx || prefersReducedMotion) return;
    const dt = Math.min((now - lastFrameTime) / 16.67, 2);
    lastFrameTime = now;

    ctx.globalCompositeOperation = 'source-over';
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // snow drift
    for (const s of snowParticles) {
        s.y += s.vy * dt;
        s.x += (s.vx + Math.sin(now * 0.001 + s.phase) * 0.18) * dt;

        if (s.y > canvas.height + 10) {
            s.y = -10;
            s.x = Math.random() * canvas.width;
        }
        if (s.x < -20) s.x = canvas.width + 20;
        if (s.x > canvas.width + 20) s.x = -20;

        const twinkle = 0.6 + 0.4 * Math.sin(now * 0.002 + s.phase);
        const alpha = s.a * (0.7 + twinkle * 0.3);
        ctx.beginPath();
        ctx.fillStyle = `rgba(${s.color},${alpha})`;
        ctx.arc(s.x, s.y, s.r, 0, Math.PI * 2);
        ctx.fill();
    }

    for (const p of particles) {
        // gentle drift
        p.x += p.vx * dt;
        p.y += p.vy * dt;

        if (p.x < -20) p.x = canvas.width + 20;
        if (p.x > canvas.width + 20) p.x = -20;
        if (p.y < -20) p.y = canvas.height + 20;
        if (p.y > canvas.height + 20) p.y = -20;

        // soft mouse repulsion
        const dx = p.x - mouse.x;
        const dy = p.y - mouse.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 140) {
            const push = (140 - dist) / 140;
            p.x += (dx / (dist || 1)) * push * 0.8 * dt;
            p.y += (dy / (dist || 1)) * push * 0.8 * dt;
        }

        ctx.beginPath();
        ctx.fillStyle = `rgba(${p.color},${p.a})`;
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fill();
    }

    // fire fall particles (from dragon spit)
    fireParticles = fireParticles.filter((p) => {
        p.life += 16.67 * dt;
        p.x += p.vx * dt;
        p.y += p.vy * dt;
        p.vx *= 0.96;
        p.vy *= 0.98;
        const alpha = Math.max(0, 1 - p.life / p.ttl);
        if (alpha > 0) drawFire(p, alpha);
        return p.life < p.ttl;
    });

    ctx.globalCompositeOperation = 'source-over';

    // code bolts (dragon spit)
    codeBolts = codeBolts.filter((bolt) => {
        bolt.life += 16.67 * dt;
        bolt.x += bolt.vx * dt;
        bolt.y += bolt.vy * dt;

        const alpha = Math.max(0, 1 - bolt.life / bolt.ttl);
        if (alpha > 0) {
            drawCodeBolt(bolt, alpha);
            spawnFire(bolt.x, bolt.y, bolt.vx, bolt.vy);
        }

        if (bolt.life >= bolt.ttl) {
            spawnCodeBurst(bolt.x, bolt.y);
            return false;
        }
        return true;
    });

    // code bursts
    ctx.font = '12px "Space Grotesk", monospace';
    ctx.textBaseline = 'middle';
    codeBursts = codeBursts.filter((p) => {
        p.life += 16.67 * dt;
        p.x += p.vx * dt;
        p.y += p.vy * dt;
        p.vy += 0.01 * dt;
        p.vx *= 0.98;
        p.vy *= 0.98;

        const alpha = Math.max(0, 1 - p.life / p.ttl);
        if (alpha > 0) {
            ctx.fillStyle = `rgba(${COLOR_BLACK},${alpha})`;
            ctx.save();
            ctx.translate(p.x, p.y);
            ctx.rotate(p.rot);
            ctx.fillText(p.text, 0, 0);
            ctx.fillStyle = `rgba(${p.color},${alpha})`;
            ctx.fillText(p.text, -1, -1);
            ctx.restore();
        }
        return p.life < p.ttl;
    });

    requestAnimationFrame(drawParticles);
}

if (canvas && ctx && !prefersReducedMotion) {
    resizeCanvas();
    particles = createParticles();
    snowParticles = createSnow(Math.min(MAX_SNOW, Math.floor(window.innerWidth / 4.5)));
    requestAnimationFrame(drawParticles);
    window.addEventListener('resize', () => {
        resizeCanvas();
        particles = createParticles();
        snowParticles = createSnow(Math.min(MAX_SNOW, Math.floor(window.innerWidth / 4.5)));
        ctx.clearRect(0, 0, canvas.width, canvas.height);
    });
    window.addEventListener('mousemove', (e) => {
        mouse = { x: e.clientX, y: e.clientY };
    });
    window.addEventListener('click', (e) => {
        const origin = dragonFollower ? getDragonMouthPosition() : { x: e.clientX, y: e.clientY };
        spawnCodeBolt(origin.x, origin.y, e.clientX, e.clientY);
    });
}

// Dragon follow animation loop
function getDragonMouthPosition() {
    const cos = Math.cos(dragonAngle);
    const sin = Math.sin(dragonAngle);
    const ox = DRAGON_MOUTH_OFFSET.x;
    const oy = DRAGON_MOUTH_OFFSET.y;
    return {
        x: dragonPos.x + ox * cos - oy * sin,
        y: dragonPos.y + ox * sin + oy * cos
    };
}

if (dragonFollower && !prefersReducedMotion) {
    window.addEventListener('mousemove', (e) => {
        dragonTarget = { x: e.clientX, y: e.clientY };
    });

    const animateDragon = () => {
        const dx = dragonTarget.x - dragonPos.x;
        const dy = dragonTarget.y - dragonPos.y;
        dragonPos.x += dx * 0.12;
        dragonPos.y += dy * 0.12;
        const targetAngle = Math.atan2(dy, dx);
        dragonAngle += (targetAngle - dragonAngle) * 0.15;
        dragonFollower.style.transform = `translate(${dragonPos.x}px, ${dragonPos.y}px) translate(-50%, -50%) rotate(${dragonAngle}rad)`;
        requestAnimationFrame(animateDragon);
    };

    animateDragon();
}

function spawnCodeBurst(x, y) {
    const count = 10 + Math.floor(Math.random() * 8);
    const angle = Math.random() * Math.PI * 2;
    const spread = 12;
    for (let i = 0; i < count; i += 1) {
        const offset = (i - count / 2) * spread;
        const ox = x + Math.cos(angle) * offset;
        const oy = y + Math.sin(angle) * offset;
        codeBursts.push({
            x: ox,
            y: oy,
            vx: Math.cos(angle) * (1.2 + Math.random() * 1.8) + (Math.random() - 0.5) * 0.8,
            vy: Math.sin(angle) * (1.2 + Math.random() * 1.8) + (Math.random() - 0.5) * 0.8,
            life: 0,
            ttl: 1100 + Math.random() * 900,
            text: CODE_LINES[Math.floor(Math.random() * CODE_LINES.length)],
            color: COLOR_RED,
            rot: (Math.random() - 0.5) * 0.4
        });
    }

    if (codeBursts.length > MAX_CODE_BURSTS) {
        codeBursts.splice(0, codeBursts.length - MAX_CODE_BURSTS);
    }
}

// -----------------------------------------
// 4) Title glitch/scramble
// -----------------------------------------
function scrambleText(el, duration = 900) {
    if (!el) return;
    const original = el.textContent;
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';
    const start = performance.now();

    function tick(now) {
        const elapsed = now - start;
        const progress = Math.min(elapsed / duration, 1);
        const revealCount = Math.floor(progress * original.length);
        let out = '';
        for (let i = 0; i < original.length; i += 1) {
            if (original[i] === ' ') {
                out += ' ';
            } else if (i < revealCount) {
                out += original[i];
            } else {
                out += chars[Math.floor(Math.random() * chars.length)];
            }
        }
        el.textContent = out;
        if (progress < 1) {
            requestAnimationFrame(tick);
        } else {
            el.textContent = original;
        }
    }

    if (prefersReducedMotion) {
        el.textContent = original;
        return;
    }
    requestAnimationFrame(tick);
}

if (title) {
    scrambleText(title, 1200);
    title.addEventListener('mouseenter', () => scrambleText(title, 800));
}

// -----------------------------------------
// 5) Scanline shimmer
// -----------------------------------------
if (!prefersReducedMotion) {
    const shimmer = document.createElement('div');
    shimmer.style.cssText = `
        position: fixed;
        inset: -20% 0 0 0;
        height: 120%;
        pointer-events: none;
        background: linear-gradient(
            180deg,
            transparent 0%,
            rgba(242, 236, 221,0.05) 40%,
            rgba(242, 236, 221,0.16) 50%,
            rgba(242, 236, 221,0.05) 60%,
            transparent 100%
        );
        mix-blend-mode: screen;
        opacity: 0.18;
        animation: shimmerScan 9s linear infinite;
        z-index: 2;
    `;
    document.body.appendChild(shimmer);

    const style = document.createElement('style');
    style.textContent = `
        @keyframes shimmerScan {
            0% { transform: translateY(-40%); }
            100% { transform: translateY(40%); }
        }
    `;
    document.head.appendChild(style);
}

// -----------------------------------------
// 6) Input focus FX (extra glow)
// -----------------------------------------
document.querySelectorAll('.form-input').forEach((input) => {
    input.addEventListener('focus', () => {
        card?.classList.add('focus-glow');
    });
    input.addEventListener('blur', () => {
        card?.classList.remove('focus-glow');
    });
});

// Password toggle
const passwordInput = document.getElementById('password');
const togglePassword = document.getElementById('togglePassword');
if (passwordInput && togglePassword) {
    togglePassword.addEventListener('click', () => {
        const isHidden = passwordInput.type === 'password';
        passwordInput.type = isHidden ? 'text' : 'password';
        togglePassword.querySelector('.eye-icon').textContent = isHidden ? 'HIDE' : 'VIEW';
    });
}

// Add minimal glow via injected CSS (keeps changes inside JS)
const fxStyle = document.createElement('style');
fxStyle.textContent = `
    .focus-glow {
        box-shadow:
            0 25px 70px rgba(0, 0, 0, 0.65),
            0 0 0 1px rgba(242, 236, 221, 0.34) inset,
            0 0 120px rgba(242, 236, 221, 0.26);
    }
`;
document.head.appendChild(fxStyle);

// -----------------------------------------
// Safe demo submit (no data collection)
// -----------------------------------------
const loginForm = document.getElementById('loginForm');
if (loginForm) {
    loginForm.addEventListener('submit', (e) => {
        e.preventDefault();
        submitBtn?.classList.add('loading');
        setTimeout(() => {
            submitBtn?.classList.remove('loading');
            showToast('Demo mode: no data is sent.', 'info');
        }, 900);
    });
}

function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.style.cssText = `
        position: fixed;
        top: 24px;
        right: 24px;
        max-width: 360px;
        padding: 14px 18px;
        background: ${type === 'info' ? 'rgba(242, 236, 221,0.92)' : 'rgba(177,18,18,0.92)'};
        color: #0b0b0e;
        border-radius: 12px;
        font-size: 14px;
        font-weight: 600;
        box-shadow: 0 10px 30px rgba(0,0,0,0.35);
        z-index: 9999;
        letter-spacing: 0.03em;
        animation: toastIn 220ms ease-out;
    `;
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.animation = 'toastOut 220ms ease-in';
        setTimeout(() => toast.remove(), 240);
    }, 1800);
}

const toastStyle = document.createElement('style');
toastStyle.textContent = `
    @keyframes toastIn {
        from { transform: translateY(-10px); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
    }
    @keyframes toastOut {
        from { transform: translateY(0); opacity: 1; }
        to { transform: translateY(-10px); opacity: 0; }
    }
`;
document.head.appendChild(toastStyle);
// Spatial light follow
const spatialLight = document.querySelector('.spatial-light');
if (spatialLight && !prefersReducedMotion) {
    window.addEventListener('mousemove', (e) => {
        const x = (e.clientX / window.innerWidth) * 100;
        const y = (e.clientY / window.innerHeight) * 100;
        spatialLight.style.setProperty('--lx', x + '%');
        spatialLight.style.setProperty('--ly', y + '%');
    });
}
