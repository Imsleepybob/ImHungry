(function () {
    const FOODS = [
        ['🍕', '피자'], ['🍔', '햄버거'], ['🍟', '감자튀김'], ['🌭', '핫도그'], ['🌮', '타코'],
        ['🍣', '초밥'], ['🍜', '라멘'], ['🍱', '도시락'], ['🥟', '만두'], ['🍛', '카레'],
        ['🍝', '파스타'], ['🥗', '샐러드'], ['🍗', '치킨'], ['🥪', '샌드위치'], ['🍙', '주먹밥'],
        ['🥞', '팬케이크'], ['🍰', '케이크'], ['🍩', '도넛'], ['🍦', '아이스크림'], ['🍓', '딸기']
    ];
    const ROW = 76;
    const CYCLE = FOODS.length * ROW;
    const DECAY = 0.002;
    const SETTLE = 0.014;
    const MIN_V = 0.05;
    const MAX_V = 5;
    const FRICTION = 0.0004;
    const DRAG = 0.0005;
    const RAMP = 0.25;
    const STEP = 4;
    const STOP_V = 0.02;
    const TARGETS = '.today-meal-type, .today-meal-title, .meal-title';
    const EMOJI = /\p{Extended_Pictographic}\uFE0F?/gu;

    const CLOSE_ICON = '<svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden="true"><path d="M3.5 3.5l11 11M14.5 3.5l-11 11" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>';
    const CSS = `
.egg-emoji { cursor: pointer; display: inline-block; -webkit-tap-highlight-color: transparent; user-select: none; transition: scale 0.15s ease; animation: eggHint 3.6s ease-in-out var(--egg-delay, 0s) infinite; }
@media (hover: hover) { .egg-emoji:hover { scale: 1.25; } }
.egg-emoji:active { scale: 1.25; }
.egg-emoji.egg-pop { animation: eggPop 0.45s cubic-bezier(0.34, 1.56, 0.64, 1), eggHint 3.6s ease-in-out calc(0.45s + var(--egg-delay, 0s)) infinite; }
@keyframes eggHint { 0%, 58%, 90%, 100% { transform: none; } 64% { transform: scale(1.2) rotate(-10deg); } 70% { transform: scale(1.2) rotate(10deg); } 76% { transform: scale(1.15) rotate(-7deg); } 83% { transform: scale(1.1) rotate(5deg); } }
@keyframes eggPop { 0% { transform: scale(0.4); } 100% { transform: scale(1); } }
.egg-overlay { position: fixed; inset: 0; z-index: 10000; display: flex; align-items: center; justify-content: center; opacity: 0; visibility: hidden; transition: opacity 0.3s ease, visibility 0.3s; touch-action: none; overscroll-behavior: contain; background: color-mix(in srgb, var(--bg-container, #fff) 78%, transparent); -webkit-backdrop-filter: blur(26px) saturate(1.4); backdrop-filter: blur(26px) saturate(1.4); }
.egg-overlay.show { opacity: 1; visibility: visible; }
.egg-close { position: absolute; top: max(16px, env(safe-area-inset-top)); right: 16px; width: 40px; height: 40px; border: none; border-radius: 50%; background: var(--bg-secondary, rgba(120,120,128,0.16)); color: var(--text-secondary, #666); display: flex; align-items: center; justify-content: center; cursor: pointer; }
.egg-stage { width: min(100%, 420px); padding: 0 24px; text-align: center; display: flex; flex-direction: column; align-items: center; }
.egg-preview { display: flex; flex-direction: column; align-items: center; gap: 4px; min-height: 130px; opacity: 0; transform: scale(0.9); transition: opacity 0.4s ease, transform 0.4s ease; }
.egg-overlay.intro-3 .egg-preview { opacity: 1; transform: scale(1); }
.egg-preview-emoji { font-size: 84px; line-height: 1.1; filter: drop-shadow(0 8px 10px rgba(0, 0, 0, 0.12)); }
.egg-preview-emoji.bump { animation: eggBump 0.18s ease-out; }
@keyframes eggBump { 0% { transform: scale(0.84); } 55% { transform: scale(1.08); } 100% { transform: scale(1); } }
.egg-preview-emoji.land { animation: eggLand 0.28s ease-out; }
@keyframes eggLand { 0% { transform: scale(1); } 10% { transform: scale(1.22); } 22% { transform: scale(0.95); } 38% { transform: scale(1.14); } 60% { transform: scale(0.99); } 100% { transform: scale(1); } }
.egg-preview-name { font-size: 17px; font-weight: 700; color: var(--text-primary, #202124); letter-spacing: -0.02em; }
.egg-roller { position: relative; width: 100%; height: min(46vh, 340px); margin: 10px 0 18px; overflow: hidden; cursor: grab; user-select: none; touch-action: none; outline: none; -webkit-mask-image: linear-gradient(transparent, #000 22%, #000 78%, transparent); mask-image: linear-gradient(transparent, #000 22%, #000 78%, transparent); opacity: 0; transition: opacity 0.4s ease; }
.egg-overlay.intro-3 .egg-roller { opacity: 1; }
.egg-roller.dragging { cursor: grabbing; }
.egg-selection { position: absolute; left: 12px; right: 12px; top: 50%; height: 76px; transform: translateY(-50%); border-radius: 20px; background: color-mix(in srgb, var(--accent-color, #faa41a) 14%, transparent); border: 1px solid color-mix(in srgb, var(--accent-color, #faa41a) 28%, transparent); }
.egg-items { position: absolute; inset: 0; }
.egg-item { position: absolute; left: 0; right: 0; top: 50%; height: 76px; margin-top: -38px; display: flex; align-items: center; justify-content: center; font-size: 42px; will-change: transform, opacity; pointer-events: none; }
.egg-title, .egg-hint { margin: 0; opacity: 0; transform: translateY(10px); transition: opacity 0.45s ease, transform 0.45s ease; }
.egg-title { font-size: 22px; font-weight: 750; letter-spacing: -0.04em; color: var(--text-primary, #202124); }
.egg-hint { margin-top: 6px; font-size: 14px; color: var(--text-secondary, #77777d); }
.egg-overlay.intro-1 .egg-title, .egg-overlay.intro-2 .egg-hint { opacity: 1; transform: translateY(0); }
@media (prefers-reduced-motion: reduce) { .egg-emoji { transition: none; } .egg-overlay, .egg-title, .egg-hint, .egg-preview, .egg-roller { transition: none; } .egg-emoji, .egg-emoji.egg-pop, .egg-preview-emoji.bump, .egg-preview-emoji.land { animation: none; } }
`;

    let overlay = null;
    let rollerEl = null;
    let itemsEl = null;
    let previewEmoji = null;
    let previewName = null;
    let nodes = [];
    let source = null;
    let lastFocus = null;
    let position = 0;
    let velocity = 0;
    let dragging = false;
    let frame = 0;
    let active = 0;
    let lastY = 0;
    let lastTime = 0;
    let introTimers = [];
    let releaseAttach = null;
    let landTimer = 0;
    let moved = false;
    let reported = false;

    const HAPTIC_FALLBACK = { tick: 'select', land: 'success' };

    function haptic(name, arg) {
        const api = window.Haptics;
        if (!api) return;
        const fn = typeof api[name] === 'function' ? api[name] : api[HAPTIC_FALLBACK[name]];
        if (typeof fn === 'function') fn.call(api, arg);
    }

    function wrap(n) {
        return ((n % FOODS.length) + FOODS.length) % FOODS.length;
    }

    function reduced() {
        return typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    }

    function wrapEmojis(root) {
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
        const textNodes = [];
        while (walker.nextNode()) textNodes.push(walker.currentNode);
        textNodes.forEach((node) => {
            if (!node.nodeValue || !EMOJI.test(node.nodeValue)) return;
            EMOJI.lastIndex = 0;
            if (node.parentElement && node.parentElement.classList.contains('egg-emoji')) return;
            const fragment = document.createDocumentFragment();
            let last = 0;
            node.nodeValue.replace(EMOJI, (match, offset) => {
                if (offset > last) fragment.appendChild(document.createTextNode(node.nodeValue.slice(last, offset)));
                const span = document.createElement('span');
                span.className = 'egg-emoji';
                span.style.setProperty('--egg-delay', (Math.random() * 3).toFixed(2) + 's');
                span.textContent = match;
                fragment.appendChild(span);
                last = offset + match.length;
                return match;
            });
            if (last < node.nodeValue.length) fragment.appendChild(document.createTextNode(node.nodeValue.slice(last)));
            node.parentNode.replaceChild(fragment, node);
        });
    }

    function injectStyle() {
        if (document.getElementById('egg-style')) return;
        const style = document.createElement('style');
        style.id = 'egg-style';
        style.textContent = CSS;
        document.head.appendChild(style);
    }

    function buildOverlay() {
        injectStyle();

        overlay = document.createElement('div');
        overlay.className = 'egg-overlay';
        overlay.setAttribute('role', 'dialog');
        overlay.setAttribute('aria-modal', 'true');
        overlay.setAttribute('aria-label', '음식 롤러');
        overlay.innerHTML =
            '<button type="button" class="egg-close" aria-label="닫기">' + CLOSE_ICON + '</button>' +
            '<div class="egg-stage">' +
            '<div class="egg-preview" aria-live="polite"><span class="egg-preview-emoji"></span><span class="egg-preview-name"></span></div>' +
            '<div class="egg-roller" tabindex="0" role="listbox" aria-label="음식 선택 롤러"><div class="egg-selection"></div><div class="egg-items"></div></div>' +
            '<p class="egg-title">점메추 ㄱㄱ</p>' +
            '<p class="egg-hint">위아래로 드래그하거나 스크롤해 보세요</p>' +
            '</div>';
        document.body.appendChild(overlay);

        rollerEl = overlay.querySelector('.egg-roller');
        itemsEl = overlay.querySelector('.egg-items');
        previewEmoji = overlay.querySelector('.egg-preview-emoji');
        previewName = overlay.querySelector('.egg-preview-name');
        nodes = FOODS.map(([emoji]) => {
            const el = document.createElement('div');
            el.className = 'egg-item';
            el.setAttribute('role', 'option');
            el.textContent = emoji;
            itemsEl.appendChild(el);
            return el;
        });

        overlay.querySelector('.egg-close').addEventListener('click', () => close());
        overlay.addEventListener('click', (event) => {
            if (event.target === overlay || event.target.classList.contains('egg-stage')) close();
        });
        overlay.addEventListener('touchmove', (event) => event.preventDefault(), { passive: false });
        rollerEl.addEventListener('pointerdown', onPointerDown);
        rollerEl.addEventListener('pointermove', onPointerMove);
        rollerEl.addEventListener('pointerup', onRelease);
        rollerEl.addEventListener('pointercancel', onRelease);
        rollerEl.addEventListener('wheel', onWheel, { passive: false });
        rollerEl.addEventListener('keydown', onKey);
        document.addEventListener('keydown', (event) => {
            if (overlay.classList.contains('show') && event.key === 'Escape') close();
        });
    }

    function paint() {
        nodes.forEach((el, i) => {
            const d = ((i * ROW - position + CYCLE / 2) % CYCLE + CYCLE) % CYCLE - CYCLE / 2;
            el.style.transform = `translate3d(0,${d}px,0) scale(${Math.max(0.76, 1 - Math.abs(d) / 900)})`;
            el.style.opacity = String(Math.max(0.12, 1 - Math.abs(d) / 250));
            el.setAttribute('aria-selected', Math.abs(d) < ROW * 0.48 ? 'true' : 'false');
        });
        const next = wrap(Math.round(position / ROW));
        if (next !== active) {
            active = next;
            moved = true;
            showPreview();
            haptic('tick');
        }
    }

    function showPreview() {
        previewEmoji.textContent = FOODS[active][0];
        previewName.textContent = FOODS[active][1];
        previewEmoji.classList.remove('bump', 'land');
        void previewEmoji.offsetWidth;
        if (!reduced()) previewEmoji.classList.add('bump');
    }

    function land() {
        if (!moved) return;
        moved = false;
        previewEmoji.classList.remove('bump', 'land');
        void previewEmoji.offsetWidth;
        if (!reduced()) previewEmoji.classList.add('land');
        haptic('land');
    }

    function simulate(speed, mult) {
        const pos = [0];
        const vel = [speed];
        let v = speed;
        let x = 0;
        while (v > STOP_V && pos.length < 3000) {
            v = Math.max(0, v - mult * (FRICTION * v + DRAG * Math.min(1, v / RAMP)) * STEP);
            x += v * STEP;
            pos.push(x);
            vel.push(v);
        }
        return { pos, vel };
    }

    function flickPlan(v0, x0) {
        const dir = Math.sign(v0);
        const speed = Math.abs(v0);
        const natural = simulate(speed, 1).pos;
        let target = Math.round((x0 + dir * natural[natural.length - 1]) / ROW) * ROW;
        let ahead = dir > 0 ? Math.ceil(x0 / ROW) * ROW : Math.floor(x0 / ROW) * ROW;
        if (Math.abs(ahead - x0) < 1) ahead += dir * ROW;
        if ((target - ahead) * dir < 0) target = ahead;
        const dist = Math.abs(target - x0);
        let lo = 0.3;
        let hi = 3;
        for (let n = 0; n < 16; n++) {
            const mid = (lo + hi) / 2;
            const pos = simulate(speed, mid).pos;
            if (pos[pos.length - 1] > dist) lo = mid; else hi = mid;
        }
        const mult = (lo + hi) / 2;
        const run = simulate(speed, mult);
        const reach = run.pos[run.pos.length - 1];
        if (mult < 0.32 || mult > 2.9 || Math.abs(reach - dist) > 1) return null;
        return {
            target,
            end: (run.pos.length - 1) * STEP,
            at(t) {
                const f = t / STEP;
                const i = Math.min(Math.floor(f), run.pos.length - 2);
                const r = f - i;
                return [x0 + dir * (run.pos[i] + (run.pos[i + 1] - run.pos[i]) * r), dir * (run.vel[i] + (run.vel[i + 1] - run.vel[i]) * r)];
            }
        };
    }

    function springPlan(v0, x0) {
        const flick = Math.abs(v0) >= MIN_V;
        let target = Math.round(x0 / ROW) * ROW;
        if (flick) {
            const dir = Math.sign(v0);
            let ahead = dir > 0 ? Math.ceil(x0 / ROW) * ROW : Math.floor(x0 / ROW) * ROW;
            if (Math.abs(ahead - x0) < 1) ahead += dir * ROW;
            target = Math.round((x0 + v0 / DECAY) / ROW) * ROW;
            if ((target - ahead) * dir < 0) target = ahead;
        }
        const A = x0 - target;
        if (Math.abs(A) < 0.01) return { target, end: 0 };
        const omega = Math.max(flick ? DECAY : SETTLE, Math.abs(v0) / Math.abs(A), Math.log(Math.max(Math.abs(A), 1) / 0.5) / 3000);
        const B = v0 + omega * A;
        let end = 0;
        while (end < 4000 && Math.abs((A + B * end) * Math.exp(-omega * end)) > 0.5) end += 8;
        return {
            target,
            end,
            at(t) {
                const e = Math.exp(-omega * t);
                return [target + (A + B * t) * e, (B - omega * (A + B * t)) * e];
            }
        };
    }

    function animate() {
        cancelAnimationFrame(frame);
        clearTimeout(landTimer);
        const v0 = Math.max(-MAX_V, Math.min(MAX_V, velocity / 16.67));
        const plan = (Math.abs(v0) >= MIN_V && flickPlan(v0, position)) || springPlan(v0, position);
        if (!plan.end) {
            position = plan.target;
            velocity = 0;
            paint();
            land();
            return;
        }
        const start = performance.now();
        const tick = (now) => {
            const t = Math.max(0, now - start);
            if (t >= plan.end) {
                position = plan.target;
                velocity = 0;
                paint();
                land();
                return;
            }
            const state = plan.at(t);
            position = state[0];
            velocity = state[1] * 16.67;
            paint();
            frame = requestAnimationFrame(tick);
        };
        frame = requestAnimationFrame(tick);
        if (plan.end <= 900 && window.Haptics && typeof window.Haptics.backend === 'function' && window.Haptics.backend() === 'ios-switch') landTimer = setTimeout(land, plan.end);
    }

    function report() {
        if (reported || typeof window.trackEvent !== 'function') return;
        reported = true;
        const api = window.Haptics;
        const haptics = api && typeof api.backend === 'function' ? api.backend() : 'none';
        const input = window.matchMedia && window.matchMedia('(pointer: coarse)').matches ? 'touch' : 'mouse';
        const mode = (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) || navigator.standalone ? 'pwa' : 'web';
        try { window.trackEvent('egg_open', [haptics, input, mode].join('|')); } catch (e) {}
    }

    function onPointerDown(event) {
        dragging = true;
        rollerEl.classList.add('dragging');
        if (rollerEl.setPointerCapture) { try { rollerEl.setPointerCapture(event.pointerId); } catch (e) {} }
        lastY = event.clientY;
        lastTime = performance.now();
        velocity = 0;
        cancelAnimationFrame(frame);
        clearTimeout(landTimer);
    }

    function onPointerMove(event) {
        if (!dragging) return;
        const now = performance.now();
        const dy = event.clientY - lastY;
        const dt = Math.max(1, now - lastTime);
        position -= dy * 1.25;
        velocity = velocity * 0.25 + (-dy / dt) * 16.67 * 1.55 * 0.75;
        lastY = event.clientY;
        lastTime = now;
        paint();
    }

    function onRelease() {
        if (!dragging) return;
        dragging = false;
        rollerEl.classList.remove('dragging');
        if (performance.now() - lastTime > 80) velocity = 0;
        animate();
    }

    function onWheel(event) {
        event.preventDefault();
        velocity += Math.max(-18, Math.min(18, event.deltaY * 0.06));
        animate();
    }

    function onKey(event) {
        if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
            event.preventDefault();
            position += (event.key === 'ArrowDown' ? 1 : -1) * ROW;
            paint();
        }
    }

    function clearIntro() {
        introTimers.forEach(clearTimeout);
        introTimers = [];
        overlay.classList.remove('intro-1', 'intro-2', 'intro-3');
    }

    function playIntro() {
        clearIntro();
        const steps = [[0, 1], [420, 2], [840, 3]];
        steps.forEach(([delay, step], index) => {
            const run = () => {
                overlay.classList.add('intro-' + step);
                if (index > 0) haptic('intro', index);
            };
            if (reduced()) run();
            else introTimers.push(setTimeout(run, delay));
        });
    }

    function open(emojiElement) {
        if (!overlay) buildOverlay();
        source = emojiElement;
        lastFocus = document.activeElement;
        const current = FOODS.findIndex(([emoji]) => emoji === emojiElement.textContent);
        position = (current >= 0 ? current : Math.floor(Math.random() * FOODS.length)) * ROW;
        velocity = 0;
        moved = false;
        active = wrap(Math.round(position / ROW));
        showPreview();
        paint();
        haptic('tap');
        report();
        document.body.style.overflow = 'hidden';
        overlay.classList.add('show');
        if (window.Haptics && typeof window.Haptics.attach === 'function') releaseAttach = window.Haptics.attach(rollerEl);
        playIntro();
        setTimeout(() => rollerEl.focus({ preventScroll: true }), 50);
    }

    function close() {
        if (!overlay || !overlay.classList.contains('show')) return;
        cancelAnimationFrame(frame);
        clearTimeout(landTimer);
        dragging = false;
        clearIntro();
        overlay.classList.remove('show');
        document.body.style.overflow = '';
        if (releaseAttach) { releaseAttach(); releaseAttach = null; }
        if (source) {
            source.textContent = FOODS[active][0];
            source.classList.remove('egg-pop');
            void source.offsetWidth;
            if (!reduced()) source.classList.add('egg-pop');
        }
        if (lastFocus && lastFocus.focus) { try { lastFocus.focus({ preventScroll: true }); } catch (e) {} }
        source = null;
    }

    function init() {
        injectStyle();
        document.querySelectorAll(TARGETS).forEach(wrapEmojis);
        document.addEventListener('click', (event) => {
            const target = event.target.closest ? event.target.closest('.egg-emoji') : null;
            if (!target) return;
            open(target);
        });
    }

    window.FoodRoller = { open, close, _foods: FOODS };
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();
