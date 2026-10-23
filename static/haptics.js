(function () {
    const canVibrate = typeof navigator.vibrate === 'function';
    const ua = navigator.userAgent || '';
    const isAppEnv = ua.includes('ImHungryApp');
    const INTERACTIVE = 'button, a[href], [role="button"], summary, label, select, input[type="checkbox"], input[type="radio"], input[type="submit"], [data-haptic]';
    const ATTACHABLE = 'button, a[href], [role="button"], summary, [data-haptic-attach]';
    const AD_AREA = 'ins.kakao_ad_area, .adsbygoogle, [id^="google_ads"], [id^="aswift"]';
    const ANDROID = {
        tap: 10,
        select: 6,
        toggle: 14,
        heavy: 24,
        success: [12, 40, 22],
        warning: [18, 50, 18],
        error: [30, 50, 30, 50, 70]
    };

    let enabled = true;
    try { enabled = localStorage.getItem('imhungry_haptics') !== 'off'; } catch (e) {}

    let tappt = null;
    let tapptPromise = null;
    let lastPulse = 0;
    let lastKind = '';
    const PATTERN_KINDS = new Set(['success', 'warning', 'error', 'heavy']);
    const attached = new WeakMap();

    function reducedMotion() {
        return typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    }

    function capacitorHaptics() {
        return window.Capacitor && window.Capacitor.Plugins && window.Capacitor.Plugins.Haptics;
    }

    function loadTappt() {
        if (canVibrate || isAppEnv) return Promise.resolve(null);
        if (!tapptPromise) {
            tapptPromise = import('/static/vendor/tappt.min.js').then((mod) => {
                tappt = mod;
                if (mod.haptic.getBackend() === 'ios-switch') scanAndObserve();
                return mod;
            }).catch(() => null);
        }
        return tapptPromise;
    }

    function allowed(minGap, kind) {
        if (!enabled || reducedMotion()) return false;
        const now = performance.now();
        const elapsed = now - lastPulse;
        const upgrade = PATTERN_KINDS.has(kind) && !PATTERN_KINDS.has(lastKind) && elapsed < 200;
        if (elapsed < minGap && !upgrade) return false;
        lastPulse = now;
        lastKind = kind;
        return true;
    }

    function android(name, minGap) {
        if (!allowed(minGap, name)) return false;
        try { return navigator.vibrate(ANDROID[name]); } catch (e) { return false; }
    }

    function ios(kind, minGap) {
        if (!tappt || !allowed(minGap, kind)) return false;
        try {
            if (kind === 'success' || kind === 'warning' || kind === 'error') tappt.haptic.notify(kind);
            else tappt.haptic.selection();
            return true;
        } catch (e) {
            return false;
        }
    }

    function capacitor(kind) {
        const plugin = capacitorHaptics();
        if (!plugin) return false;
        try {
            if (kind === 'success' || kind === 'warning' || kind === 'error') plugin.notification({ type: kind.toUpperCase() });
            else if (kind === 'select') plugin.selectionChanged();
            else plugin.impact({ style: kind === 'heavy' ? 'HEAVY' : 'LIGHT' });
            return true;
        } catch (e) {
            return false;
        }
    }

    function fire(kind, minGap) {
        if (isAppEnv && capacitor(kind)) return true;
        if (canVibrate) return android(kind, minGap);
        return ios(kind, minGap);
    }

    function inAd(element) {
        return !!(element.closest && element.closest(AD_AREA));
    }

    function attachTo(element) {
        if (!tappt || attached.has(element) || element.hasAttribute('data-no-haptic') || inAd(element)) return;
        if (!element.matches(ATTACHABLE)) return;
        if (getComputedStyle(element).display === 'inline') return;
        attached.set(element, tappt.attach(element));
    }

    function scan(root) {
        if (!tappt || tappt.haptic.getBackend() !== 'ios-switch') return;
        if (root.nodeType === 1 && root.matches(ATTACHABLE)) attachTo(root);
        if (root.querySelectorAll) root.querySelectorAll(ATTACHABLE).forEach(attachTo);
    }

    function scanAndObserve() {
        scan(document.body);
        new MutationObserver((records) => {
            for (const record of records) record.addedNodes.forEach((node) => { if (node.nodeType === 1 && !node.hasAttribute('data-tappt-overlay')) scan(node); });
        }).observe(document.body, { childList: true, subtree: true });
    }

    function kindFor(target) {
        const tag = target.tagName;
        const type = (target.getAttribute('type') || '').toLowerCase();
        const custom = target.getAttribute('data-haptic');
        if (custom && ANDROID[custom]) return custom;
        if (tag === 'SELECT' || type === 'checkbox' || type === 'radio') return 'toggle';
        return 'tap';
    }

    function onClick(event) {
        if (!enabled) return;
        const target = event.target.closest ? event.target.closest(INTERACTIVE) : null;
        if (!target || target.hasAttribute('data-no-haptic') || target.disabled || target.getAttribute('aria-disabled') === 'true' || inAd(target)) return;
        if (target.tagName === 'SELECT' && !canVibrate && !isAppEnv) return;
        if (canVibrate || isAppEnv) {
            if (event.isTrusted) fire(kindFor(target), 30);
            return;
        }
        const insideOverlay = event.target.closest && event.target.closest('[data-tappt-overlay]');
        if (event.isTrusted && insideOverlay) return;
        fire(kindFor(target), 40);
    }

    const Haptics = {
        tap() { return fire('tap', 30); },
        select() { return fire('select', 22); },
        toggle() { return fire('toggle', 30); },
        heavy() { return fire('heavy', 30); },
        success() { return fire('success', 60); },
        warning() { return fire('warning', 60); },
        error() { return fire('error', 60); },
        intro(step) {
            const strength = 8 + Math.min(Math.max(step || 0, 0), 4) * 4;
            if (canVibrate) {
                if (!allowed(0, 'intro')) return false;
                try { return navigator.vibrate(strength); } catch (e) { return false; }
            }
            return ios('select', 0);
        },
        attach(element) {
            if (!tappt || tappt.haptic.getBackend() !== 'ios-switch') return () => {};
            if (!attached.has(element)) attached.set(element, tappt.attach(element));
            return () => { const off = attached.get(element); if (off) { off(); attached.delete(element); } };
        },
        setEnabled(value) {
            enabled = !!value;
            try { localStorage.setItem('imhungry_haptics', enabled ? 'on' : 'off'); } catch (e) {}
        },
        isEnabled() { return enabled; },
        backend() {
            if (isAppEnv && capacitorHaptics()) return 'capacitor';
            if (canVibrate) return 'vibration';
            return tappt ? tappt.haptic.getBackend() : 'pending';
        },
        ready: loadTappt
    };

    window.Haptics = Haptics;
    document.addEventListener('click', onClick, true);
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', loadTappt);
    else loadTappt();
})();
