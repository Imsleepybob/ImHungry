(function () {
    var MAX_AGE = 60 * 60 * 24 * 400;
    var CODE_RE = /^\d{5,10}$/;
    var REGION_RE = /^[A-Z]\d{2}$/;

    function readCookie(name) {
        var match = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
        if (!match) return '';
        try { return decodeURIComponent(match[1]); } catch (e) { return match[1]; }
    }

    function writeCookie(name, value) {
        document.cookie = name + '=' + encodeURIComponent(value) + '; max-age=' + MAX_AGE + '; path=/; samesite=lax';
    }

    function clearCookie(name) {
        document.cookie = name + '=; max-age=0; path=/; samesite=lax';
    }

    function get() {
        var code = readCookie('my_school_code');
        var region = readCookie('my_school_region');
        var name = readCookie('my_school_name');
        if (!CODE_RE.test(code) || !REGION_RE.test(region) || !name) return null;
        return { code: code, region: region, name: name };
    }

    function set(code, name, region) {
        if (!CODE_RE.test(code) || !REGION_RE.test(region) || !name) return false;
        writeCookie('my_school_code', code);
        writeCookie('my_school_name', name);
        writeCookie('my_school_region', region);
        window.dispatchEvent(new CustomEvent('myschoolchange'));
        return true;
    }

    function clear() {
        clearCookie('my_school_code');
        clearCookie('my_school_name');
        clearCookie('my_school_region');
        window.dispatchEvent(new CustomEvent('myschoolchange'));
    }

    window.MySchool = { get: get, set: set, clear: clear };

    function refresh(button) {
        var mine = get();
        var active = !!mine && mine.code === button.getAttribute('data-code');
        var label = button.querySelector('[data-my-school-label]');
        var text = active ? '내 학교로 설정됨' : '내 학교로 설정';
        button.classList.toggle('is-set', active);
        button.setAttribute('aria-pressed', active ? 'true' : 'false');
        button.setAttribute('aria-label', text);
        if (label) label.textContent = text;
        button.setAttribute('title', active ? '누르면 내 학교 설정이 해제돼요' : '홈에서 바로 이 학교의 급식이 열려요');
    }

    function init() {
        var buttons = document.querySelectorAll('[data-my-school]');
        buttons.forEach(function (button) {
            refresh(button);
            button.addEventListener('click', function () {
                var mine = get();
                var code = button.getAttribute('data-code');
                if (mine && mine.code === code) {
                    clear();
                } else {
                    set(code, button.getAttribute('data-name'), button.getAttribute('data-region'));
                }
            });
        });
        window.addEventListener('myschoolchange', function () {
            buttons.forEach(refresh);
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
