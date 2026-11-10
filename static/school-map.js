(function () {
    var box = document.getElementById('sp-map');
    if (!box) return;
    var key = box.getAttribute('data-key');
    var lat = parseFloat(box.getAttribute('data-lat'));
    var lng = parseFloat(box.getAttribute('data-lng'));
    var code = box.getAttribute('data-code') || '';
    if (!key || isNaN(lat) || isNaN(lng)) return;
    var agent = navigator.userAgent || '';
    if (navigator.webdriver || /bot|crawl|spider|slurp|yeti|daum|mediapartners|lighthouse|facebookexternalhit|headless/i.test(agent)) return;

    var started = false;

    function track(name) {
        var body = JSON.stringify({ event: name, value: code });
        try {
            if (navigator.sendBeacon) {
                navigator.sendBeacon('/api/track', new Blob([body], { type: 'application/json' }));
            } else {
                fetch('/api/track', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body, keepalive: true });
            }
        } catch (e) {}
    }

    function showState(message) {
        box.textContent = '';
        var text = document.createElement('p');
        text.className = 'sp-map-state';
        text.textContent = message;
        box.appendChild(text);
    }

    function fail() {
        showState('지도를 불러오지 못했어요. 아래 링크로 확인해 주세요.');
        track('school_map_fail');
    }

    function render() {
        try {
            window.kakao.maps.load(function () {
                try {
                    box.textContent = '';
                    var center = new window.kakao.maps.LatLng(lat, lng);
                    var map = new window.kakao.maps.Map(box, { center: center, level: 3 });
                    new window.kakao.maps.Marker({ position: center, map: map });
                    box.classList.add('is-ready');
                    track('school_map_load');
                } catch (e) {
                    fail();
                }
            });
        } catch (e) {
            fail();
        }
    }

    function start() {
        if (started) return;
        started = true;
        var script = document.createElement('script');
        script.src = 'https://dapi.kakao.com/v2/maps/sdk.js?appkey=' + encodeURIComponent(key) + '&autoload=false';
        script.async = true;
        script.onload = render;
        script.onerror = fail;
        document.head.appendChild(script);
    }

    if ('IntersectionObserver' in window) {
        var observer = new IntersectionObserver(function (entries) {
            for (var i = 0; i < entries.length; i++) {
                if (entries[i].isIntersecting) {
                    observer.disconnect();
                    start();
                    return;
                }
            }
        }, { rootMargin: '200px' });
        observer.observe(box);
    } else {
        start();
    }
})();
