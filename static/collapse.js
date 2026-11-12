(function () {
    var DURATION = 260;
    var EASING = 'cubic-bezier(0.22, 0.8, 0.3, 1)';

    function reduced() {
        return typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    }

    function reset(body) {
        body.style.height = '';
        body.style.transition = '';
    }

    function run(body, from, to, done, details) {
        clearTimeout(details._collapseTimer);
        body.style.transition = 'none';
        body.style.height = from + 'px';
        void body.offsetHeight;
        body.style.transition = 'height ' + DURATION + 'ms ' + EASING;
        body.style.height = to + 'px';
        details._collapseTimer = setTimeout(function () {
            reset(body);
            if (done) done();
        }, DURATION + 20);
    }

    document.addEventListener('click', function (event) {
        var summary = event.target.closest ? event.target.closest('summary') : null;
        if (!summary) return;
        var details = summary.parentElement;
        if (!details || !details.matches('details.meal-detail')) return;
        event.preventDefault();
        var body = details.querySelector(':scope > .meal-detail-body');
        if (!body || reduced()) {
            details.open = !details.open;
            return;
        }
        var closing = details.open && !details.classList.contains('is-closing');
        if (closing) {
            details.classList.add('is-closing');
            run(body, body.getBoundingClientRect().height, 0, function () {
                details.open = false;
                details.classList.remove('is-closing');
            }, details);
        } else {
            var from = details.open ? body.getBoundingClientRect().height : 0;
            details.classList.remove('is-closing');
            details.open = true;
            run(body, from, body.scrollHeight, null, details);
        }
    });
})();
