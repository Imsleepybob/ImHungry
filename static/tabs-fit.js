(function () {
    var nav = document.querySelector('.sp-tabs');
    if (!nav) return;
    var tabs = Array.prototype.slice.call(nav.querySelectorAll('.sp-tab[data-short]'));
    if (!tabs.length) return;

    function textWidth(tab) {
        var range = document.createRange();
        range.selectNodeContents(tab);
        return range.getBoundingClientRect().width;
    }

    function fit(tab) {
        var long = tab.getAttribute('data-long');
        var short = tab.getAttribute('data-short');
        var wasShort = tab.textContent === short;
        if (wasShort) tab.textContent = long;
        var style = getComputedStyle(tab);
        var room = tab.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
        var previous = tab.style.whiteSpace;
        tab.style.whiteSpace = 'nowrap';
        var needShort = textWidth(tab) > room + 0.5;
        tab.style.whiteSpace = previous;
        if (needShort) {
            tab.textContent = short;
            tab.setAttribute('aria-label', long);
        } else {
            tab.removeAttribute('aria-label');
        }
    }

    function run() { tabs.forEach(fit); }

    run();
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(run);
    if (typeof ResizeObserver === 'function') {
        var lastWidth = nav.clientWidth;
        new ResizeObserver(function () {
            if (nav.clientWidth !== lastWidth) {
                lastWidth = nav.clientWidth;
                run();
            }
        }).observe(nav);
    } else {
        window.addEventListener('resize', run);
    }
})();
