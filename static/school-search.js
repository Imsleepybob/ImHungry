(function () {
    var form = document.getElementById('regionForm');
    var region = document.getElementById('region');
    var input = document.getElementById('school_name');
    var results = document.getElementById('autocomplete-results');
    if (!form || !region || !input || !results) return;

    var timer = null;
    var requestId = 0;
    var composing = false;
    var selected = -1;

    function trimIncompleteJamo(query) {
        if (!query) return query;
        var last = query.charCodeAt(query.length - 1);
        var loose = (last >= 0x3131 && last <= 0x314E) || (last >= 0x3161 && last <= 0x3163);
        return loose ? query.slice(0, -1) : query;
    }

    function hide() {
        results.style.display = 'none';
        results.textContent = '';
        selected = -1;
        requestId++;
    }

    function message(className, text) {
        results.textContent = '';
        var box = document.createElement('div');
        box.className = className;
        box.textContent = text;
        results.appendChild(box);
        results.style.display = 'block';
    }

    function go(code) {
        window.location.href = '/meal/' + encodeURIComponent(code);
    }

    function render(schools) {
        if (!schools.length) { message('autocomplete-no-results', '검색 결과가 없습니다.'); return; }
        results.textContent = '';
        schools.forEach(function (school) {
            var item = document.createElement('div');
            item.className = 'autocomplete-item';
            item.textContent = school.name;
            item.setAttribute('data-code', school.code);
            item.addEventListener('click', function () {
                if (window.Haptics) window.Haptics.select();
                go(school.code);
            });
            results.appendChild(item);
        });
        results.style.display = 'block';
        selected = -1;
    }

    function search() {
        var query = trimIncompleteJamo(input.value.trim());
        if (!query || !region.value) { hide(); return; }
        var current = ++requestId;
        message('autocomplete-loading', '검색 중...');
        fetch('/api/schools/search?q=' + encodeURIComponent(query) + '&region=' + encodeURIComponent(region.value))
            .then(function (response) {
                if (!response.ok) throw new Error('HTTP ' + response.status);
                return response.json();
            })
            .then(function (schools) { if (current === requestId) render(schools); })
            .catch(function () { if (current === requestId) message('autocomplete-error', '검색 중 오류가 발생했습니다.'); });
    }

    function schedule() {
        if (timer) clearTimeout(timer);
        timer = setTimeout(search, 300);
    }

    input.addEventListener('compositionstart', function () { composing = true; });
    input.addEventListener('compositionend', function () { composing = false; schedule(); });
    input.addEventListener('input', function () { if (!composing) schedule(); });
    input.addEventListener('keydown', function (event) {
        var items = results.querySelectorAll('.autocomplete-item');
        if (!items.length || results.style.display === 'none') return;
        if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
            event.preventDefault();
            selected = event.key === 'ArrowDown' ? Math.min(selected + 1, items.length - 1) : Math.max(selected - 1, 0);
            items.forEach(function (item, index) { item.classList.toggle('selected', index === selected); });
        } else if (event.key === 'Enter' && selected >= 0) {
            event.preventDefault();
            go(items[selected].getAttribute('data-code'));
        } else if (event.key === 'Escape') {
            hide();
        }
    });
    region.addEventListener('change', function () { hide(); if (input.value.trim()) search(); });
    document.addEventListener('click', function (event) {
        if (!input.contains(event.target) && !results.contains(event.target)) hide();
    });
    form.addEventListener('submit', function (event) {
        if (!region.value) {
            event.preventDefault();
            alert('지역을 선택해주세요.');
            region.focus();
        }
    });
})();
