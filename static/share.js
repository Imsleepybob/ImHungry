(function () {
    document.addEventListener('click', async function (event) {
        var button = event.target.closest('[data-share]');
        if (!button) return;
        var url = button.getAttribute('data-url') || window.location.href;
        var title = button.getAttribute('data-title') || document.title;
        var text = button.getAttribute('data-text') || '';
        if (navigator.share) {
            try { await navigator.share({ title: title, text: text, url: url }); } catch (e) {}
            return;
        }
        try {
            await navigator.clipboard.writeText(url);
            alert('공유 링크가 클립보드에 복사되었습니다.');
        } catch (e) {
            alert('공유 기능을 지원하지 않는 브라우저입니다.');
        }
    });
})();
