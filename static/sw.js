const OFFLINE_HTML = '<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>급식알리미</title></head><body style="margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;font-family:sans-serif;text-align:center;color:#333;background:#fff"><p>인터넷에 연결되어 있지 않아요.<br>연결을 확인한 뒤 다시 시도해 주세요.</p></body></html>';

self.addEventListener('install', () => self.skipWaiting());

self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

self.addEventListener('fetch', (event) => {
    if (event.request.mode !== 'navigate') return;
    event.respondWith(fetch(event.request).catch(() => new Response(OFFLINE_HTML, {
        status: 503,
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
    })));
});

self.addEventListener('push', (event) => {
    let data = {};
    try {
        data = event.data ? event.data.json() : {};
    } catch (e) {
        data = {};
    }
    event.waitUntil(self.registration.showNotification(data.title || '급식알리미', {
        body: data.body || '',
        icon: '/static/apple-touch-icon-180x180.png',
        tag: data.tag || undefined,
        data: { url: data.url || '/' }
    }));
});

self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    const url = (event.notification.data && event.notification.data.url) || '/';
    event.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((windows) => {
        for (const client of windows) {
            if ('focus' in client) return client.focus();
        }
        return self.clients.openWindow(url);
    }));
});
