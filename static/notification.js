const NotificationManager = {

    _installEvent: null,

    // ---- 환경 / PWA 판별 ----

    isAppEnvironment() {
        return navigator.userAgent.includes('ImHungryApp');
    },

    getEnvironment() {
        const ua = navigator.userAgent || '';
        const isIPadOS = navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1;
        const platform = (/iPhone|iPad|iPod/i.test(ua) || isIPadOS) ? 'ios' : (/Android/i.test(ua) ? 'android' : 'desktop');
        const inApp = /KAKAOTALK|NAVER\(inapp|FBAN|FBAV|Instagram|Line\/|DaumApps|everytimeApp|Snapchat|Twitter|MicroMessenger|; wv\)/i.test(ua);
        let browser = 'other';
        if (/SamsungBrowser/i.test(ua)) browser = 'samsung';
        else if (/EdgA|EdgiOS|Edg\//i.test(ua)) browser = 'edge';
        else if (/Whale/i.test(ua)) browser = 'whale';
        else if (/OPR\/|OPiOS|Opera/i.test(ua)) browser = 'opera';
        else if (/Firefox|FxiOS/i.test(ua)) browser = 'firefox';
        else if (/DuckDuckGo|GSA\//i.test(ua)) browser = 'other';
        else if (/CriOS|Chrome\//i.test(ua)) browser = 'chrome';
        else if (/Safari\//i.test(ua)) browser = 'safari';
        const match = ua.match(/OS (\d+)[_.](\d+)/);
        const iosVersion = (platform === 'ios' && match) ? [parseInt(match[1], 10), parseInt(match[2], 10)] : null;
        return { platform, browser, inApp, iosVersion };
    },

    isIOSVersionUnsupported(env) {
        const v = (env || this.getEnvironment()).iosVersion;
        return !!v && (v[0] < 16 || (v[0] === 16 && v[1] < 4));
    },

    isStandalone() {
        const modes = ['standalone', 'fullscreen', 'minimal-ui', 'window-controls-overlay'];
        const byMedia = typeof window.matchMedia === 'function' && modes.some((m) => window.matchMedia(`(display-mode: ${m})`).matches);
        return byMedia || window.navigator.standalone === true;
    },

    hasPwaFlag() {
        try {
            return sessionStorage.getItem('imhungry_pwa') === '1';
        } catch (e) {
            return false;
        }
    },

    isPWA() {
        return !this.isAppEnvironment() && (this.isStandalone() || this.hasPwaFlag());
    },

    markPwaFromUrl() {
        const params = new URLSearchParams(location.search);
        if (params.get('source') !== 'pwa') return;
        try { sessionStorage.setItem('imhungry_pwa', '1'); } catch (e) {}
        params.delete('source');
        const query = params.toString();
        history.replaceState(null, '', location.pathname + (query ? '?' + query : '') + location.hash);
    },

    getDeviceId() {
        try {
            let id = localStorage.getItem('imhungry_device_id');
            if (!id) {
                const bytes = new Uint8Array(8);
                crypto.getRandomValues(bytes);
                id = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
                localStorage.setItem('imhungry_device_id', id);
            }
            return id;
        } catch (e) {
            return '';
        }
    },

    getCookieValue(name) {
        const match = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
        return match ? decodeURIComponent(match[1]) : '';
    },

    trackPwaVisit() {
        if (!this.isPWA()) return;
        const code = this.getCookieValue('school_code');
        const key = 'imhungry_pwa_ping:' + code;
        try {
            if (sessionStorage.getItem(key)) return;
            sessionStorage.setItem(key, '1');
        } catch (e) {}
        fetch('/api/track', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ event: 'pwa_visit', value: code, uid: this.getDeviceId() }),
            keepalive: true
        }).catch(() => {});
    },

    // ---- PWA 설치 안내 ----

    canPromptInstall() {
        return !!this._installEvent;
    },

    async promptInstall() {
        const installEvent = this._installEvent;
        if (!installEvent) return 'unavailable';
        this._installEvent = null;
        installEvent.prompt();
        const choice = await installEvent.userChoice;
        return choice.outcome;
    },

    getInstallGuide() {
        const env = this.getEnvironment();
        const closeAction = { id: 'close', label: '닫기' };
        const copyAction = { id: 'copy', label: '링크 복사', primary: true };
        const openApp = '설치된 급식알리미 앱을 열고 알림 버튼을 누르면 알림 권한을 요청하고, 받을 시간을 설정할 수 있어요.';
        const installed = '이미 설치했다면 설치된 급식알리미 앱에서 알림 버튼을 눌러 주세요.';

        if (this.isIOSVersionUnsupported(env)) {
            return {
                title: '이 기기에서는 알림을 받을 수 없어요',
                desc: 'iOS 16.4 이상에서만 홈 화면 앱 알림을 지원해요. iOS를 업데이트한 뒤 다시 시도해 주세요.',
                steps: [],
                actions: [closeAction]
            };
        }

        if (env.inApp) {
            if (env.platform === 'ios') {
                return {
                    title: 'Safari에서 열어 주세요',
                    desc: '지금 보고 있는 앱 안의 브라우저에서는 설치할 수 없어요.',
                    steps: [
                        '아래 링크 복사 버튼을 눌러 주소를 복사하세요.',
                        'Safari를 열고 주소창에 붙여넣어 접속하세요.',
                        'Safari의 공유 버튼에서 홈 화면에 추가를 선택하세요.',
                        openApp
                    ],
                    actions: [copyAction, closeAction]
                };
            }
            return {
                title: '기본 브라우저에서 열어 주세요',
                desc: '지금 보고 있는 앱 안의 브라우저에서는 설치할 수 없어요.',
                steps: [
                    '화면의 메뉴에서 다른 브라우저로 열기를 선택하세요.',
                    '또는 아래 링크 복사 버튼으로 주소를 복사해 Chrome에 붙여넣으세요.',
                    '브라우저 메뉴에서 앱 설치 또는 홈 화면에 추가를 선택하세요.',
                    openApp
                ],
                actions: [copyAction, closeAction]
            };
        }

        if (env.platform === 'ios') {
            if (env.browser === 'safari') {
                return {
                    title: '앱으로 설치하면 알림을 받을 수 있어요',
                    desc: 'iPhone과 iPad에서는 홈 화면에 추가한 앱에서만 알림을 받을 수 있어요.',
                    steps: [
                        'Safari 하단의 공유 버튼을 누르세요. 보이지 않으면 점 세 개 메뉴 안에 있어요.',
                        '목록에서 홈 화면에 추가를 선택하세요.',
                        '오른쪽 위의 추가를 누르세요.',
                        openApp
                    ],
                    actions: [closeAction]
                };
            }
            return {
                title: 'Safari에서 설치해 주세요',
                desc: '이 브라우저에서는 알림을 받을 수 있는 앱으로 설치할 수 없어요.',
                steps: [
                    '아래 링크 복사 버튼을 눌러 주소를 복사하세요.',
                    'Safari를 열고 주소창에 붙여넣어 접속하세요.',
                    'Safari의 공유 버튼에서 홈 화면에 추가를 선택하세요.',
                    openApp
                ],
                actions: [copyAction, closeAction]
            };
        }

        if (this.canPromptInstall()) {
            return {
                title: '앱으로 설치하면 알림을 받을 수 있어요',
                desc: '설치 버튼을 누르면 급식알리미 앱이 추가돼요. 설치한 뒤 앱에서 알림 버튼을 눌러 주세요.',
                steps: [],
                actions: [{ id: 'install', label: '설치', primary: true }, closeAction]
            };
        }

        if (env.platform === 'android') {
            if (env.browser === 'firefox') {
                return {
                    title: '앱으로 설치하면 알림을 받을 수 있어요',
                    desc: installed,
                    steps: ['브라우저 메뉴(점 세 개)를 누르세요.', '설치를 선택하세요.', openApp],
                    actions: [closeAction]
                };
            }
            if (env.browser === 'samsung') {
                return {
                    title: '앱으로 설치하면 알림을 받을 수 있어요',
                    desc: installed,
                    steps: ['브라우저 메뉴(줄 세 개)를 누르세요.', '메뉴에서 홈 화면에 추가 또는 앱 설치 항목을 선택하세요.', openApp],
                    actions: [closeAction]
                };
            }
            return {
                title: '앱으로 설치하면 알림을 받을 수 있어요',
                desc: installed,
                steps: [
                    '브라우저 오른쪽 위 메뉴(점 세 개)를 누르세요.',
                    '앱 설치 또는 홈 화면에 추가를 선택하세요.',
                    '설치를 눌러 완료하세요.',
                    openApp
                ],
                actions: [closeAction]
            };
        }

        if (env.browser === 'safari') {
            return {
                title: '앱으로 설치하면 알림을 받을 수 있어요',
                desc: 'macOS Sonoma(14) 이상의 Safari에서 설치할 수 있어요.',
                steps: ['화면 위쪽 메뉴 막대에서 파일을 선택하세요.', 'Dock에 추가를 선택하세요.', openApp],
                actions: [closeAction]
            };
        }
        if (env.browser === 'firefox') {
            return {
                title: '이 브라우저에서는 앱 설치를 지원하지 않아요',
                desc: 'Chrome 또는 Edge에서 접속하면 설치할 수 있어요.',
                steps: [],
                actions: [copyAction, closeAction]
            };
        }
        return {
            title: '앱으로 설치하면 알림을 받을 수 있어요',
            desc: installed,
            steps: [
                '주소창 오른쪽의 설치 아이콘을 클릭하세요.',
                '보이지 않으면 브라우저 메뉴에서 앱 설치 또는 앱으로 설치를 선택하세요.',
                '설치를 눌러 완료하세요.',
                openApp
            ],
            actions: [closeAction]
        };
    },

    getInstalledGuide() {
        return {
            title: '설치가 완료되었어요',
            desc: '설치된 급식알리미 앱을 열고 알림 버튼을 눌러 알림을 설정해 주세요.',
            steps: [],
            actions: [{ id: 'close', label: '확인', primary: true }]
        };
    },

    getDeniedGuide() {
        const platform = this.getEnvironment().platform;
        const where = {
            ios: '설정 앱에서 알림 항목의 급식알리미를 열어 알림 허용을 켜 주세요.',
            android: '기기 설정의 앱 알림에서 급식알리미(또는 사용 중인 브라우저)의 알림을 허용해 주세요.',
            desktop: '앱 창 또는 주소창의 정보 아이콘에서 사이트 설정을 열어 알림을 허용으로 바꿔 주세요.'
        }[platform];
        return {
            title: '알림이 차단되어 있어요',
            desc: where + ' 설정을 바꾼 뒤 알림 버튼을 다시 눌러 주세요.',
            steps: [],
            actions: [{ id: 'close', label: '확인', primary: true }]
        };
    },

    getPermissionDismissedGuide() {
        return {
            title: '알림 권한이 필요해요',
            desc: '권한 요청 창에서 허용을 선택해야 알림을 설정할 수 있어요. 알림 버튼을 다시 눌러 주세요.',
            steps: [],
            actions: [{ id: 'close', label: '확인', primary: true }]
        };
    },

    getUnsupportedGuide() {
        const unsupportedIOS = this.isIOSVersionUnsupported();
        return {
            title: '이 환경에서는 알림을 지원하지 않아요',
            desc: unsupportedIOS
                ? 'iOS 16.4 이상으로 업데이트한 뒤 다시 시도해 주세요.'
                : '최신 버전의 Chrome, Edge, Safari에서 설치한 앱으로 이용해 주세요.',
            steps: [],
            actions: [{ id: 'close', label: '확인', primary: true }]
        };
    },

    // ---- 웹 푸시 ----

    isAvailable() {
        return !!(window.Capacitor?.Plugins?.LocalNotifications);
    },

    isWebPushSupported() {
        return !this.isAppEnvironment() && 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
    },

    async requestWebPermission() {
        if (Notification.permission !== 'default') return Notification.permission;
        return await Notification.requestPermission();
    },

    urlBase64ToUint8Array(base64) {
        const padded = (base64 + '='.repeat((4 - base64.length % 4) % 4)).replace(/-/g, '+').replace(/_/g, '/');
        const raw = atob(padded);
        const output = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) output[i] = raw.charCodeAt(i);
        return output;
    },

    async subscribeWebPush(settings) {
        try {
            await navigator.serviceWorker.register('/sw.js', { scope: '/' });
            const registration = await navigator.serviceWorker.ready;
            let subscription = await registration.pushManager.getSubscription();
            if (!subscription) {
                const keyRes = await fetch('/api/push/key');
                if (!keyRes.ok) return false;
                const { key } = await keyRes.json();
                subscription = await registration.pushManager.subscribe({
                    userVisibleOnly: true,
                    applicationServerKey: this.urlBase64ToUint8Array(key)
                });
            }
            const res = await fetch('/api/push/subscribe', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    subscription: subscription.toJSON(),
                    school_code: settings.school.code,
                    region_code: settings.school.region,
                    settings: { breakfast: settings.breakfast, lunch: settings.lunch, dinner: settings.dinner, days: settings.days }
                })
            });
            return res.ok;
        } catch (e) {
            return false;
        }
    },

    async unsubscribeWebPush() {
        try {
            const registration = await navigator.serviceWorker.getRegistration('/');
            const subscription = registration ? await registration.pushManager.getSubscription() : null;
            if (!subscription) return;
            await fetch('/api/push/unsubscribe', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ endpoint: subscription.endpoint })
            });
            await subscription.unsubscribe();
        } catch (e) {}
    },

    async syncWebPush() {
        const settings = this.loadSettings();
        if (!settings || !settings.enabled || !settings.school || Notification.permission !== 'granted') return;
        await this.subscribeWebPush(settings);
    },

    waitForCapacitor() {
        return new Promise((resolve) => {
            if (this.isAvailable()) { resolve(true); return; }
            let tries = 0;
            const interval = setInterval(() => {
                tries++;
                if (this.isAvailable()) { clearInterval(interval); resolve(true); }
                else if (tries >= 50) { clearInterval(interval); resolve(false); }
            }, 100);
        });
    },

    // [수정] 햅틱 피드백 - impact: 'LIGHT'|'MEDIUM'|'HEAVY', notification: 'SUCCESS'|'WARNING'|'ERROR'
    triggerHaptic(type = 'impact', style = 'LIGHT') {
        if (!this.isAppEnvironment()) return;
        const haptics = window.Capacitor?.Plugins?.Haptics;
        if (!haptics) return;
        try {
            if (type === 'impact') haptics.impact({ style });
            else if (type === 'notification') haptics.notification({ type: style });
        } catch (e) {}
    },

    async requestPermission() {
        if (this.isWebPushSupported()) return (await this.requestWebPermission()) === 'granted';
        if (!this.isAvailable()) return false;
        const { LocalNotifications } = window.Capacitor.Plugins;
        const result = await LocalNotifications.requestPermissions();
        return result.display === 'granted';
    },

    saveSettings(settings) {
        localStorage.setItem('notification_settings', JSON.stringify(settings));
    },

    loadSettings() {
        const raw = localStorage.getItem('notification_settings');
        return raw ? JSON.parse(raw) : null;
    },

    async cancelAll() {
        if (this.isWebPushSupported()) { await this.unsubscribeWebPush(); return; }
        if (!this.isAvailable()) return;
        const { LocalNotifications } = window.Capacitor.Plugins;
        const pending = await LocalNotifications.getPending();
        if (pending.notifications.length > 0) {
            await LocalNotifications.cancel({ notifications: pending.notifications });
        }
    },

    async schedule(settings, mealData) {
        if (!this.isAvailable()) return 0;
        const { LocalNotifications } = window.Capacitor.Plugins;

        await this.cancelAll();

        const mealTypes = [
            { key: 'breakfast', label: '조식', enabled: settings.breakfast.enabled, time: settings.breakfast.time },
            { key: 'lunch',     label: '중식', enabled: settings.lunch.enabled,     time: settings.lunch.time },
            { key: 'dinner',    label: '석식', enabled: settings.dinner.enabled,    time: settings.dinner.time },
        ];

        const notifications = [];
        let id = 1;
        // KST 기준 현재 날짜 계산: UTC+9 고정, getUTC* 메서드로 KST 날짜 추출
        const nowKST = new Date(new Date().getTime() + 9 * 60 * 60 * 1000);

        for (let offset = 0; offset < 30; offset++) {
            const dateKST = new Date(nowKST.getTime());
            dateKST.setUTCDate(dateKST.getUTCDate() + offset);

            // getUTCDay()가 KST 요일을 반환 (nowKST가 +9h shift된 상태이므로)
            const dayOfWeek = dateKST.getUTCDay();
            if (!settings.days.includes(dayOfWeek)) continue;

            const dateStr = [
                dateKST.getUTCFullYear(),
                String(dateKST.getUTCMonth() + 1).padStart(2, '0'),
                String(dateKST.getUTCDate()).padStart(2, '0')
            ].join('');

            const dayMeal = mealData[dateStr];
            if (!dayMeal) continue;

            for (const mealType of mealTypes) {
                if (!mealType.enabled || !mealType.time) continue;
                const menu = dayMeal[mealType.key];
                if (!menu || menu === '급식 정보 없음') continue;

                const [hours, minutes] = mealType.time.split(':').map(Number);
                // new Date(y, m, d, h, min): 기기 로컬 타임존 기준
                // 기기가 KST(UTC+9) 설정이면 올바르게 동작
                const localDate = new Date(
                    dateKST.getUTCFullYear(),
                    dateKST.getUTCMonth(),
                    dateKST.getUTCDate(),
                    hours, minutes, 0, 0
                );
                if (localDate <= new Date()) continue;

                const preview = menu.split('\n').slice(0, 3).join(', ');
                notifications.push({
                    id: id++,
                    title: `🍱 오늘의 ${mealType.label}`,
                    body: preview,
                    schedule: { at: localDate },
                    extra: { dateStr, mealType: mealType.key }
                });
            }
        }

        if (notifications.length > 0) {
            await LocalNotifications.schedule({ notifications });
        }

        return notifications.length;
    },

    async autoSchedule(mealData) {
        const settings = this.loadSettings();
        if (!settings || !settings.enabled) return;
        await this.schedule(settings, mealData);
    }

};

NotificationManager.init = function () {
    this.markPwaFromUrl();
    if (!this.isAppEnvironment()) {
        if ('serviceWorker' in navigator) {
            window.addEventListener('load', () => {
                navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(() => {});
            });
        }
        window.addEventListener('beforeinstallprompt', (event) => {
            event.preventDefault();
            this._installEvent = event;
        });
        window.addEventListener('appinstalled', () => {
            this._installEvent = null;
        });
    }
    const onReady = () => this.trackPwaVisit();
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', onReady);
    else onReady();
};

NotificationManager.init();
