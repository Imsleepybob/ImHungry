const NotificationManager = {

    isAppEnvironment() {
        return navigator.userAgent.includes('ImHungryApp');
    },

    isAndroidBrowser() {
        return /android/i.test(navigator.userAgent) && !this.isAppEnvironment();
    },

    isIOSBrowser() {
        const ua = navigator.userAgent;
        const isIOS = ['iPad Simulator','iPhone Simulator','iPod Simulator','iPad','iPhone','iPod'].includes(navigator.platform) ||
            (ua.includes('Mac') && 'ontouchend' in document);
        return isIOS && !this.isAppEnvironment();
    },

    isAvailable() {
        return !!(window.Capacitor?.Plugins?.LocalNotifications);
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

    async requestPermission() {
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
        const nowKST = new Date(new Date().getTime() + 9 * 60 * 60 * 1000);

        for (let offset = 0; offset < 30; offset++) {
            const dateKST = new Date(nowKST.getTime());
            dateKST.setUTCDate(dateKST.getUTCDate() + offset);

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
