const NotificationManager = {

    isAvailable() {
        return !!(window.Capacitor?.Plugins?.LocalNotifications);
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

    // [알림 스케줄링 - 핵심 함수]
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
        const now = new Date();

        for (let offset = 0; offset < 30; offset++) {
            const date = new Date();
            date.setDate(now.getDate() + offset);
            const dayOfWeek = date.getDay();

            if (!settings.days.includes(dayOfWeek)) continue;

            const dateStr = [
                date.getFullYear(),
                String(date.getMonth() + 1).padStart(2, '0'),
                String(date.getDate()).padStart(2, '0')
            ].join('');

            const dayMeal = mealData[dateStr];
            if (!dayMeal) continue;

            for (const mealType of mealTypes) {
                if (!mealType.enabled || !mealType.time) continue;
                const menu = dayMeal[mealType.key];
                if (!menu || menu === '급식 정보 없음') continue;

                const [hours, minutes] = mealType.time.split(':').map(Number);
                const scheduleAt = new Date(date);
                scheduleAt.setHours(hours, minutes, 0, 0);
                if (scheduleAt <= now) continue;

                const preview = menu.split('\n').slice(0, 3).join(', ');

                notifications.push({
                    id: id++,
                    title: `🍱 오늘의 ${mealType.label}`,
                    body: preview,
                    schedule: { at: scheduleAt },
                    extra: { dateStr, mealType: mealType.key }
                });
            }
        }

        if (notifications.length > 0) {
            await LocalNotifications.schedule({ notifications });
        }

        return notifications.length;
    },

    // [앱 실행 시 자동 재스케줄링]
    async autoSchedule(mealData) {
        const settings = this.loadSettings();
        if (!settings || !settings.enabled) return;
        await this.schedule(settings, mealData);
    }
};
