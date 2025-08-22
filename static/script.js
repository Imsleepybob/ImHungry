const regions_data = {{ regions | tojson | safe }};

// 자동완성 기능에 필요한 변수 선언
let autocompleteTimeout;
let autocompleteVisible = false;
let selectedIndex = -1;

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) {
        try {
            return decodeURIComponent(parts.pop().split(';').shift());
        } catch (e) {
            return parts.pop().split(';').shift();
        }
    }
    return null;
}

function isIOS() {
    return ['iPad Simulator', 'iPhone Simulator', 'iPod Simulator', 'iPad', 'iPhone', 'iPod'].includes(navigator.platform) ||
        (navigator.userAgent.includes("Mac") && "ontouchend" in document);
}

function isSafari() {
    return /^((?!chrome|android).)*safari/i.test(navigator.userAgent);
}

function shouldShowGuide() {
    return !localStorage.getItem('ios-webapp-guide-shown') && isIOS() && isSafari() && !window.navigator.standalone;
}

function dismissIOSGuide() {
    const guideElement = document.getElementById('ios-webapp-guide');
    if (guideElement) {
        guideElement.classList.remove('show');
        setTimeout(() => {
            guideElement.style.display = 'none';
        }, 500);
        localStorage.setItem('ios-webapp-guide-shown', 'true');
    }
}

function loadNotificationSettings() {
    console.log("Loading notification settings...");
    const settings = JSON.parse(localStorage.getItem('notificationSettings') || '{}');
    
    const breakfastEnable = document.getElementById('breakfast-enable');
    const breakfastTime = document.getElementById('breakfast-time');
    const lunchEnable = document.getElementById('lunch-enable');
    const lunchTime = document.getElementById('lunch-time');
    const dinnerEnable = document.getElementById('dinner-enable');
    const dinnerTime = document.getElementById('dinner-time');
    
    if (breakfastEnable) breakfastEnable.checked = settings.breakfast?.enabled || false;
    if (breakfastTime) breakfastTime.value = settings.breakfast?.time || '07:00';
    if (lunchEnable) lunchEnable.checked = settings.lunch?.enabled || false;
    if (lunchTime) lunchTime.value = settings.lunch?.time || '12:00';
    if (dinnerEnable) dinnerEnable.checked = settings.dinner?.enabled || false;
    if (dinnerTime) dinnerTime.value = settings.dinner?.time || '18:00';
    
    const days = settings.days || [1, 2, 3, 4, 5]; // Default Mon-Fri
    document.querySelectorAll('.day-setting input[type="checkbox"]').forEach(cb => {
        cb.checked = days.includes(parseInt(cb.value));
    });
    console.log("Settings loaded:", settings);
}

let notificationTimeouts = [];

function clearNotificationTimeouts() {
    console.log("Clearing all notifications timeouts.");
    notificationTimeouts.forEach(timeoutId => clearTimeout(timeoutId));
    notificationTimeouts = [];
}

async function requestAndScheduleNotifications() {
    console.log("Requesting permission and scheduling...");
    if (!('Notification' in window)) {
        alert('이 브라우저는 알림을 지원하지 않습니다.');
        return;
    }
    const permission = await Notification.requestPermission();
    if (permission === 'granted') {
        console.log("Permission granted. Scheduling...");
        await scheduleNextNotifications();
    } else {
        console.warn("Permission denied.");
        alert('알림 권한이 필요합니다. 설정을 확인해주세요.');
    }
}

async function scheduleNextNotifications() {
    clearNotificationTimeouts();
    const settings = JSON.parse(localStorage.getItem('notificationSettings') || '{}');
    const schoolCode = getCookie('school_code');
    if (!settings || !schoolCode) {
        console.log("No settings or school code, skipping schedule.");
        return;
    }

    try {
        const response = await fetch('/current_time');
        const data = await response.json();
        const now = new Date(data.current_time);
        console.log("Current KST:", now);

        const mealTypes = ['breakfast', 'lunch', 'dinner'];
        mealTypes.forEach(mealType => {
            if (settings[mealType]?.enabled && settings[mealType]?.time && settings.days) {
                const [hours, minutes] = settings[mealType].time.split(':');
                settings.days.forEach(dayOfWeek => {
                    let nextTime = new Date(now);

                    nextTime.setHours(parseInt(hours), parseInt(minutes), 0, 0);
                    let currentDay = now.getDay();
                    let dayDiff = dayOfWeek - currentDay;

                    if (dayDiff < 0) {
                        dayDiff += 7;
                    }
                    nextTime.setDate(now.getDate() + dayDiff);
                    if (nextTime <= now) {
                        nextTime.setDate(nextTime.getDate() + 7);
                    }
                    const delay = nextTime.getTime() - now.getTime();

                    if (delay > 0) {
                        console.log(`Scheduling ${mealType} for ${nextTime} (Delay: ${Math.round(delay/1000)}s)`);
                        const timeoutId = setTimeout(async () => {
                            console.log(`Triggering notification for ${mealType} at ${new Date()}`);
                            await sendNotification(mealType, nextTime);
                            await scheduleNextNotifications(); // Reschedule *after* sending
                        }, delay);
                        notificationTimeouts.push(timeoutId);
                    } else {
                        console.warn(`Could not schedule ${mealType} for day ${dayOfWeek}, time is past.`);
                    }
                });
            }
        });
    } catch (error) {
        console.error('Error during scheduling:', error);
    }
}

async function sendNotification(mealType, notificationDate) {
    if (Notification.permission !== 'granted') return;
    const schoolCode = getCookie('school_code');
    const schoolName = getCookie('school_name');
    if (!schoolCode || !schoolName) return;
    try {
        const dateString = notificationDate.toISOString().slice(0, 10).replace(/-/g, '');
        console.log(`Fetching meal for ${schoolName} (${schoolCode}) on ${dateString}`);
        const mealResponse = await fetch(`/api/meals/${schoolCode}/${dateString}`);
        if (!mealResponse.ok) {
            console.error("API Fetch Error:", mealResponse.statusText);
            return;
        }
        const mealData = await mealResponse.json();
        console.log("Meal data received:", mealData);

        const mealContent = mealData[mealType];
        if (mealContent && mealContent !== "급식 정보 없음") {
            const meal = mealContent.length > 80 ?
                mealContent.substring(0, 80) + '...' : mealContent;
            const titleMap = {
                breakfast: "아침",
                lunch: "점심",
                dinner: "저녁"
            };
            console.log(`Sending notification: ${titleMap[mealType]} - ${meal}`);
            const notification = new Notification(`${schoolName} 오늘의 ${titleMap[mealType]} 🍗`, {
                body: meal,
                icon: "/favicon.svg",
                tag: `${dateString}-${mealType}`
            });
            notification.onclick = function(event) {
                event.preventDefault();
                window.open(`/meal/${schoolCode}`, '_blank');
            };
        } else {
            console.log(`No ${mealType} for ${dateString}, skipping notification.`);
        }
    } catch (error) {
        console.error('알림 전송 오류:', error);
    }
}

async function searchSchools(query, region) {
    try {
        const response = await fetch(`/api/schools/search?q=${encodeURIComponent(query)}&region=${encodeURIComponent(region)}`);
        const schools = await response.json();
        showAutocomplete(schools);
    } catch (error) {
        console.error('자동완성 검색 오류:', error);
        hideAutocomplete();
    }
}

function showAutocomplete(schools) {
    const autocompleteResults = document.getElementById("autocomplete-results");
    if (!autocompleteResults) return;

    if (schools.length === 0) {
        hideAutocomplete();
        return;
    }

    autocompleteResults.innerHTML = '';

    schools.forEach((school, index) => {
        const item = document.createElement('div');
        item.className = 'autocomplete-item';
        item.textContent = school.name;
        item.dataset.code = school.code;
        item.dataset.name = school.name;

        item.addEventListener('click', () => selectSchool(item));
        autocompleteResults.appendChild(item);
    });

    autocompleteResults.style.display = 'block';
    autocompleteVisible = true;
    selectedIndex = -1;
}

function hideAutocomplete() {
    const autocompleteResults = document.getElementById("autocomplete-results");
    if (autocompleteResults) {
        autocompleteResults.style.display = 'none';
    }
    autocompleteVisible = false;
    selectedIndex = -1;
}

function updateSelection(items) {
    items.forEach((item, index) => {
        item.classList.toggle('selected', index === selectedIndex);
    });
}

function selectSchool(item) {
    const schoolNameInput = document.getElementById("school_name");
    const schoolCode = item.dataset.code;
    const schoolName = item.dataset.name;

    if (schoolNameInput) {
        schoolNameInput.value = schoolName;
    }
    hideAutocomplete();

    // 직접 해당 학교 페이지로 이동
    window.location.href = `/meal/${schoolCode}`;
}

document.addEventListener('DOMContentLoaded', function() {
    console.log("DOM Content Loaded - Starting initialization");
    
    const schoolNameInput = document.getElementById("school_name");
    const regionSelect = document.getElementById("region");
    const autocompleteResults = document.getElementById("autocomplete-results");
    const notificationBtn = document.getElementById('notification-btn');
    const notificationModal = document.getElementById('notification-modal');
    const closeBtn = document.querySelector('#notification-modal .close');
    const regionForm = document.getElementById('regionForm');
    const loadingDiv = document.getElementById('loading');
    const notificationForm = document.getElementById('notification-form');
    const toggleMonthBtn = document.getElementById('toggleMonthBtn');
    const monthTable = document.getElementById('monthTable');
    const iosGuide = document.getElementById('ios-webapp-guide');
    const dismissBtn = document.getElementById('dismiss-ios-btn');
    const shareBtn = document.getElementById('share-btn');

    console.log("Elements found:", {
        schoolNameInput: !!schoolNameInput,
        regionSelect: !!regionSelect,
        autocompleteResults: !!autocompleteResults,
        notificationBtn: !!notificationBtn,
        toggleMonthBtn: !!toggleMonthBtn,
        monthTable: !!monthTable
    });

    // 자동완성 기능
    if (schoolNameInput && regionSelect && autocompleteResults) {
        console.log("Setting up autocomplete functionality");
        
        // 입력 시 자동완성
        schoolNameInput.addEventListener('input', function() {
            const query = this.value.trim();
            const region = regionSelect.value;
            clearTimeout(autocompleteTimeout);
            if (query.length < 2 || !region) {
                hideAutocomplete();
                return;
            }
            autocompleteTimeout = setTimeout(() => {
                searchSchools(query, region);
            }, 300);
        });

        // 키보드 네비게이션
        schoolNameInput.addEventListener('keydown', function(e) {
            if (!autocompleteVisible) return;
            const items = autocompleteResults.querySelectorAll('.autocomplete-item');
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                selectedIndex = Math.min(selectedIndex + 1, items.length - 1);
                updateSelection(items);
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                selectedIndex = Math.max(selectedIndex - 1, -1);
                updateSelection(items);
            } else if (e.key === 'Enter' && selectedIndex >= 0) {
                e.preventDefault();
                selectSchool(items[selectedIndex]);
            } else if (e.key === 'Escape') {
                hideAutocomplete();
            }
        });

        // 지역 변경 시 자동완성 숨기기
        regionSelect.addEventListener('change', function() {
            hideAutocomplete();
        });

        // 외부 클릭 시 자동완성 숨기기
        document.addEventListener('click', function(e) {
            if (!schoolNameInput.contains(e.target) && !autocompleteResults.contains(e.target)) {
                hideAutocomplete();
            }
        });
    }

    // 공유 기능
    if (shareBtn) {
        shareBtn.addEventListener('click', async () => {
            const schoolCode = getCookie('school_code');
            const schoolName = getCookie('school_name') || '학교';
            const shareUrl = `https://imsleepy.xyz/meal/${schoolCode}`;

            if (navigator.share && schoolCode) {
                try {
                    await navigator.share({
                        title: `${schoolName} 급식 정보`,
                        text: `${schoolName}의 급식을 확인하세요!`,
                        url: shareUrl
                    });
                } catch (error) {
                    console.error('공유 실패:', error);
                }
            } else if (schoolCode) {
                try {
                    await navigator.clipboard.writeText(shareUrl);
                    alert('공유 링크가 클립보드에 복사되었습니다.');
                } catch (err) {
                    alert('공유 기능을 지원하지 않는 브라우저입니다.');
                }
            } else {
                alert('학교를 먼저 검색해주세요.');
            }
        });
    }

    // 모달 관련 함수들
    const openModal = () => {
        if (notificationModal) {
            console.log("Opening notification modal...");
            loadNotificationSettings();
            notificationModal.style.display = 'block';
            setTimeout(() => {
                notificationModal.style.opacity = '1';
            }, 10);
        }
    };

    const closeModal = () => {
        if (notificationModal) {
            console.log("Closing notification modal...");
            notificationModal.style.opacity = '0';
            setTimeout(() => {
                notificationModal.style.display = 'none';
            }, 300);
        }
    };

    // 이벤트 리스너 등록
    if (notificationBtn) {
        notificationBtn.addEventListener('click', openModal);
    }
    
    if (closeBtn) {
        closeBtn.addEventListener('click', closeModal);
    }
    
    // 모달 외부 클릭 시 닫기
    if (notificationModal) {
        window.addEventListener('click', (event) => {
            if (event.target === notificationModal) {
                closeModal();
            }
        });
    }

    if (dismissBtn) {
        dismissBtn.addEventListener('click', dismissIOSGuide);
    }

    // 폼 제출 처리
    if (regionForm) {
        regionForm.addEventListener('submit', function(event) {
            if (!regionSelect || !regionSelect.value) {
                event.preventDefault();
                alert("지역을 선택해주세요.");
                if (regionSelect) regionSelect.focus();
                return;
            }
            if (loadingDiv) loadingDiv.style.display = 'flex';
        });
    }

    // 알림 설정 폼 처리
    if (notificationForm) {
        notificationForm.addEventListener('submit', function(event) {
            event.preventDefault();
            const schoolCode = getCookie('school_code');
            if (!schoolCode) {
                alert('먼저 학교를 검색해주세요.');
                return;
            }
            
            const selectedDays = Array.from(document.querySelectorAll('.day-setting input[type="checkbox"]:checked')).map(cb => parseInt(cb.value));
            
            const breakfastEnable = document.getElementById('breakfast-enable');
            const breakfastTime = document.getElementById('breakfast-time');
            const lunchEnable = document.getElementById('lunch-enable');
            const lunchTime = document.getElementById('lunch-time');
            const dinnerEnable = document.getElementById('dinner-enable');
            const dinnerTime = document.getElementById('dinner-time');
            
            const settings = {
                breakfast: {
                    enabled: breakfastEnable ? breakfastEnable.checked : false,
                    time: breakfastTime ? breakfastTime.value : '07:00'
                },
                lunch: {
                    enabled: lunchEnable ? lunchEnable.checked : false,
                    time: lunchTime ? lunchTime.value : '12:00'
                },
                dinner: {
                    enabled: dinnerEnable ? dinnerEnable.checked : false,
                    time: dinnerTime ? dinnerTime.value : '18:00'
                },
                days: selectedDays
            };
            
            console.log("Saving settings:", settings);
            localStorage.setItem('notificationSettings', JSON.stringify(settings));
            alert('알림이 저장되었습니다.');
            closeModal();
            requestAndScheduleNotifications();
        });
    }

    // 월간 급식표 토글 기능
    if (toggleMonthBtn && monthTable) {
        console.log("Setting up month toggle functionality");
        toggleMonthBtn.addEventListener('click', function() {
            console.log("Month toggle clicked!");
            const isHidden = monthTable.style.display === 'none';
            monthTable.style.display = isHidden ? 'block' : 'none';
            toggleMonthBtn.innerHTML = isHidden ? '▲ 월간 급식표 접기' : '▼ 월간 급식표 보기';

            if (isHidden) {
                monthTable.scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    } else {
        console.warn("Month toggle button or table not found!");
    }

    if (iosGuide && shouldShowGuide()) {
        console.log("Showing iOS Guide");
        setTimeout(() => {
            iosGuide.style.display = 'block';
            setTimeout(() => {
                iosGuide.classList.add('show');
            }, 10);
        }, 1000);
    }

    if ('Notification' in window && Notification.permission === 'granted') {
        if (getCookie('school_code')) {
            requestAndScheduleNotifications();
        }
    }

    if (loadingDiv) {
        loadingDiv.style.display = 'none';
    }

    const savedSchool = getCookie('school_name');
    const savedRegionName = getCookie('region_name');
    if (savedSchool && schoolNameInput) {
        try {
            schoolNameInput.value = decodeURIComponent(savedSchool);
        } catch (e) {
            schoolNameInput.value = savedSchool;
        }
    }
    if (savedRegionName && regionSelect) {
        regionSelect.value = savedRegionName;
    }

    console.log("DOM Loaded and JS initialized successfully");

    setTimeout(() => {
        const bodyAdDesktop = document.getElementById('bodyad-desktop');
        const bodyAdMobile = document.getElementById('bodyad-mobile');

        if (bodyAdDesktop) {
            bodyAdDesktop.classList.add('show-ad');
        }
        if (bodyAdMobile) {
            bodyAdMobile.classList.add('show-ad');
        }
    }, 1500);
});
