import logging
import os
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone

import requests

KST = timezone(timedelta(hours=9))
RESEND_API_URL = 'https://api.resend.com/emails'
RESEND_API_KEY = os.environ.get('RESEND_API_KEY', '').strip()
ALERT_EMAIL_TO = os.environ.get('ALERT_EMAIL_TO', '').strip()
ALERT_EMAIL_FROM = os.environ.get('ALERT_EMAIL_FROM', 'ImHungry Alert <alerts@geupsikalimi.com>').strip()
HOURLY_LIMIT = 20
DAILY_LIMIT = 60

logger = logging.getLogger('mailer')
_lock = threading.Lock()
_sent = deque()
_dedupe = {}


def configured():
    return bool(RESEND_API_KEY and ALERT_EMAIL_TO)


def _allowed(key, dedupe_seconds):
    now = time.time()
    with _lock:
        while _sent and now - _sent[0] >= 86400:
            _sent.popleft()
        if key is not None:
            if now - _dedupe.get(key, 0) < dedupe_seconds:
                return False
        if len(_sent) >= DAILY_LIMIT:
            logger.warning('보안 알림 메일 일일 한도(%d) 초과로 발송하지 않음', DAILY_LIMIT)
            return False
        if sum(1 for t in _sent if now - t < 3600) >= HOURLY_LIMIT:
            logger.warning('보안 알림 메일 시간당 한도(%d) 초과로 발송하지 않음', HOURLY_LIMIT)
            return False
        if len(_dedupe) > 5000:
            _dedupe.clear()
        if key is not None:
            _dedupe[key] = now
        _sent.append(now)
        return True


def _post(subject, text):
    try:
        response = requests.post(
            RESEND_API_URL,
            headers={'Authorization': f'Bearer {RESEND_API_KEY}', 'User-Agent': 'imhungry-alert/1.0'},
            json={'from': ALERT_EMAIL_FROM, 'to': [ALERT_EMAIL_TO], 'subject': subject, 'text': text},
            timeout=10,
        )
        if response.status_code >= 300:
            logger.warning('보안 알림 메일 발송 실패: %s %s', response.status_code, response.text[:200])
    except Exception as e:
        logger.warning('보안 알림 메일 발송 예외: %s', e)


def send_alert(subject, fields, key=None, dedupe_seconds=600):
    if not configured():
        return False
    if not _allowed(key, dedupe_seconds):
        return False
    subject = ' '.join(str(subject).split())[:150]
    lines = [f'{name}: {str(value)[:300]}' for name, value in fields.items()]
    lines.append(f'시각(KST): {datetime.now(KST).strftime("%Y-%m-%d %H:%M:%S")}')
    threading.Thread(target=_post, args=(subject, '\n'.join(lines)), daemon=True).start()
    return True
