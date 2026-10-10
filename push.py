import atexit
import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import urlparse

import requests
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Blueprint, jsonify, redirect, request, send_from_directory, make_response
from pywebpush import webpush, WebPushException

push_bp = Blueprint('push', __name__)

VAPID_PUBLIC_KEY = os.environ.get('VAPID_PUBLIC_KEY', '').strip()
VAPID_PRIVATE_KEY = os.environ.get('VAPID_PRIVATE_KEY', '').strip()
VAPID_SUBJECT = os.environ.get('VAPID_SUBJECT', '').strip()

GITHUB_TOKEN = (os.environ.get('PUSH_GITHUB_TOKEN') or os.environ.get('GITHUB_TOKEN', '')).strip()
GITHUB_REPO = os.environ.get('PUSH_GITHUB_REPO', '').strip()
GITHUB_BRANCH = os.environ.get('PUSH_GITHUB_BRANCH', 'main').strip()
GITHUB_PATH = os.environ.get('PUSH_GITHUB_PATH', 'push_subscriptions.json').strip()
GITHUB_API = 'https://api.github.com'
GITHUB_SYNC_DEBOUNCE = 60
GITHUB_RETRY_DELAY = 120

MEALS = (('breakfast', '조식'), ('lunch', '중식'), ('dinner', '석식'))
NO_MEAL = '급식 정보 없음'
GRACE_SECONDS = 300
MAX_BODY_BYTES = 8192
MAX_SUBSCRIPTIONS = 5000
MAX_BODY_CHARS = 120
MAX_TITLE_CHARS = 30
ALLOWED_PUSH_HOSTS = ('.googleapis.com', '.push.services.mozilla.com', '.push.apple.com', '.notify.windows.com')

TIME_RE = re.compile(r'^([01]\d|2[0-3]):[0-5]\d$')
SCHOOL_RE = re.compile(r'^\d{5,10}$')
REGION_RE = re.compile(r'^[A-Z]\d{2}$')

_state = {'path': None, 'get_month_meals': None, 'tz': None, 'logger': None, 'scheduler': None, 'admin_check': None, 'configured': False, 'started_pid': None, 'csrf': None}
_subs = {}
_lock = threading.Lock()
_init_lock = threading.Lock()
_remote = {'loaded': False, 'sha': None, 'pushed_hash': None, 'pending': False, 'last_restore': '-', 'last_push': '-'}
_broadcast = {'running': False, 'started': '', 'finished': '', 'title': '', 'body': '', 'total': 0, 'done': 0, 'ok': 0, 'gone': 0, 'fail': 0, 'errors': []}
_broadcast_lock = threading.Lock()
_remote_lock = threading.Lock()
_gh_io_lock = threading.Lock()
_logged_skips = set()


def _clip(text, limit=MAX_BODY_CHARS):
    if len(text) <= limit:
        return text
    return text[:limit - 2] + '..'


def _note_remote(kind, ok, message):
    stamp = datetime.now(_state['tz']).strftime('%Y-%m-%d %H:%M:%S')
    _remote['last_' + kind] = f"{stamp} {'성공' if ok else '실패'} - {message}"


def push_enabled():
    return bool(VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY and VAPID_SUBJECT)


def _load_store():
    global _subs
    try:
        with open(_state['path'], 'r', encoding='utf-8') as f:
            data = json.load(f)
        _subs = data if isinstance(data, dict) else {}
    except (FileNotFoundError, ValueError):
        _subs = {}


def _save_store(sync=True):
    tmp_path = _state['path'] + '.tmp'
    with open(tmp_path, 'w', encoding='utf-8') as f:
        json.dump(_subs, f, ensure_ascii=False)
    os.replace(tmp_path, _state['path'])
    if sync:
        _schedule_remote_sync()


def _gh_enabled():
    return bool(GITHUB_TOKEN and GITHUB_REPO)


def _gh_url():
    return f'{GITHUB_API}/repos/{GITHUB_REPO}/contents/{GITHUB_PATH}'


def _gh_headers(accept):
    return {
        'Authorization': f'Bearer {GITHUB_TOKEN}',
        'Accept': accept,
        'X-GitHub-Api-Version': '2022-11-28',
    }


def _gh_fetch_sha():
    resp = requests.get(_gh_url(), headers=_gh_headers('application/vnd.github.object+json'), params={'ref': GITHUB_BRANCH}, timeout=10)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json().get('sha')


def _gh_download():
    resp = requests.get(_gh_url(), headers=_gh_headers('application/vnd.github.raw+json'), params={'ref': GITHUB_BRANCH}, timeout=15)
    if resp.status_code == 404:
        return None, None, None
    resp.raise_for_status()
    raw = resp.content
    data = json.loads(raw.decode('utf-8'))
    return data, _gh_fetch_sha(), raw


def _clean_remote_record(endpoint, record):
    if not _valid_endpoint(endpoint) or not isinstance(record, dict):
        return None
    p256dh, auth = record.get('p256dh'), record.get('auth')
    school_code, region_code = record.get('school_code'), record.get('region_code')
    settings = _clean_settings(record.get('settings'))
    if not (isinstance(p256dh, str) and isinstance(auth, str) and 0 < len(p256dh) <= 200 and 0 < len(auth) <= 100):
        return None
    if not (isinstance(school_code, str) and SCHOOL_RE.match(school_code) and isinstance(region_code, str) and REGION_RE.match(region_code)):
        return None
    if settings is None:
        return None
    return {'p256dh': p256dh, 'auth': auth, 'school_code': school_code, 'region_code': region_code, 'settings': settings, 'sent': {'date': '', 'meals': []}}


def _restore_remote():
    data, sha, raw = _gh_download()
    with _lock:
        if isinstance(data, dict):
            for endpoint, record in data.items():
                if endpoint in _subs or len(_subs) >= MAX_SUBSCRIPTIONS:
                    continue
                cleaned = _clean_remote_record(endpoint, record)
                if cleaned is not None:
                    _subs[endpoint] = cleaned
            _save_store(sync=False)
    _remote['sha'] = sha
    _remote['pushed_hash'] = hashlib.sha256(raw).hexdigest() if raw else None
    _remote['loaded'] = True
    remote_count = len(data) if isinstance(data, dict) else 0
    _note_remote('restore', True, f'GitHub {remote_count}건 확인, 복원 후 현재 {len(_subs)}건')
    _state['logger'].info(f'푸시 구독 GitHub 복원 완료: GitHub {remote_count}건 확인, 현재 {len(_subs)}건')


def _remote_payload():
    with _lock:
        snapshot = {endpoint: {k: v for k, v in record.items() if k != 'sent'} for endpoint, record in _subs.items()}
    return json.dumps(snapshot, ensure_ascii=False, sort_keys=True).encode('utf-8')


def _gh_push():
    for attempt in range(2):
        payload = _remote_payload()
        digest = hashlib.sha256(payload).hexdigest()
        if digest == _remote['pushed_hash']:
            return True
        body = {
            'message': f"chore: 푸시 구독 자동 갱신 ({datetime.now(_state['tz']).strftime('%Y-%m-%d %H:%M:%S')})",
            'content': base64.b64encode(payload).decode('ascii'),
            'branch': GITHUB_BRANCH,
        }
        if _remote['sha']:
            body['sha'] = _remote['sha']
        resp = requests.put(_gh_url(), headers=_gh_headers('application/vnd.github+json'), json=body, timeout=15)
        if resp.status_code in (200, 201):
            _remote['sha'] = resp.json()['content']['sha']
            _remote['pushed_hash'] = digest
            _note_remote('push', True, f'구독 {len(_subs)}건 저장')
            _state['logger'].info('푸시 구독 GitHub 동기화 완료')
            return True
        if resp.status_code in (409, 422) and attempt == 0:
            _restore_remote()
            continue
        _note_remote('push', False, f'HTTP {resp.status_code} {resp.text[:120]}')
        _state['logger'].error(f'푸시 구독 GitHub 동기화 실패: {resp.status_code} {resp.text[:200]}')
        return False
    return False


def _remote_sync_worker():
    with _remote_lock:
        _remote['pending'] = False
    ok = False
    with _gh_io_lock:
        try:
            if not _remote['loaded']:
                _restore_remote()
            ok = _gh_push()
        except Exception as e:
            _note_remote('push', False, f'{type(e).__name__}: {str(e)[:150]}')
            _state['logger'].error(f'푸시 구독 GitHub 동기화 예외: {e}')
    if not ok:
        _schedule_remote_sync(GITHUB_RETRY_DELAY)


def _schedule_remote_sync(delay=None):
    if not _gh_enabled():
        return
    with _remote_lock:
        if _remote['pending']:
            return
        _remote['pending'] = True
    timer = threading.Timer(GITHUB_SYNC_DEBOUNCE if delay is None else delay, _remote_sync_worker)
    timer.daemon = True
    timer.start()


def _flush_remote():
    if not _gh_enabled() or not _remote['loaded']:
        return
    if not _gh_io_lock.acquire(timeout=10):
        return
    try:
        _gh_push()
    except Exception as e:
        _state['logger'].error(f'푸시 구독 종료 시 GitHub 저장 실패: {e}')
    finally:
        _gh_io_lock.release()


def _initial_restore():
    with _gh_io_lock:
        try:
            _restore_remote()
            restored = True
        except Exception as e:
            _note_remote('restore', False, f'{type(e).__name__}: {str(e)[:150]}')
            _state['logger'].error(f'푸시 구독 GitHub 복원 실패: {e}')
            restored = False
    if restored:
        _schedule_remote_sync()
    else:
        timer = threading.Timer(GITHUB_RETRY_DELAY, _initial_restore)
        timer.daemon = True
        timer.start()


def _valid_endpoint(endpoint):
    if not isinstance(endpoint, str) or len(endpoint) > 1000:
        return False
    parsed = urlparse(endpoint)
    host = (parsed.hostname or '').lower()
    if parsed.scheme != 'https' or not host:
        return False
    return any(host.endswith(suffix) for suffix in ALLOWED_PUSH_HOSTS)


def _clean_settings(raw):
    if not isinstance(raw, dict):
        return None
    cleaned = {}
    for key, _ in MEALS:
        meal = raw.get(key)
        meal = meal if isinstance(meal, dict) else {}
        time_str = meal.get('time')
        valid_time = isinstance(time_str, str) and bool(TIME_RE.match(time_str))
        cleaned[key] = {
            'enabled': bool(meal.get('enabled')) and valid_time,
            'time': time_str if valid_time else '00:00',
        }
    days = raw.get('days')
    days = days if isinstance(days, list) else []
    cleaned['days'] = sorted({d for d in days if type(d) is int and 0 <= d <= 6})
    return cleaned


@push_bp.route('/sw.js')
def service_worker():
    response = make_response(send_from_directory(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static'), 'sw.js', mimetype='application/javascript'))
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['Service-Worker-Allowed'] = '/'
    return response


@push_bp.route('/api/push/key')
def push_key():
    if not push_enabled():
        return jsonify({'error': 'push disabled'}), 503
    return jsonify({'key': VAPID_PUBLIC_KEY})


@push_bp.route('/api/push/subscribe', methods=['POST'])
def push_subscribe():
    if not push_enabled():
        return jsonify({'error': 'push disabled'}), 503
    if request.content_length is not None and request.content_length > MAX_BODY_BYTES:
        return jsonify({'error': 'too large'}), 413
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'invalid body'}), 400

    subscription = data.get('subscription')
    subscription = subscription if isinstance(subscription, dict) else {}
    keys = subscription.get('keys')
    keys = keys if isinstance(keys, dict) else {}
    endpoint = subscription.get('endpoint')
    p256dh = keys.get('p256dh')
    auth = keys.get('auth')
    school_code = data.get('school_code')
    region_code = data.get('region_code')
    settings = _clean_settings(data.get('settings'))

    if not _valid_endpoint(endpoint):
        return jsonify({'error': 'invalid endpoint'}), 400
    if not (isinstance(p256dh, str) and isinstance(auth, str) and 0 < len(p256dh) <= 200 and 0 < len(auth) <= 100):
        return jsonify({'error': 'invalid keys'}), 400
    if not (isinstance(school_code, str) and SCHOOL_RE.match(school_code)):
        return jsonify({'error': 'invalid school'}), 400
    if not (isinstance(region_code, str) and REGION_RE.match(region_code)):
        return jsonify({'error': 'invalid region'}), 400
    if settings is None:
        return jsonify({'error': 'invalid settings'}), 400

    with _lock:
        existing = _subs.get(endpoint)
        if existing is None and len(_subs) >= MAX_SUBSCRIPTIONS:
            return jsonify({'error': 'capacity reached'}), 503
        record = {
            'p256dh': p256dh,
            'auth': auth,
            'school_code': school_code,
            'region_code': region_code,
            'settings': settings,
            'sent': existing['sent'] if existing else {'date': '', 'meals': []},
        }
        if existing != record:
            _subs[endpoint] = record
            _save_store()
    return jsonify({'ok': True})


@push_bp.route('/api/push/unsubscribe', methods=['POST'])
def push_unsubscribe():
    if request.content_length is not None and request.content_length > MAX_BODY_BYTES:
        return jsonify({'error': 'too large'}), 413
    data = request.get_json(silent=True)
    endpoint = data.get('endpoint') if isinstance(data, dict) else None
    if not _valid_endpoint(endpoint):
        return jsonify({'error': 'invalid endpoint'}), 400
    with _lock:
        if _subs.pop(endpoint, None) is not None:
            _save_store()
    return jsonify({'ok': True})


def _host(endpoint):
    return urlparse(endpoint).hostname or ''


def _endpoint_id(endpoint):
    return hashlib.sha256(endpoint.encode('utf-8')).hexdigest()[:12]


def _send_one(endpoint, p256dh, auth, title, body, tag):
    subscription = {'endpoint': endpoint, 'keys': {'p256dh': p256dh, 'auth': auth}}
    payload = json.dumps({'title': title, 'body': body, 'tag': tag, 'url': '/'}, ensure_ascii=False)
    try:
        response = webpush(
            subscription_info=subscription,
            data=payload,
            vapid_private_key=VAPID_PRIVATE_KEY,
            vapid_claims={'sub': VAPID_SUBJECT},
            ttl=3600,
            timeout=10,
        )
        return endpoint, 'ok', f"HTTP {getattr(response, 'status_code', '')}".strip()
    except WebPushException as e:
        resp = getattr(e, 'response', None)
        status = resp.status_code if resp is not None else None
        text = (resp.text or '')[:200] if resp is not None else ''
        detail = f'HTTP {status} {text}'.strip() if status else f'{type(e).__name__}: {str(e)[:200]}'
        if status in (404, 410):
            return endpoint, 'gone', detail
        if status is None or status == 429 or status >= 500:
            return endpoint, 'retry', detail
        return endpoint, 'fail', detail
    except requests.exceptions.RequestException as e:
        return endpoint, 'retry', f'{type(e).__name__}: {str(e)[:200]}'
    except Exception as e:
        return endpoint, 'fail', f'{type(e).__name__}: {str(e)[:200]}'


def _slot_time_state(now, meal_setting):
    hours, minutes = map(int, meal_setting['time'].split(':'))
    due = now.replace(hour=hours, minute=minutes, second=0, microsecond=0)
    elapsed = (now - due).total_seconds()
    if elapsed < 0:
        return 'wait', int(-elapsed // 60) + 1
    if elapsed >= GRACE_SECONDS:
        return 'late', int(elapsed // 60)
    return 'window', int(elapsed // 60)


def _log_skip_once(endpoint, slot, today, reason, info):
    key = (endpoint, slot, today, reason)
    if key in _logged_skips:
        return
    if len(_logged_skips) > 5000:
        _logged_skips.clear()
    _logged_skips.add(key)
    _state['logger'].info(f'[push] 건너뜀({info}): {reason}')


def send_due(now=None):
    now = now or datetime.now(_state['tz'])
    today = now.strftime('%Y%m%d')
    weekday = (now.weekday() + 1) % 7
    logger = _state['logger']

    with _lock:
        snapshot = [(endpoint, dict(record)) for endpoint, record in _subs.items()]

    candidates = []
    for endpoint, record in snapshot:
        settings = record['settings']
        already = record['sent']['meals'] if record['sent'].get('date') == today else []
        for key, label in MEALS:
            meal_setting = settings.get(key) or {}
            if not meal_setting.get('enabled'):
                continue
            time_state, _ = _slot_time_state(now, meal_setting)
            if time_state != 'window':
                continue
            slot = f"{key}@{meal_setting['time']}"
            info = f"{label} {meal_setting['time']} school={record['school_code']} host={_host(endpoint)}"
            if weekday not in settings.get('days', []):
                _log_skip_once(endpoint, slot, today, f"오늘 요일이 알림 요일에 없음 (오늘={weekday}, 설정={settings.get('days')})", info)
                continue
            if slot in already:
                continue
            candidates.append((endpoint, record, key, label, slot, info))

    meal_cache = {}
    jobs = []
    for endpoint, record, key, label, slot, info in candidates:
        school_key = (record['school_code'], record['region_code'])
        if school_key not in meal_cache:
            try:
                meal_cache[school_key] = _state['get_month_meals'](*school_key)
            except Exception as e:
                logger.error(f'[push] 급식 조회 실패 {school_key}: {e}')
                meal_cache[school_key] = {}
        menu = (meal_cache[school_key].get(today) or {}).get(key)
        if not menu or menu == NO_MEAL:
            _log_skip_once(endpoint, slot, today, '오늘 해당 급식 정보 없음', info)
            continue
        body = _clip(', '.join(menu.split('\n')[:3]))
        jobs.append((endpoint, record['p256dh'], record['auth'], slot, f'🍱 오늘의 {label}', body, f'{today}-{key}', info))

    if not jobs:
        return 0

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda j: _send_one(j[0], j[1], j[2], j[4], j[5], j[6]), jobs))

    finished = []
    gone = set()
    for job, (endpoint, outcome, detail) in zip(jobs, results):
        info = job[7]
        if outcome == 'ok':
            logger.info(f'[push] 발송 성공({info}): {detail}')
        elif outcome == 'gone':
            logger.info(f'[push] 구독 만료로 삭제({info}): {detail}')
            gone.add(endpoint)
        elif outcome == 'fail':
            logger.warning(f'[push] 발송 실패({info}): {detail}')
        else:
            logger.warning(f'[push] 일시 오류로 다음 분에 재시도({info}): {detail}')
        if outcome in ('ok', 'fail'):
            finished.append((endpoint, job[3]))

    with _lock:
        for endpoint, slot in finished:
            record = _subs.get(endpoint)
            if record is None:
                continue
            if record['sent'].get('date') != today:
                record['sent'] = {'date': today, 'meals': []}
            if slot not in record['sent']['meals']:
                record['sent']['meals'].append(slot)
        for endpoint in gone:
            _subs.pop(endpoint, None)
        if finished or gone:
            _save_store(sync=bool(gone))
    return len(jobs)


def _admin_gate():
    check = _state.get('admin_check')
    if check is None:
        return make_response('관리자 인증이 설정되지 않았습니다.', 503)
    return check()


def _csrf_token():
    if not _state.get('csrf'):
        _state['csrf'] = secrets.token_hex(16)
    return _state['csrf']


def _csrf_ok():
    return hmac.compare_digest(request.form.get('csrf', ''), _csrf_token())


def _run_broadcast(snapshot, title, body, tag):
    logger = _state['logger']
    gone = set()
    try:
        pending = snapshot
        for attempt in range(2):
            retry = []
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = pool.map(lambda item: _send_one(item[0], item[1], item[2], title, body, tag), pending)
                for item, (endpoint, outcome, detail) in zip(pending, results):
                    with _broadcast_lock:
                        if outcome == 'ok':
                            _broadcast['ok'] += 1
                            _broadcast['done'] += 1
                        elif outcome == 'gone':
                            _broadcast['gone'] += 1
                            _broadcast['done'] += 1
                            gone.add(endpoint)
                        elif outcome == 'retry' and attempt == 0:
                            retry.append(item)
                        else:
                            _broadcast['fail'] += 1
                            _broadcast['done'] += 1
                            if len(_broadcast['errors']) < 10:
                                _broadcast['errors'].append(f'{_host(endpoint)}: {detail}')
            if not retry:
                break
            time.sleep(2)
            pending = retry
        if gone:
            with _lock:
                for endpoint in gone:
                    _subs.pop(endpoint, None)
                _save_store(sync=True)
    except Exception as e:
        logger.error(f'[push] 전체 발송 중 예외: {e}')
    finally:
        with _broadcast_lock:
            _broadcast['running'] = False
            _broadcast['finished'] = datetime.now(_state['tz']).strftime('%Y-%m-%d %H:%M:%S')
            summary = f"대상 {_broadcast['total']}건, 성공 {_broadcast['ok']}, 만료 삭제 {_broadcast['gone']}, 실패 {_broadcast['fail']}"
        logger.info(f'[push] 전체 발송 완료: {summary}')


def _start_broadcast(title, body):
    with _lock:
        snapshot = [(endpoint, record['p256dh'], record['auth']) for endpoint, record in _subs.items()]
    if not snapshot:
        return False, '구독자가 없습니다.'
    now = datetime.now(_state['tz'])
    with _broadcast_lock:
        if _broadcast['running']:
            return False, '이미 발송이 진행 중입니다.'
        _broadcast.update(running=True, started=now.strftime('%Y-%m-%d %H:%M:%S'), finished='', title=title, body=body,
                          total=len(snapshot), done=0, ok=0, gone=0, fail=0, errors=[])
    _state['logger'].info(f"[push] 전체 발송 시작: 대상 {len(snapshot)}건, 제목={title[:30]}, 내용={body[:50]}")
    threading.Thread(target=_run_broadcast, args=(snapshot, title, body, f'broadcast-{int(now.timestamp())}'), daemon=True).start()
    return True, ''


def _admin_page(result=None):
    esc = html.escape
    now = datetime.now(_state['tz'])
    scheduler = _state['scheduler']
    next_run = '-'
    running = False
    stale = False
    if scheduler:
        running = bool(scheduler.running)
        job = scheduler.get_job('push_send_due')
        if job is not None and job.next_run_time is not None:
            next_run = job.next_run_time.strftime('%Y-%m-%d %H:%M:%S')
            stale = (now - job.next_run_time).total_seconds() > 90
    today = now.strftime('%Y%m%d')
    with _lock:
        snapshot = [(endpoint, dict(record)) for endpoint, record in _subs.items()]

    weekday = (now.weekday() + 1) % 7
    meal_cache = {}

    def menu_for(record, key):
        school_key = (record['school_code'], record['region_code'])
        if school_key not in meal_cache:
            try:
                meal_cache[school_key] = _state['get_month_meals'](*school_key)
            except Exception:
                meal_cache[school_key] = None
        data = meal_cache[school_key]
        if data is None:
            return None
        menu = (data.get(today) or {}).get(key)
        return bool(menu and menu != NO_MEAL)

    def verdict(record, key):
        settings = record['settings']
        meal_setting = settings.get(key) or {}
        if not meal_setting.get('enabled'):
            return '꺼짐'
        slot = f"{key}@{meal_setting['time']}"
        head = f"{meal_setting['time']} - "
        if weekday not in settings.get('days', []):
            return head + f"오늘 요일 제외 (오늘={weekday})"
        has_menu = menu_for(record, key)
        menu_text = '급식 조회 실패' if has_menu is None else ('급식 있음' if has_menu else '오늘 급식 없음(발송 안 함)')
        time_state, minutes = _slot_time_state(now, meal_setting)
        sent = record['sent']['meals'] if record['sent'].get('date') == today else []
        if slot in sent:
            return head + '오늘 발송 처리됨'
        if time_state == 'wait':
            return head + f"{minutes}분 뒤 발송 예정 / {menu_text}"
        if time_state == 'late':
            return head + f"설정 시각이 {minutes}분 지나 오늘은 발송 안 함 / {menu_text}"
        return head + f"발송 가능 구간(다음 분 실행 때 발송) / {menu_text}"

    rows = []
    for endpoint, record in sorted(snapshot, key=lambda x: x[1]['school_code']):
        settings = record['settings']
        rows.append(
            '<tr>'
            f"<td>{esc(_endpoint_id(endpoint))}</td><td>{esc(_host(endpoint))}</td>"
            f"<td>{esc(record['school_code'])} / {esc(record['region_code'])}</td>"
            f"<td>{esc(','.join(str(d) for d in settings.get('days', [])))}</td>"
            f"<td>{esc(verdict(record, 'breakfast'))}</td><td>{esc(verdict(record, 'lunch'))}</td><td>{esc(verdict(record, 'dinner'))}</td>"
            '<td><form method="post" action="/admin/push/test">'
            f'<input type="hidden" name="csrf" value="{esc(_csrf_token())}">'
            f'<input type="hidden" name="id" value="{esc(_endpoint_id(endpoint))}">'
            '<button type="submit">테스트 발송</button></form></td>'
            '</tr>'
        )

    result_html = ''
    if result is not None:
        result_html = f'<h3>처리 결과</h3><pre>{esc(result)}</pre>'
    with _broadcast_lock:
        bc = dict(_broadcast)
        bc['errors'] = list(_broadcast['errors'])
    bc_status = ''
    if bc['started']:
        state_text = f"진행 중 ({bc['done']}/{bc['total']})" if bc['running'] else f"완료 {bc['finished']}"
        bc_status = (
            f"<p>마지막 전체 발송: {esc(bc['started'])} / {esc(state_text)}<br>"
            f"대상 {bc['total']}건, 성공 {bc['ok']}, 만료 삭제 {bc['gone']}, 실패 {bc['fail']}<br>"
            f"제목: {esc(bc['title'])} / 내용: {esc(bc['body'])}</p>"
        )
        if bc['errors']:
            bc_status += '<pre>' + esc('\n'.join(bc['errors'])) + '</pre>'
    broadcast_html = (
        '<h3>전체 발송</h3>'
        f"<form method=\"post\" action=\"/admin/push/broadcast\" onsubmit=\"return confirm('현재 구독 {len(snapshot)}건 모두에게 알림을 발송합니다. 계속할까요?')\">"
        f'<input type="hidden" name="csrf" value="{esc(_csrf_token())}">'
        f'<p><input name="title" maxlength="{MAX_TITLE_CHARS}" placeholder="제목 (비우면 급식알리미)" style="width:100%;box-sizing:border-box;padding:8px"></p>'
        f'<p><textarea id="bc-body" name="body" maxlength="{MAX_BODY_CHARS}" rows="3" required placeholder="내용" style="width:100%;box-sizing:border-box;padding:8px"></textarea></p>'
        f'<p><span id="bc-count">0 / {MAX_BODY_CHARS}</span> <button type="submit">전체 발송</button></p></form>'
        f"<script>var t=document.getElementById('bc-body'),c=document.getElementById('bc-count');t.addEventListener('input',function(){{c.textContent=t.value.length+' / {MAX_BODY_CHARS}'}});</script>"
        f'{bc_status}'
    )
    refresh = '<meta http-equiv="refresh" content="3">' if bc['running'] else ''
    status = [
        ('서버 시각(KST)', now.strftime('%Y-%m-%d %H:%M:%S') + f' (요일 번호 {(now.weekday() + 1) % 7}, 일=0)'),
        ('푸시 활성', '예' if push_enabled() else '아니오'),
        ('VAPID 공개키 앞 12자', VAPID_PUBLIC_KEY[:12]),
        ('VAPID subject', VAPID_SUBJECT),
        ('스케줄러', ('실행 중' if running else '중지') + f' / 다음 실행 {next_run}' + (' / 경고: 다음 실행 시각이 과거입니다. 이 프로세스에서 스케줄러가 동작하지 않습니다.' if stale else '')),
        ('프로세스', f"요청 처리 PID {os.getpid()} / 스케줄러 시작 PID {_state['started_pid']}"),
        ('구독 수', str(len(snapshot))),
        ('GitHub 백업', f"{'사용' if _gh_enabled() else '미사용'} / 레포 {GITHUB_REPO or '-'} / 복원 완료 {'예' if _remote['loaded'] else '아니오'}"),
        ('GitHub 마지막 복원', _remote['last_restore']),
        ('GitHub 마지막 저장', _remote['last_push']),
    ]
    status_html = ''.join(f'<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>' for k, v in status)
    return (
        '<!doctype html><html lang="ko"><head><meta charset="utf-8">'
        f'<meta name="viewport" content="width=device-width,initial-scale=1">{refresh}<title>푸시 진단</title>'
        '<style>body{font-family:sans-serif;margin:16px}table{border-collapse:collapse;margin-bottom:16px}'
        'th,td{border:1px solid #ccc;padding:6px 10px;font-size:14px;text-align:left}pre{background:#f4f4f4;padding:12px;white-space:pre-wrap}</style></head><body>'
        f'<h2>푸시 알림 진단</h2><table>{status_html}</table>{result_html}{broadcast_html}'
        '<h3>구독 목록</h3><table><tr><th>ID</th><th>푸시 서비스</th><th>학교 / 지역</th><th>요일</th><th>조식 판정</th><th>중식 판정</th><th>석식 판정</th><th></th></tr>'
        f"{''.join(rows) or '<tr><td colspan=8>구독 없음</td></tr>'}</table></body></html>"
    )


@push_bp.route('/admin/push')
def admin_push():
    denied = _admin_gate()
    if denied is not None:
        return denied
    return _admin_page()


@push_bp.route('/admin/push/test', methods=['POST'])
def admin_push_test():
    denied = _admin_gate()
    if denied is not None:
        return denied
    if not _csrf_ok():
        return _admin_page('요청이 만료되었거나 유효하지 않습니다. 페이지를 새로고침한 뒤 다시 시도하세요.'), 403
    target = request.form.get('id', '')
    with _lock:
        match = [(endpoint, dict(record)) for endpoint, record in _subs.items() if _endpoint_id(endpoint) == target]
    if not match:
        return _admin_page('해당 ID의 구독을 찾을 수 없습니다.'), 404
    endpoint, record = match[0]
    _, outcome, detail = _send_one(endpoint, record['p256dh'], record['auth'], '급식알리미 테스트', '이 알림이 보이면 서버에서 기기까지의 발송 경로는 정상입니다.', 'push-test')
    return _admin_page(f'대상: {_host(endpoint)} ({target})\n결과: {outcome}\n상세: {detail}')


@push_bp.route('/admin/push/broadcast', methods=['POST'])
def admin_push_broadcast():
    denied = _admin_gate()
    if denied is not None:
        return denied
    if not _csrf_ok():
        return _admin_page('요청이 만료되었거나 유효하지 않습니다. 페이지를 새로고침한 뒤 다시 시도하세요.'), 403
    title = (request.form.get('title') or '').strip() or '급식알리미'
    body = (request.form.get('body') or '').strip()
    if not body:
        return _admin_page('내용을 입력해 주세요.'), 400
    if len(title) > MAX_TITLE_CHARS or len(body) > MAX_BODY_CHARS:
        return _admin_page(f'제목은 {MAX_TITLE_CHARS}자, 내용은 {MAX_BODY_CHARS}자 이내로 입력해 주세요.'), 400
    started, message = _start_broadcast(title, body)
    if not started:
        return _admin_page(message), 409
    return redirect('/admin/push')


def _safe_send_due():
    try:
        send_due()
    except Exception as e:
        _state['logger'].error(f'send_due failed: {e}')


def ensure_started():
    pid = os.getpid()
    if _state['started_pid'] == pid or not _state['configured'] or not push_enabled():
        return
    with _init_lock:
        if _state['started_pid'] == pid:
            return
        _state['started_pid'] = pid
        logger = _state['logger']
        _load_store()
        logger.info(f'푸시 기능 시작(PID {pid}): 로컬 구독 {len(_subs)}건, GitHub 백업 {"사용" if _gh_enabled() else "미사용"}')
        if _gh_enabled():
            threading.Thread(target=_initial_restore, daemon=True).start()
            atexit.register(_flush_remote)
        else:
            logger.warning('푸시 구독 GitHub 백업 비활성: PUSH_GITHUB_REPO / PUSH_GITHUB_TOKEN(또는 GITHUB_TOKEN)이 설정되지 않았습니다.')
        scheduler = BackgroundScheduler(timezone=_state['tz'])
        scheduler.add_job(_safe_send_due, 'cron', minute='*', max_instances=1, coalesce=True, id='push_send_due')
        scheduler.start()
        _state['scheduler'] = scheduler


def _reset_after_fork():
    global _lock, _remote_lock, _gh_io_lock, _init_lock, _broadcast_lock
    _broadcast_lock = threading.Lock()
    _lock = threading.Lock()
    _remote_lock = threading.Lock()
    _gh_io_lock = threading.Lock()
    _init_lock = threading.Lock()
    _remote.update(loaded=False, sha=None, pushed_hash=None, pending=False, last_restore='-', last_push='-')
    _broadcast.update(running=False)
    _state['csrf'] = None
    _logged_skips.clear()
    _subs.clear()
    _state['scheduler'] = None
    _state['started_pid'] = None


if hasattr(os, 'register_at_fork'):
    os.register_at_fork(after_in_child=_reset_after_fork)


@push_bp.before_app_request
def _start_on_request():
    ensure_started()


def init_push(app, get_month_meals, tz, store_path, admin_check=None):
    with _init_lock:
        if _state['configured']:
            return
        _state.update(path=store_path, get_month_meals=get_month_meals, tz=tz, logger=app.logger, admin_check=admin_check, configured=True)
        app.register_blueprint(push_bp)
        if not push_enabled():
            app.logger.warning('Web push disabled: VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY / VAPID_SUBJECT 환경변수가 설정되지 않았습니다.')
