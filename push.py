import base64
import hashlib
import html
import json
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import urlparse

import requests
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Blueprint, jsonify, request, send_from_directory, make_response
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
ALLOWED_PUSH_HOSTS = ('.googleapis.com', '.push.services.mozilla.com', '.push.apple.com', '.notify.windows.com')

TIME_RE = re.compile(r'^([01]\d|2[0-3]):[0-5]\d$')
SCHOOL_RE = re.compile(r'^\d{5,10}$')
REGION_RE = re.compile(r'^[A-Z]\d{2}$')

_state = {'path': None, 'get_month_meals': None, 'tz': None, 'logger': None, 'scheduler': None, 'admin_check': None}
_subs = {}
_lock = threading.Lock()
_init_lock = threading.Lock()
_remote = {'loaded': False, 'sha': None, 'pushed_hash': None, 'pending': False}
_remote_lock = threading.Lock()
_gh_io_lock = threading.Lock()


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
    _state['logger'].info(f'푸시 구독 GitHub 복원 완료: 현재 {len(_subs)}건')


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
            _state['logger'].info('푸시 구독 GitHub 동기화 완료')
            return True
        if resp.status_code in (409, 422) and attempt == 0:
            _restore_remote()
            continue
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


def _initial_restore():
    with _gh_io_lock:
        try:
            _restore_remote()
            restored = True
        except Exception as e:
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
            hours, minutes = map(int, meal_setting['time'].split(':'))
            due = now.replace(hour=hours, minute=minutes, second=0, microsecond=0)
            elapsed = (now - due).total_seconds()
            if not 0 <= elapsed < GRACE_SECONDS:
                continue
            slot = f"{key}@{meal_setting['time']}"
            info = f"{label} {meal_setting['time']} school={record['school_code']} host={_host(endpoint)}"
            if weekday not in settings.get('days', []):
                if elapsed < 60:
                    logger.info(f"[push] 건너뜀({info}): 오늘 요일이 알림 요일에 없음 (오늘={weekday}, 설정={settings.get('days')})")
                continue
            if slot in already:
                continue
            candidates.append((endpoint, record, key, label, slot, info, elapsed))

    meal_cache = {}
    jobs = []
    for endpoint, record, key, label, slot, info, elapsed in candidates:
        school_key = (record['school_code'], record['region_code'])
        if school_key not in meal_cache:
            try:
                meal_cache[school_key] = _state['get_month_meals'](*school_key)
            except Exception as e:
                logger.error(f'[push] 급식 조회 실패 {school_key}: {e}')
                meal_cache[school_key] = {}
        menu = (meal_cache[school_key].get(today) or {}).get(key)
        if not menu or menu == NO_MEAL:
            if elapsed < 60:
                logger.info(f'[push] 건너뜀({info}): 오늘 해당 급식 정보 없음')
            continue
        body = ', '.join(menu.split('\n')[:3])
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


def _admin_page(result=None):
    esc = html.escape
    now = datetime.now(_state['tz'])
    scheduler = _state['scheduler']
    next_run = '-'
    running = False
    if scheduler:
        running = bool(scheduler.running)
        job = scheduler.get_job('push_send_due')
        if job is not None and job.next_run_time is not None:
            next_run = job.next_run_time.strftime('%Y-%m-%d %H:%M:%S')
    today = now.strftime('%Y%m%d')
    with _lock:
        snapshot = [(endpoint, dict(record)) for endpoint, record in _subs.items()]

    rows = []
    for endpoint, record in sorted(snapshot, key=lambda x: x[1]['school_code']):
        settings = record['settings']
        meals = []
        for key, label in MEALS:
            m = settings.get(key) or {}
            meals.append(f"{m['time']} (켬)" if m.get('enabled') else '꺼짐')
        sent = ', '.join(record['sent']['meals']) if record['sent'].get('date') == today and record['sent']['meals'] else '-'
        rows.append(
            '<tr>'
            f"<td>{esc(_endpoint_id(endpoint))}</td><td>{esc(_host(endpoint))}</td>"
            f"<td>{esc(record['school_code'])} / {esc(record['region_code'])}</td>"
            f"<td>{esc(','.join(str(d) for d in settings.get('days', [])))}</td>"
            f"<td>{esc(meals[0])}</td><td>{esc(meals[1])}</td><td>{esc(meals[2])}</td><td>{esc(sent)}</td>"
            '<td><form method="post" action="/admin/push/test">'
            f'<input type="hidden" name="id" value="{esc(_endpoint_id(endpoint))}">'
            '<button type="submit">테스트 발송</button></form></td>'
            '</tr>'
        )

    result_html = ''
    if result is not None:
        result_html = f'<h3>테스트 발송 결과</h3><pre>{esc(result)}</pre>'
    status = [
        ('서버 시각(KST)', now.strftime('%Y-%m-%d %H:%M:%S') + f' (요일 번호 {(now.weekday() + 1) % 7}, 일=0)'),
        ('푸시 활성', '예' if push_enabled() else '아니오'),
        ('VAPID 공개키 앞 12자', VAPID_PUBLIC_KEY[:12]),
        ('VAPID subject', VAPID_SUBJECT),
        ('스케줄러', ('실행 중' if running else '중지') + f' / 다음 실행 {next_run}'),
        ('구독 수', str(len(snapshot))),
        ('GitHub 백업', f"{'사용' if _gh_enabled() else '미사용'} / 레포 {GITHUB_REPO or '-'} / 복원 완료 {'예' if _remote['loaded'] else '아니오'}"),
    ]
    status_html = ''.join(f'<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>' for k, v in status)
    return (
        '<!doctype html><html lang="ko"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1"><title>푸시 진단</title>'
        '<style>body{font-family:sans-serif;margin:16px}table{border-collapse:collapse;margin-bottom:16px}'
        'th,td{border:1px solid #ccc;padding:6px 10px;font-size:14px;text-align:left}pre{background:#f4f4f4;padding:12px;white-space:pre-wrap}</style></head><body>'
        f'<h2>푸시 알림 진단</h2><table>{status_html}</table>{result_html}'
        '<h3>구독 목록</h3><table><tr><th>ID</th><th>푸시 서비스</th><th>학교 / 지역</th><th>요일</th><th>조식</th><th>중식</th><th>석식</th><th>오늘 발송 기록</th><th></th></tr>'
        f"{''.join(rows) or '<tr><td colspan=9>구독 없음</td></tr>'}</table></body></html>"
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
    target = request.form.get('id', '')
    with _lock:
        match = [(endpoint, dict(record)) for endpoint, record in _subs.items() if _endpoint_id(endpoint) == target]
    if not match:
        return _admin_page('해당 ID의 구독을 찾을 수 없습니다.'), 404
    endpoint, record = match[0]
    _, outcome, detail = _send_one(endpoint, record['p256dh'], record['auth'], '급식알리미 테스트', '이 알림이 보이면 서버에서 기기까지의 발송 경로는 정상입니다.', 'push-test')
    return _admin_page(f'대상: {_host(endpoint)} ({target})\n결과: {outcome}\n상세: {detail}')


def _safe_send_due():
    try:
        send_due()
    except Exception as e:
        _state['logger'].error(f'send_due failed: {e}')


def init_push(app, get_month_meals, tz, store_path, admin_check=None):
    with _init_lock:
        if _state['scheduler'] is not None:
            return
        _state.update(path=store_path, get_month_meals=get_month_meals, tz=tz, logger=app.logger, admin_check=admin_check)
        app.register_blueprint(push_bp)
        if not push_enabled():
            app.logger.warning('Web push disabled: VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY / VAPID_SUBJECT 환경변수가 설정되지 않았습니다.')
            _state['scheduler'] = False
            return
        _load_store()
        app.logger.info(f'푸시 기능 시작: 로컬 구독 {len(_subs)}건, GitHub 백업 {"사용" if _gh_enabled() else "미사용"}')
        if _gh_enabled():
            threading.Thread(target=_initial_restore, daemon=True).start()
        else:
            app.logger.warning('푸시 구독 GitHub 백업 비활성: PUSH_GITHUB_REPO / PUSH_GITHUB_TOKEN(또는 GITHUB_TOKEN)이 설정되지 않았습니다.')
        scheduler = BackgroundScheduler(timezone=tz)
        scheduler.add_job(_safe_send_due, 'cron', minute='*', max_instances=1, coalesce=True, id='push_send_due')
        scheduler.start()
        _state['scheduler'] = scheduler
