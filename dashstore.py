import atexit
import base64
import hashlib
import json
import os
import re
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import requests

import dashagg

GITHUB_TOKEN = (os.environ.get('PUSH_GITHUB_TOKEN') or os.environ.get('GITHUB_TOKEN', '')).strip()
GITHUB_REPO = os.environ.get('PUSH_GITHUB_REPO', '').strip()
GITHUB_BRANCH = os.environ.get('PUSH_GITHUB_BRANCH', 'main').strip()
GITHUB_DIR = os.environ.get('DASH_GITHUB_DIR', 'dashboard').strip().strip('/')
GITHUB_API = 'https://api.github.com'
SYNC_INTERVAL = 600
PUSH_INTERVAL = 21600
REFRESH_INTERVAL = 120
RETENTION_DAYS = 90
DAY_FILE_RE = re.compile(r'^(\d{4}-\d{2}-\d{2})\.json$')


def _dumps(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


class DashStore:
    def __init__(self, local_dir, tz, logger, security_merge=None):
        self.local_dir = local_dir
        self.tz = tz
        self.logger = logger
        self.security_merge = security_merge
        self.lock = threading.RLock()
        self.io_lock = threading.Lock()
        self.parts = {}
        self.live = {}
        self.ipinfo = {}
        self.security = {}
        self.dirty = set()
        self.remote = {}
        self.persisted_hash = {}
        self.boot_id = None
        self.started_pid = None
        self.restored = False
        self.restore_note = '-'
        self.sync_note = '-'
        self.on_restored = []
        self.stop = threading.Event()
        self.tick_hook = None
        self.put_count = 0
        self.api = GITHUB_API

    def gh_enabled(self):
        return bool(GITHUB_TOKEN and GITHUB_REPO)

    def _headers(self, accept):
        return {'Authorization': f'Bearer {GITHUB_TOKEN}', 'Accept': accept, 'X-GitHub-Api-Version': '2022-11-28'}

    def _url(self, path):
        return f'{self.api}/repos/{GITHUB_REPO}/contents/{GITHUB_DIR}/{path}'

    def _key_path(self, key):
        return f'days/{key[4:]}.json' if key.startswith('day:') else f'{key}.json'

    def _local_path(self, key):
        return os.path.join(self.local_dir, self._key_path(key).replace('/', os.sep))

    def _note(self, kind, ok, message):
        stamp = datetime.now(self.tz).strftime('%Y-%m-%d %H:%M:%S')
        setattr(self, kind + '_note', f"{stamp} {'성공' if ok else '실패'} - {message}")

    def doc_for(self, key):
        with self.lock:
            if key.startswith('day:'):
                return {'date': key[4:], 'parts': self.parts.get(key[4:], {})}
            if key == 'ipinfo':
                return self.ipinfo
            return self.security

    def write_local(self, key):
        path = self._local_path(key)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + '.tmp'
        with open(tmp, 'wb') as f:
            f.write(_dumps(self.doc_for(key)))
        os.replace(tmp, path)

    def load_local(self):
        base = os.path.join(self.local_dir, 'days')
        if os.path.isdir(base):
            for name in os.listdir(base):
                match = DAY_FILE_RE.match(name)
                if not match:
                    continue
                try:
                    with open(os.path.join(base, name), 'r', encoding='utf-8') as f:
                        doc = json.load(f)
                    self._merge_day(match.group(1), doc.get('parts') or {})
                except (OSError, ValueError):
                    continue
        for key in ('ipinfo', 'security'):
            try:
                with open(self._local_path(key), 'r', encoding='utf-8') as f:
                    doc = json.load(f)
                if key == 'ipinfo':
                    self._merge_ipinfo(doc)
                else:
                    self._merge_security(doc)
            except (OSError, ValueError):
                continue

    def _rel_cutoff(self):
        return (datetime.now(self.tz).date() - timedelta(days=dashagg.REL_RETENTION_DAYS)).isoformat()

    def _merge_day(self, date_str, parts):
        if date_str < self._rel_cutoff():
            for agg in parts.values():
                if isinstance(agg, dict):
                    agg.pop('rel', None)
                    agg.pop('ua_names', None)
        with self.lock:
            mine = self.parts.setdefault(date_str, {})
            for boot, agg in parts.items():
                if boot != self.boot_id and boot not in mine:
                    mine[boot] = agg

    def _merge_ipinfo(self, doc):
        with self.lock:
            for ip, value in (doc or {}).items():
                if not isinstance(value, list) or len(value) != 2:
                    continue
                current = self.ipinfo.get(ip)
                if current is None or value[0] > current[0]:
                    self.ipinfo[ip] = value

    def _merge_security(self, doc):
        with self.lock:
            if self.security_merge:
                self.security = self.security_merge(self.security, doc or {})
            elif not self.security:
                self.security = doc or {}

    def stored_parts(self, date_str):
        with self.lock:
            return [agg for boot, agg in self.parts.get(date_str, {}).items() if boot != self.boot_id]

    def prune_rel(self):
        cutoff = self._rel_cutoff()
        with self.lock:
            for date_str, parts in self.parts.items():
                if date_str >= cutoff:
                    continue
                changed = False
                for agg in parts.values():
                    if isinstance(agg, dict) and ('rel' in agg or 'ua_names' in agg):
                        agg.pop('rel', None)
                        agg.pop('ua_names', None)
                        changed = True
                if changed:
                    key = 'day:' + date_str
                    self.dirty.add(key)
                    self.write_local(key)

    def with_days(self, today, days, fn):
        _, dates = dashagg.window_dates(today, days)
        with self.lock:
            raw = {}
            for date_str in dates:
                aggs = self.stored_parts(date_str)
                if date_str in self.live:
                    aggs = aggs + [self.live[date_str]]
                if aggs:
                    raw[date_str] = aggs
            return fn(raw)

    def merged_days(self, today, days, with_rel=True):
        _, dates = dashagg.window_dates(today, days)
        out = {}
        with self.lock:
            for date_str in dates:
                aggs = self.stored_parts(date_str)
                if date_str in self.live:
                    aggs = aggs + [self.live[date_str]]
                if not aggs:
                    continue
                total = dashagg.new_agg()
                for agg in aggs:
                    dashagg.merge(total, agg, with_rel=with_rel)
                out[date_str] = total
        return out

    def persist_live(self):
        with self.lock:
            for date_str, agg in self.live.items():
                packed = dashagg.compact(agg)
                digest = hashlib.sha256(_dumps(packed)).hexdigest()
                key = 'day:' + date_str
                if self.persisted_hash.get(key) == digest:
                    continue
                self.persisted_hash[key] = digest
                self.parts.setdefault(date_str, {})[self.boot_id] = packed
                self.dirty.add(key)
                self.write_local(key)

    def set_security(self, doc):
        with self.lock:
            self.security = doc
            self.dirty.add('security')
            self.write_local('security')

    def touch_ipinfo(self, entries):
        with self.lock:
            changed = False
            for ip, value in entries.items():
                current = self.ipinfo.get(ip)
                if current is None or current[0] != value[0]:
                    self.ipinfo[ip] = value
                    changed = True
            if changed:
                self.dirty.add('ipinfo')
                self.write_local('ipinfo')

    def _list_remote_days(self):
        resp = requests.get(self._url('days'), headers=self._headers('application/vnd.github+json'), params={'ref': GITHUB_BRANCH}, timeout=15)
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        return resp.json()

    def _fetch_raw(self, path):
        resp = requests.get(self._url(path), headers=self._headers('application/vnd.github.raw+json'), params={'ref': GITHUB_BRANCH}, timeout=20)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.content

    def _fetch_sha(self, path):
        resp = requests.get(self._url(path), headers=self._headers('application/vnd.github.object+json'), params={'ref': GITHUB_BRANCH}, timeout=10)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json().get('sha')

    def restore_remote(self):
        cutoff = (datetime.now(self.tz).date() - timedelta(days=RETENTION_DAYS)).isoformat()
        listing = self._list_remote_days()
        wanted = []
        stale = []
        for item in listing:
            match = DAY_FILE_RE.match(item.get('name', ''))
            if not match:
                continue
            (stale if match.group(1) < cutoff else wanted).append((match.group(1), item))

        def fetch(entry):
            date_str, item = entry
            raw = self._fetch_raw('days/' + item['name'])
            return date_str, item.get('sha'), raw

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(fetch, wanted))
        loaded_days = 0
        for date_str, sha, raw in results:
            if raw is None:
                continue
            doc = json.loads(raw.decode('utf-8'))
            self._merge_day(date_str, doc.get('parts') or {})
            self.remote['day:' + date_str] = {'sha': sha, 'hash': hashlib.sha256(raw).hexdigest()}
            loaded_days += 1
        for key in ('ipinfo', 'security'):
            raw = self._fetch_raw(f'{key}.json')
            if raw is None:
                continue
            doc = json.loads(raw.decode('utf-8'))
            if key == 'ipinfo':
                self._merge_ipinfo(doc)
            else:
                self._merge_security(doc)
            self.remote[key] = {'sha': self._fetch_sha(f'{key}.json'), 'hash': hashlib.sha256(raw).hexdigest()}
        for date_str, item in stale:
            try:
                requests.delete(self._url('days/' + item['name']), headers=self._headers('application/vnd.github+json'),
                                json={'message': f'chore: 보관 기간 지난 대시보드 기록 삭제 ({date_str})', 'sha': item['sha'], 'branch': GITHUB_BRANCH}, timeout=15)
            except requests.RequestException:
                pass
        with self.lock:
            for date_str in list(self.parts):
                if date_str < cutoff:
                    self.parts.pop(date_str, None)
            for key in ('ipinfo', 'security'):
                self.dirty.add(key)
            for date_str in self.parts:
                self.dirty.add('day:' + date_str)
        self.restored = True
        self._note('restore', True, f'일 단위 기록 {loaded_days}일, IP 정보 {len(self.ipinfo)}건 복원')
        self.logger.info(f'[dashboard] GitHub 복원 완료: 일 단위 기록 {loaded_days}일, IP 정보 {len(self.ipinfo)}건')
        for hook in self.on_restored:
            try:
                hook()
            except Exception as e:
                self.logger.error(f'[dashboard] 복원 후처리 실패: {e}')

    def refresh_remote(self):
        cutoff = (datetime.now(self.tz).date() - timedelta(days=RETENTION_DAYS)).isoformat()
        merged = 0
        for item in self._list_remote_days():
            match = DAY_FILE_RE.match(item.get('name', ''))
            if not match or match.group(1) < cutoff:
                continue
            key = 'day:' + match.group(1)
            if (self.remote.get(key) or {}).get('sha') == item.get('sha'):
                continue
            raw = self._fetch_raw('days/' + item['name'])
            if raw is None:
                continue
            self._merge_day(match.group(1), json.loads(raw.decode('utf-8')).get('parts') or {})
            self.remote[key] = {'sha': item.get('sha'), 'hash': hashlib.sha256(raw).hexdigest()}
            self.dirty.add(key)
            merged += 1
        for key in ('ipinfo', 'security'):
            sha = self._fetch_sha(f'{key}.json')
            if not sha or sha == (self.remote.get(key) or {}).get('sha'):
                continue
            raw = self._fetch_raw(f'{key}.json')
            if raw is None:
                continue
            doc = json.loads(raw.decode('utf-8'))
            if key == 'ipinfo':
                self._merge_ipinfo(doc)
            else:
                self._merge_security(doc)
            self.remote[key] = {'sha': sha, 'hash': hashlib.sha256(raw).hexdigest()}
            self.dirty.add(key)
            merged += 1
        if merged:
            self.logger.info(f'[dashboard] 다른 인스턴스가 저장한 기록 {merged}건을 병합했습니다')
        return merged

    def _push_key(self, key):
        path = self._key_path(key)
        for attempt in range(2):
            payload = _dumps(self.doc_for(key))
            digest = hashlib.sha256(payload).hexdigest()
            known = self.remote.get(key) or {}
            if digest == known.get('hash'):
                return True
            body = {
                'message': f"chore: 대시보드 기록 갱신 ({datetime.now(self.tz).strftime('%Y-%m-%d %H:%M:%S')}) {key}",
                'content': base64.b64encode(payload).decode('ascii'),
                'branch': GITHUB_BRANCH,
            }
            sha = known.get('sha')
            if sha:
                body['sha'] = sha
            resp = requests.put(self._url(path), headers=self._headers('application/vnd.github+json'), json=body, timeout=30)
            if resp.status_code in (200, 201):
                self.remote[key] = {'sha': resp.json()['content']['sha'], 'hash': digest}
                self.put_count += 1
                return True
            if resp.status_code in (409, 422) and attempt == 0:
                raw = self._fetch_raw(path)
                if raw is not None:
                    doc = json.loads(raw.decode('utf-8'))
                    if key.startswith('day:'):
                        self._merge_day(key[4:], doc.get('parts') or {})
                    elif key == 'ipinfo':
                        self._merge_ipinfo(doc)
                    else:
                        self._merge_security(doc)
                self.remote[key] = {'sha': self._fetch_sha(path), 'hash': None}
                continue
            self.logger.error(f'[dashboard] GitHub 저장 실패({key}): {resp.status_code} {resp.text[:150]}')
            self._note('sync', False, f'{key} HTTP {resp.status_code}')
            return False
        return False

    def sync(self, push=True):
        if self.tick_hook:
            try:
                self.tick_hook()
            except Exception as e:
                self.logger.error(f'[dashboard] 로그 집계 실패: {e}')
        self.prune_rel()
        self.persist_live()
        if not push or not self.gh_enabled():
            return
        with self.io_lock:
            with self.lock:
                keys = sorted(self.dirty)
            done = []
            failed = 0
            put_before = self.put_count
            for key in keys:
                try:
                    if self._push_key(key):
                        done.append(key)
                    else:
                        failed += 1
                except Exception as e:
                    failed += 1
                    self._note('sync', False, f'{key} {type(e).__name__}: {str(e)[:120]}')
                    self.logger.error(f'[dashboard] GitHub 저장 예외({key}): {e}')
            with self.lock:
                for key in done:
                    self.dirty.discard(key)
            if done and not failed:
                self._note('sync', True, f'변경된 파일 {self.put_count - put_before}개 저장 (확인 {len(done)}개)')

    def _loop(self):
        next_restore = 0
        next_refresh = time.time() + REFRESH_INTERVAL
        next_sync = 0
        next_push = time.time() + PUSH_INTERVAL
        while not self.stop.is_set():
            now = time.time()
            if self.gh_enabled() and not self.restored and now >= next_restore:
                try:
                    with self.io_lock:
                        self.restore_remote()
                except Exception as e:
                    self._note('restore', False, f'{type(e).__name__}: {str(e)[:150]}')
                    self.logger.error(f'[dashboard] GitHub 복원 실패: {e}')
                    next_restore = time.time() + 120
            if self.gh_enabled() and self.restored and now >= next_refresh:
                try:
                    with self.io_lock:
                        self.refresh_remote()
                except Exception as e:
                    self.logger.error(f'[dashboard] GitHub 병합 실패: {e}')
                next_refresh = time.time() + REFRESH_INTERVAL
            if now >= next_sync:
                push = now >= next_push
                try:
                    self.sync(push=push)
                except Exception as e:
                    self.logger.error(f'[dashboard] 동기화 예외: {e}')
                if push:
                    next_push = time.time() + PUSH_INTERVAL
                next_sync = time.time() + SYNC_INTERVAL
            self.stop.wait(2)

    def save_now(self):
        self.sync()
        return self.sync_note

    def flush(self):
        try:
            if self.tick_hook:
                self.tick_hook()
            self.persist_live()
            if self.gh_enabled() and self.io_lock.acquire(timeout=15):
                try:
                    for key in sorted(self.dirty):
                        self._push_key(key)
                finally:
                    self.io_lock.release()
        except Exception as e:
            self.logger.error(f'[dashboard] 종료 시 저장 실패: {e}')

    def start(self):
        pid = os.getpid()
        if self.started_pid == pid:
            return
        with self.lock:
            if self.started_pid == pid:
                return
            self.started_pid = pid
            self.boot_id = f"{time.strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(3)}"
            self.load_local()
        self.logger.info(f'[dashboard] 기록 저장소 시작(PID {pid}, boot {self.boot_id}): 로컬 {len(self.parts)}일, GitHub {"사용" if self.gh_enabled() else "미사용"}')
        threading.Thread(target=self._loop, daemon=True).start()
        atexit.register(self.flush)

    def reset_after_fork(self):
        self.lock = threading.RLock()
        self.io_lock = threading.Lock()
        self.stop = threading.Event()
        self.started_pid = None
        self.boot_id = None
        self.live = {}
        self.parts = {}
        self.ipinfo = {}
        self.security = {}
        self.dirty = set()
        self.remote = {}
        self.persisted_hash = {}
        self.restored = False
