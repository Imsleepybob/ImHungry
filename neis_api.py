import os
import re
import threading
import time
from collections import OrderedDict
from datetime import datetime, timedelta, timezone

import requests

KST = timezone(timedelta(hours=9))
BASE_URL = 'https://open.neis.go.kr/hub/'
KEY_RE = re.compile(r'^[A-Za-z0-9]{16,64}$')
DAILY_LIMIT_CODES = {'ERROR-337'}
KEY_PROBLEM_CODES = {'INFO-300', 'ERROR-290', 'INFO-100'}
KEY_PROBLEM_BLOCK_SECONDS = 3600


class KeyPool:
    def __init__(self, keys=()):
        self._lock = threading.Lock()
        self._keys = []
        self._blocked = {}
        self._cursor = 0
        for key in keys:
            self.add(key)

    def add(self, key):
        key = (key or '').strip()
        if not KEY_RE.match(key):
            return False
        with self._lock:
            if key in self._keys:
                return False
            self._keys.append(key)
        return True

    def size(self):
        with self._lock:
            return len(self._keys)

    def candidates(self):
        now = time.time()
        with self._lock:
            count = len(self._keys)
            if not count:
                return []
            start = self._cursor % count
            self._cursor = (self._cursor + 1) % count
            ordered = [self._keys[(start + offset) % count] for offset in range(count)]
            return [key for key in ordered if self._blocked.get(key, 0) <= now]

    def block(self, key, code):
        if code in DAILY_LIMIT_CODES:
            now = datetime.now(KST)
            tomorrow = (now + timedelta(days=1)).replace(hour=0, minute=1, second=0, microsecond=0)
            until = tomorrow.timestamp()
        else:
            until = time.time() + KEY_PROBLEM_BLOCK_SECONDS
        with self._lock:
            self._blocked[key] = until

    def status(self):
        now = time.time()
        with self._lock:
            return [
                {'tail': key[-4:], 'blocked': self._blocked.get(key, 0) > now,
                 'until': self._blocked.get(key, 0)}
                for key in self._keys
            ]


POOL = KeyPool()


def configure(legacy_key=''):
    for key in (os.environ.get('NEIS_API_KEYS') or '').split(','):
        POOL.add(key)
    POOL.add(legacy_key)
    return POOL


def result_code(data):
    if not isinstance(data, dict):
        return ''
    result = data.get('RESULT')
    if isinstance(result, dict):
        return str(result.get('CODE') or '')
    for value in data.values():
        if isinstance(value, list):
            for block in value:
                if not isinstance(block, dict):
                    continue
                head = block.get('head')
                if isinstance(head, list):
                    for item in head:
                        if isinstance(item, dict) and isinstance(item.get('RESULT'), dict):
                            return str(item['RESULT'].get('CODE') or '')
    return ''


def extract_rows(data, endpoint):
    if not isinstance(data, dict):
        return []
    blocks = data.get(endpoint)
    if not isinstance(blocks, list):
        return []
    for block in blocks:
        if isinstance(block, dict) and isinstance(block.get('row'), list):
            return [row for row in block['row'] if isinstance(row, dict)]
    return []


def total_count(data, endpoint):
    if not isinstance(data, dict):
        return 0
    blocks = data.get(endpoint)
    if not isinstance(blocks, list):
        return 0
    for block in blocks:
        if isinstance(block, dict) and isinstance(block.get('head'), list):
            for item in block['head']:
                if isinstance(item, dict) and 'list_total_count' in item:
                    try:
                        return int(item['list_total_count'])
                    except (TypeError, ValueError):
                        return 0
    return 0


class NeisUnavailable(Exception):
    pass


def request_json(endpoint, params, timeout=5):
    keys = POOL.candidates()
    if not keys:
        raise NeisUnavailable('사용 가능한 NEIS API 키가 없습니다.')
    last = None
    for key in keys:
        query = dict(params)
        query['KEY'] = key
        query.setdefault('Type', 'json')
        response = requests.get(BASE_URL + endpoint, params=query, timeout=timeout)
        response.raise_for_status()
        data = response.json()
        code = result_code(data)
        if code in DAILY_LIMIT_CODES or code in KEY_PROBLEM_CODES:
            POOL.block(key, code)
            last = data
            continue
        return data
    if last is not None:
        return last
    raise NeisUnavailable('NEIS API 호출에 실패했습니다.')


def fetch_rows(endpoint, params, timeout=5):
    data = request_json(endpoint, params, timeout=timeout)
    code = result_code(data)
    rows = extract_rows(data, endpoint)
    return rows, code


class TTLCache:
    def __init__(self, max_items=2000):
        self._data = OrderedDict()
        self._lock = threading.Lock()
        self._max = max_items

    def get(self, key, allow_stale=False):
        now = time.time()
        with self._lock:
            entry = self._data.get(key)
            if not entry:
                return None
            expires, value = entry
            if allow_stale or now < expires:
                self._data.move_to_end(key)
                return value
            return None

    def set(self, key, value, ttl):
        with self._lock:
            self._data[key] = (time.time() + ttl, value)
            self._data.move_to_end(key)
            while len(self._data) > self._max:
                self._data.popitem(last=False)

    def size(self):
        with self._lock:
            return len(self._data)