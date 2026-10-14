import hashlib
import hmac
import secrets
import threading
import time
from datetime import datetime

MAX_TRAIL = 300
MAX_WATCHED = 300
MAX_INCIDENTS = 500


def verify_password(password, stored):
    stored = (stored or '').strip().strip('"\'').strip()
    if not stored:
        return False
    if stored.startswith('pbkdf2_sha256$'):
        try:
            _, iterations, salt, digest = stored.split('$', 3)
            calc = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), int(iterations)).hex()
        except (ValueError, TypeError):
            return False
        return hmac.compare_digest(calc, digest.lower())
    return hmac.compare_digest(hashlib.sha256(password.encode('utf-8')).hexdigest(), stored.lower())


def make_password_hash(password, iterations=600000):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), iterations).hex()
    return f'pbkdf2_sha256${iterations}${salt}${digest}'


class LoginGuard:
    def __init__(self, limit=3, window=3600):
        self.limit = limit
        self.window = window
        self.lock = threading.Lock()
        self.fails = {}

    def failure(self, ip):
        now = time.time()
        with self.lock:
            kept = [t for t in self.fails.get(ip, []) if now - t < self.window]
            kept.append(now)
            self.fails[ip] = kept
            if len(self.fails) > 5000:
                for key in [k for k, v in self.fails.items() if not v or now - v[-1] >= self.window]:
                    self.fails.pop(key, None)
            return len(kept)

    def count(self, ip):
        now = time.time()
        with self.lock:
            return len([t for t in self.fails.get(ip, []) if now - t < self.window])

    def success(self, ip):
        with self.lock:
            self.fails.pop(ip, None)


class SessionStore:
    def __init__(self, ttl=8 * 3600, max_sessions=20):
        self.ttl = ttl
        self.max_sessions = max_sessions
        self.lock = threading.Lock()
        self.sessions = {}

    def create(self):
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self.lock:
            for key in [k for k, exp in self.sessions.items() if exp <= now]:
                self.sessions.pop(key, None)
            while len(self.sessions) >= self.max_sessions:
                self.sessions.pop(min(self.sessions, key=self.sessions.get), None)
            self.sessions[token] = now + self.ttl
        return token

    def valid(self, token):
        if not token:
            return False
        with self.lock:
            expires = self.sessions.get(token)
            if expires is None:
                return False
            if expires <= time.time():
                self.sessions.pop(token, None)
                return False
            return True

    def revoke(self, token):
        with self.lock:
            self.sessions.pop(token, None)


class Csrf:
    def __init__(self, secret=None):
        self.secret = (secret or secrets.token_hex(32)).encode('utf-8')

    def token(self, identity):
        return hmac.new(self.secret, (identity or '').encode('utf-8'), hashlib.sha256).hexdigest()

    def valid(self, identity, supplied):
        return bool(supplied) and hmac.compare_digest(self.token(identity), supplied)


def _now(tz):
    return datetime.now(tz).isoformat(timespec='seconds')


class SecurityWatch:
    def __init__(self, tz):
        self.tz = tz
        self.lock = threading.RLock()
        self.watched = {}
        self.incidents = []
        self.dirty = False

    def _entry(self, ip, reason):
        entry = self.watched.get(ip)
        if entry is None:
            if len(self.watched) >= MAX_WATCHED:
                oldest = min(self.watched, key=lambda k: self.watched[k].get('last_seen') or self.watched[k]['since'])
                self.watched.pop(oldest, None)
            entry = {'reason': reason, 'since': _now(self.tz), 'blocked_at': '', 'failures': [], 'trail': [], 'hits_after_block': 0, 'last_seen': '', 'note': ''}
            self.watched[ip] = entry
        return entry

    def watch(self, ip, reason, seed_trail=None):
        with self.lock:
            entry = self._entry(ip, reason)
            if seed_trail:
                known = {(t['t'], t['p']) for t in entry['trail']}
                for item in seed_trail:
                    if (item['t'], item['p']) not in known:
                        entry['trail'].append(item)
                entry['trail'].sort(key=lambda t: t['t'])
                del entry['trail'][:-MAX_TRAIL]
            self.dirty = True
            return entry

    def unwatch(self, ip):
        with self.lock:
            self.dirty = self.watched.pop(ip, None) is not None or self.dirty

    def is_watched(self, ip):
        return ip in self.watched

    def mark_blocked(self, ip):
        with self.lock:
            entry = self._entry(ip, '차단')
            entry['blocked_at'] = _now(self.tz)
            self.dirty = True

    def mark_unblocked(self, ip):
        with self.lock:
            entry = self.watched.get(ip)
            if entry:
                entry['blocked_at'] = ''
                self.dirty = True

    def record_failure(self, ip):
        with self.lock:
            entry = self._entry(ip, '관리자 로그인 실패')
            entry['failures'].append(_now(self.tz))
            del entry['failures'][:-50]
            self.dirty = True

    def record_request(self, ip, method, path, status, ua, referrer, blocked=False):
        with self.lock:
            entry = self.watched.get(ip)
            if entry is None:
                return
            stamp = _now(self.tz)
            entry['trail'].append({'t': stamp, 'm': method, 'p': path[:300], 's': int(status), 'u': (ua or '')[:160], 'r': (referrer or '')[:160]})
            del entry['trail'][:-MAX_TRAIL]
            entry['last_seen'] = stamp
            if entry.get('blocked_at'):
                entry['hits_after_block'] = entry.get('hits_after_block', 0) + 1
            self.dirty = True

    def incident(self, ip, kind, detail):
        with self.lock:
            self.incidents.append({'t': _now(self.tz), 'ip': ip, 'k': kind, 'd': detail[:200]})
            del self.incidents[:-MAX_INCIDENTS]
            self.dirty = True

    def snapshot(self):
        with self.lock:
            return {'watched': {ip: dict(entry, trail=list(entry['trail']), failures=list(entry['failures'])) for ip, entry in self.watched.items()},
                    'incidents': list(self.incidents)}

    def replace(self, doc):
        with self.lock:
            self.watched = dict((doc or {}).get('watched') or {})
            self.incidents = list((doc or {}).get('incidents') or [])
            self.dirty = False

    def view(self):
        with self.lock:
            rows = []
            for ip, entry in self.watched.items():
                rows.append({'ip': ip, 'reason': entry['reason'], 'since': entry['since'], 'blocked_at': entry.get('blocked_at', ''),
                             'failures': len(entry['failures']), 'hits_after_block': entry.get('hits_after_block', 0),
                             'requests': len(entry['trail']), 'last_seen': entry.get('last_seen', '')})
            rows.sort(key=lambda r: r['last_seen'] or r['since'], reverse=True)
            return rows, list(reversed(self.incidents[-50:]))

    def detail(self, ip):
        with self.lock:
            entry = self.watched.get(ip)
            if entry is None:
                return None
            return dict(entry, trail=list(entry['trail']), failures=list(entry['failures']))


def merge_security(local, remote):
    out_watched = {}
    for source in (remote.get('watched') or {}, local.get('watched') or {}):
        for ip, entry in source.items():
            mine = out_watched.get(ip)
            if mine is None:
                out_watched[ip] = dict(entry, trail=list(entry.get('trail', [])), failures=list(entry.get('failures', [])))
                continue
            known = {(t['t'], t['p']) for t in mine['trail']}
            mine['trail'].extend(t for t in entry.get('trail', []) if (t['t'], t['p']) not in known)
            mine['trail'].sort(key=lambda t: t['t'])
            del mine['trail'][:-MAX_TRAIL]
            mine['failures'] = sorted(set(mine['failures']) | set(entry.get('failures', [])))[-50:]
            mine['since'] = min(mine['since'], entry.get('since', mine['since']))
            mine['blocked_at'] = max(mine.get('blocked_at', ''), entry.get('blocked_at', ''))
            mine['hits_after_block'] = max(mine.get('hits_after_block', 0), entry.get('hits_after_block', 0))
            mine['last_seen'] = max(mine.get('last_seen', ''), entry.get('last_seen', ''))
    seen = set()
    incidents = []
    for item in list(remote.get('incidents') or []) + list(local.get('incidents') or []):
        key = (item.get('t'), item.get('ip'), item.get('k'), item.get('d'))
        if key not in seen:
            seen.add(key)
            incidents.append(item)
    incidents.sort(key=lambda i: i.get('t', ''))
    return {'watched': out_watched, 'incidents': incidents[-MAX_INCIDENTS:]}
