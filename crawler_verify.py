import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

VERIFIED_SUFFIXES = (
    (('googlebot', 'google-inspectiontool', 'googleother', 'adsbot-google', 'mediapartners-google', 'apis-google'),
     ('.googlebot.com', '.google.com')),
    (('bingbot', 'msnbot', 'adidxbot', 'bingpreview'), ('.search.msn.com',)),
    (('yandex',), ('.yandex.ru', '.yandex.net', '.yandex.com')),
    (('applebot',), ('.applebot.apple.com',)),
)

CLAIMED_AGENTS = (
    'yeti/', 'daumoa', 'duckduckbot', 'gptbot', 'oai-searchbot', 'chatgpt-user',
    'claudebot', 'claude-user', 'claude-searchbot', 'perplexitybot', 'perplexity-user',
    'ccbot', 'amazonbot', 'meta-externalagent', 'facebookexternalhit', 'kakaotalk-scrap',
)

POSITIVE_TTL = 6 * 3600
NEGATIVE_TTL = 1800
MAX_CACHE = 2000
LOOKUP_TIMEOUT = 2.0

_cache = {}
_lock = threading.Lock()
_executor = ThreadPoolExecutor(max_workers=2)


def _suffixes_for(user_agent):
    lowered = (user_agent or '').lower()
    for names, suffixes in VERIFIED_SUFFIXES:
        if any(name in lowered for name in names):
            return suffixes
    return None


def _reverse_forward(ip, suffixes):
    try:
        host = socket.gethostbyaddr(ip)[0].lower().rstrip('.')
    except (socket.herror, socket.gaierror, OSError):
        return False
    if not host.endswith(suffixes):
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, OSError):
        return False
    return any(info[4][0] == ip for info in infos)


def _cache_get(key):
    now = time.time()
    with _lock:
        entry = _cache.get(key)
        if entry and entry[0] > now:
            return entry[1]
    return None


def _cache_set(key, value, ttl):
    with _lock:
        if len(_cache) >= MAX_CACHE:
            for stale in sorted(_cache, key=lambda item: _cache[item][0])[:MAX_CACHE // 4]:
                _cache.pop(stale, None)
        _cache[key] = (time.time() + ttl, value)


def classify(ip, user_agent):
    suffixes = _suffixes_for(user_agent)
    if suffixes:
        key = (ip, suffixes)
        cached = _cache_get(key)
        if cached is None:
            future = _executor.submit(_reverse_forward, ip, suffixes)
            try:
                cached = future.result(timeout=LOOKUP_TIMEOUT)
            except FutureTimeout:
                return 'claimed'
            except Exception:
                cached = False
            _cache_set(key, cached, POSITIVE_TTL if cached else NEGATIVE_TTL)
        return 'verified' if cached else None
    lowered = (user_agent or '').lower()
    if any(name in lowered for name in CLAIMED_AGENTS):
        return 'claimed'
    return None
