import gc
import logging
import os
import threading
import time

LOG = logging.getLogger('memguard')
PAGE_SIZE = os.sysconf('SC_PAGE_SIZE') if hasattr(os, 'sysconf') else 4096
DEFAULT_SOFT_LIMIT_MB = 380
CHECK_INTERVAL = 30
REPORT_INTERVAL = 300

_trimmers = []
_started = False


def rss_mb():
    try:
        with open('/proc/self/statm') as handle:
            return int(handle.read().split()[1]) * PAGE_SIZE / 1048576
    except (OSError, ValueError, IndexError):
        return 0.0


def register(trimmer):
    _trimmers.append(trimmer)


def trim():
    for trimmer in list(_trimmers):
        try:
            trimmer()
        except Exception:
            LOG.exception('캐시 정리 중 오류가 났어요.')
    gc.collect()


def start(interval=CHECK_INTERVAL):
    global _started
    if _started:
        return
    _started = True
    try:
        soft_limit = float(os.environ.get('MEMORY_SOFT_LIMIT_MB') or DEFAULT_SOFT_LIMIT_MB)
    except ValueError:
        soft_limit = DEFAULT_SOFT_LIMIT_MB
    LOG.warning('서버 시작 pid=%s 메모리 %.0fMB 정리 기준 %.0fMB', os.getpid(), rss_mb(), soft_limit)

    def loop():
        last_report = 0.0
        while True:
            time.sleep(interval)
            current = rss_mb()
            now = time.time()
            if current >= soft_limit:
                LOG.warning('메모리 %.0fMB가 기준 %.0fMB를 넘어 캐시를 비웠어요.', current, soft_limit)
                trim()
                LOG.warning('캐시를 비운 뒤 메모리 %.0fMB', rss_mb())
            elif now - last_report >= REPORT_INTERVAL:
                LOG.warning('메모리 사용량 %.0fMB', current)
                last_report = now

    threading.Thread(target=loop, daemon=True, name='memguard').start()