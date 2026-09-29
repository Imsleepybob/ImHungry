from flask import Flask, render_template, request, send_file, make_response, jsonify, redirect, url_for, send_from_directory, abort
from datetime import datetime, timedelta, date, timezone
from collections import defaultdict, deque
import calendar
import requests
import logging
from logging.handlers import RotatingFileHandler
import ipaddress
import bisect
from urllib.parse import quote, unquote
import os
import re
import time
import json
import threading
import hashlib
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 86400

meal_cache = {}

school_code_cache = {}
search_result_cache = {}
region_schools_cache = {}

SCHOOL_CODE_CACHE_TTL = 86400
SEARCH_CACHE_TTL = 3600
REGION_SCHOOLS_CACHE_TTL = 86400

LOG_DIR = os.environ.get('LOG_DIR', os.getcwd())

BLACKLIST_FILE = os.path.join(LOG_DIR, 'ip_blacklist.txt')

request_counts = defaultdict(deque)
failed_attempts = defaultdict(int)
blocked_ips = set()

SECURITY_CONFIG = {
    'rate_limit_window': 3,
    'rate_limit_requests': 25,
    'failed_attempt_threshold': 1,
    'auto_block_duration': 864000,
    'suspicious_ua_block': True,
    'path_traversal_protection': True,
}

NO_LOG_PATHS = [
    '/wp-', '/wp/', 'wordpress', '.php', '/userfiles', '/upload', '/assets',
    'xmlrpc.php', 'wp-admin', 'wp-content', 'wp-includes',
    '/logs/', '/stats', '/security/',
    '/favicon', '/robots.txt', '/manifest.json', '/sitemap.xml',
    '/health', '/api/track', '/admin',
]

SILENT_BLOCK_PATTERNS = [
    '/wp-', '/wp/', 'wordpress', '.php', '/userfiles', '/upload', '/assets',
    'xmlrpc.php', 'wp-admin', 'wp-content', 'wp-includes', '.env', 'config',
    '.git', '.sql', 'backup', 'shell', 'cmd', 'eval', '.asp', '.jsp', '.cgi',
    '/user', '/users', '/client', '/clients', '/order', '/orders',
    '/invoice', '/refund', '/statement', '/card', '/authorization',
    '/authorize', '/private-data', '/archives', '/saving', '/savings',
    '/ebank', '/ebanking', '/balance'
]

SUSPICIOUS_PATTERNS = {
    'paths': [
        r'\.php$', r'wp-', r'admin', r'login', r'\.env', r'config',
        r'\.git', r'\.sql', r'backup', r'shell', r'cmd', r'eval',
        r'xmlrpc', r'\.asp', r'\.jsp', r'\.cgi'
    ],
    'user_agents': [
        r'spider', r'scanner', r'nikto',
        r'sqlmap', r'nmap', r'masscan', r'zap', r'burp', r'amazonbot'
    ],
    'parameters': [
        r'union.*select', r'<script', r'javascript:', r'eval\(',
        r'exec\(', r'system\(', r'\.\./', r'etc/passwd'
    ]
}

CRAWLER_NAME_MAP = [
    ('googlebot',           'Googlebot'),
    ('googleother',         'GoogleOther'),
    ('google-extended',     'Google-Extended'),
    ('google-inspectiontool', 'Google Inspection'),
    ('compatible; google',  'Google (disguised)'),
    ('bingbot',             'Bingbot'),
    ('bingpreview',         'BingPreview'),
    ('yandexbot',           'YandexBot'),
    ('yandex/',             'Yandex'),
    ('baiduspider',         'Baiduspider'),
    ('duckduckbot',         'DuckDuckBot'),
    ('applebot',            'Applebot'),
    ('semrushbot',          'SEMrushBot'),
    ('ahrefsbot',           'AhrefsBot'),
    ('mj12bot',             'MJ12bot'),
    ('amazonbot',           'AmazonBot'),
    ('petalbot',            'PetalBot'),
    ('bytespider',          'ByteSpider'),
    ('facebookexternalhit', 'FacebookBot'),
    ('facebookbot',         'FacebookBot'),
    ('twitterbot',          'TwitterBot'),
    ('linkedinbot',         'LinkedInBot'),
    ('slurp',               'Yahoo Slurp'),
    ('naverbot',            'NaverBot'),
    ('yeti/',               'Naver Yeti'),
    ('kakaotalk-scrap',     'KakaoTalk Scraper'),
    ('kakaostory',          'KakaoStory'),
    ('nikto',               'Nikto'),
    ('sqlmap',              'sqlmap'),
    ('masscan',             'masscan'),
    ('nmap',                'nmap'),
    ('zgrab',               'ZGrab'),
    ('python-requests',     'Python-requests'),
    ('curl/',               'curl'),
    ('wget/',               'wget'),
    ('go-http-client',      'Go HTTP Client'),
    ('java/',               'Java HTTP'),
    ('axios/',              'Axios'),
    ('scrapy',              'Scrapy'),
    ('spider',              'Spider'),
    ('crawler',             'Crawler'),
    ('scanner',             'Scanner'),
    ('scraper',             'Scraper'),
    ('bot',                 'Bot'),
]

KR_CORP_CRAWLER_PATTERNS = [
    ('naver',    'NaverBot'),
    ('kakao',    'KakaoBot'),
    ('ncsoft',   'NCSoft Crawler'),
    ('nexon',    'Nexon Crawler'),
    ('krafton',  'Krafton Crawler'),
]


def load_ip_blacklist():
    blacklist = []
    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                cidr_part = line.split('#', 1)[0].strip()
                try:
                    ipaddress.ip_network(cidr_part, strict=False)
                    blacklist.append(cidr_part)
                except ValueError:
                    app.logger.warning(f"Invalid CIDR format in blacklist: {line}")
    return blacklist

def save_to_blacklist(ip_or_cidr, reason="Automatic detection"):
    try:
        with open(BLACKLIST_FILE, 'a', encoding='utf-8') as f:
            f.write(f"{ip_or_cidr}  # {reason} - {datetime.now()}\n")
        app.logger.info(f"Added to blacklist: {ip_or_cidr} - {reason}")
    except Exception as e:
        app.logger.error(f"Error saving to blacklist: {e}")

def _build_blocked_index(networks):
    ranges = {4: [], 6: []}
    for cidr in networks:
        net = ipaddress.ip_network(cidr, strict=False)
        ranges[net.version].append((int(net.network_address), int(net.broadcast_address)))
    index = {}
    for version, items in ranges.items():
        items.sort()
        merged = []
        for start, end in items:
            if merged and start <= merged[-1][1] + 1:
                if end > merged[-1][1]:
                    merged[-1][1] = end
            else:
                merged.append([start, end])
        index[version] = ([m[0] for m in merged], [m[1] for m in merged])
    return index

BLOCKED_NETWORKS = []
BLOCKED_INDEX = {4: ([], []), 6: ([], [])}

def refresh_blacklist():
    global BLOCKED_NETWORKS, BLOCKED_INDEX
    networks = load_ip_blacklist()
    index = _build_blocked_index(networks)
    BLOCKED_NETWORKS = networks
    BLOCKED_INDEX = index

refresh_blacklist()

ADMIN_WHITELIST = [ip.strip() for ip in os.environ.get('ADMIN_WHITELIST', '').split(',') if ip.strip()]

GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', '')
GITHUB_REPO = os.environ.get('GITHUB_REPO', '')
GITHUB_BRANCH = os.environ.get('GITHUB_BRANCH', 'main')
GITHUB_BLACKLIST_PATH = os.environ.get('GITHUB_BLACKLIST_PATH', 'ip_blacklist.txt')
GITHUB_SYNC_DEBOUNCE = 60

_github_sync_lock = threading.Lock()
_github_sync_pending = False

def github_sync_configured():
    return bool(GITHUB_TOKEN and GITHUB_REPO)

def sync_blacklist_to_github():
    if not github_sync_configured():
        return False, "GITHUB_TOKEN / GITHUB_REPO 환경변수가 설정되지 않았습니다."
    api_url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_BLACKLIST_PATH}"
    headers = {
        'Authorization': f'Bearer {GITHUB_TOKEN}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
    }
    try:
        get_resp = requests.get(api_url, headers=headers, params={'ref': GITHUB_BRANCH}, timeout=10)
        sha = get_resp.json().get('sha') if get_resp.status_code == 200 else None
        with open(BLACKLIST_FILE, 'r', encoding='utf-8') as f:
            content = f.read()
        payload = {
            'message': f"chore: ip_blacklist.txt 자동 갱신 ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})",
            'content': base64.b64encode(content.encode('utf-8')).decode('ascii'),
            'branch': GITHUB_BRANCH,
        }
        if sha:
            payload['sha'] = sha
        put_resp = requests.put(api_url, headers=headers, json=payload, timeout=10)
        if put_resp.status_code in (200, 201):
            app.logger.info("ip_blacklist.txt GitHub 동기화 완료")
            return True, None
        app.logger.error(f"GitHub 동기화 실패: {put_resp.status_code} {put_resp.text[:300]}")
        return False, f"GitHub API 오류 ({put_resp.status_code})"
    except Exception as e:
        app.logger.error(f"GitHub 동기화 예외: {e}")
        return False, str(e)

def _github_sync_worker():
    time.sleep(GITHUB_SYNC_DEBOUNCE)
    global _github_sync_pending
    with _github_sync_lock:
        _github_sync_pending = False
    sync_blacklist_to_github()

def schedule_github_sync():
    if not github_sync_configured():
        return
    global _github_sync_pending
    with _github_sync_lock:
        if _github_sync_pending:
            return
        _github_sync_pending = True
    threading.Thread(target=_github_sync_worker, daemon=True).start()

ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH', '').strip().strip('"\'').strip().lower()

IPINFO_API_KEY = os.environ.get('IPINFO_API_KEY', '')
IP_INFO_CACHE = {}
IP_INFO_CACHE_TTL = 86400
IPINFO_CACHE_FILE = os.path.join(LOG_DIR, 'ipinfo_cache.json')

def _load_ipinfo_cache():
    """앱 시작 시 파일 캐시를 메모리로 로드."""
    if not os.path.exists(IPINFO_CACHE_FILE):
        return
    try:
        with open(IPINFO_CACHE_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        now = time.time()
        for ip, (ts, info) in data.items():
            if now - ts < IP_INFO_CACHE_TTL:
                IP_INFO_CACHE[ip] = (ts, info)
        app.logger.info(f"IPInfo 캐시 로드: {len(IP_INFO_CACHE)}개 항목")
    except Exception as e:
        app.logger.warning(f"IPInfo 캐시 파일 로드 실패: {e}")

def _save_ipinfo_cache():
    """현재 메모리 캐시를 파일로 저장."""
    try:
        now = time.time()
        valid = {ip: v for ip, v in IP_INFO_CACHE.items() if now - v[0] < IP_INFO_CACHE_TTL}
        with open(IPINFO_CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(valid, f, ensure_ascii=False)
    except Exception as e:
        app.logger.warning(f"IPInfo 캐시 파일 저장 실패: {e}")

def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    elif request.access_route:
        return request.access_route[0]
    else:
        return request.remote_addr

def should_log_request(path, method=None):
    if any(pattern in path.lower() for pattern in NO_LOG_PATHS):
        return False
    if method == 'HEAD':
        return False
    return True

def should_silent_block(path):
    return any(pattern in path.lower() for pattern in SILENT_BLOCK_PATTERNS)

def is_ip_blocked(ip_address):
    try:
        client_ip = ipaddress.ip_address(ip_address)
    except ValueError:
        app.logger.error(f"Invalid IP address detected: {ip_address}")
        return True
    if ip_address in blocked_ips:
        return True
    starts, ends = BLOCKED_INDEX.get(client_ip.version, ([], []))
    ip_int = int(client_ip)
    i = bisect.bisect_right(starts, ip_int) - 1
    return i >= 0 and ip_int <= ends[i]

def is_admin_ip(ip_address):
    try:
        client_ip = ipaddress.ip_address(ip_address)
        for admin_network in ADMIN_WHITELIST:
            network = ipaddress.ip_network(admin_network, strict=False)
            if client_ip in network:
                return True
        return False
    except ValueError:
        return False

def is_rate_limited(ip_address):
    now = time.time()
    window_start = now - SECURITY_CONFIG['rate_limit_window']
    while request_counts[ip_address] and request_counts[ip_address][0] < window_start:
        request_counts[ip_address].popleft()
    request_counts[ip_address].append(now)
    if len(request_counts[ip_address]) > SECURITY_CONFIG['rate_limit_requests']:
        return True
    return False

def is_suspicious_request():
    suspicion_score = 0
    reasons = []
    path = request.path.lower()
    for pattern in SUSPICIOUS_PATTERNS['paths']:
        if re.search(pattern, path, re.IGNORECASE):
            suspicion_score += 10
            reasons.append(f"Suspicious path: {pattern}")
    user_agent = request.headers.get('User-Agent', '').lower()
    if not user_agent or len(user_agent) < 10:
        suspicion_score += 5
        reasons.append("Missing or short User-Agent")
    for pattern in SUSPICIOUS_PATTERNS['user_agents']:
        if re.search(pattern, user_agent, re.IGNORECASE):
            suspicion_score += 15
            reasons.append(f"Suspicious User-Agent: {pattern}")
    query_string = request.query_string.decode('utf-8', errors='ignore').lower()
    for pattern in SUSPICIOUS_PATTERNS['parameters']:
        if re.search(pattern, query_string, re.IGNORECASE):
            suspicion_score += 20
            reasons.append(f"Suspicious parameter: {pattern}")
    if request.method not in ['GET', 'POST', 'HEAD']:
        suspicion_score += 10
        reasons.append(f"Suspicious method: {request.method}")
    if path.endswith(('.php', '.asp', '.jsp', '.cgi')) and not path.startswith('/api/'):
        suspicion_score += 15
        reasons.append("Non-existent extension request")
    return suspicion_score >= 10, suspicion_score, reasons

def log_security_incident(ip, incident_type, details, suspicion_score=0):
    security_logger = logging.getLogger('security')
    security_logger.warning(
        f"SECURITY INCIDENT - IP: {ip}, Type: {incident_type}, "
        f"Score: {suspicion_score}, Details: {details}, "
        f"UA: {request.headers.get('User-Agent', 'N/A')[:100]}, "
        f"Path: {request.path}, Method: {request.method}"
    )

def auto_block_ip(ip, reason, duration=None):
    if duration is None:
        duration = SECURITY_CONFIG['auto_block_duration']
    blocked_ips.add(ip)
    log_security_incident(ip, "AUTO_BLOCK", f"{reason} - Duration: {duration}s")
    failed_attempts[ip] += 1
    if failed_attempts[ip] >= SECURITY_CONFIG['failed_attempt_threshold']:
        save_to_blacklist(f"{ip}/32", f"Auto-blocked: {reason}")
        refresh_blacklist()
        schedule_github_sync()

@app.before_request
def security_check():
    client_ip = get_client_ip()
    if is_admin_ip(client_ip):
        return
    if request.path.startswith('/admin'):
        return
    if should_silent_block(request.path):
        response = make_response('', 444)
        response.headers['Connection'] = 'close'
        return response
    if is_ip_blocked(client_ip):
        log_security_incident(client_ip, "BLOCKED_IP", "IP in blacklist")
        response = make_response('', 444)
        response.headers['Connection'] = 'close'
        return response
    if is_rate_limited(client_ip):
        log_security_incident(client_ip, "RATE_LIMIT", "Too many requests")
        auto_block_ip(client_ip, "Rate limit exceeded", 864000)
        response = make_response('', 444)
        response.headers['Connection'] = 'close'
        return response
    is_suspicious, suspicion_score, reasons = is_suspicious_request()
    if is_suspicious:
        log_security_incident(client_ip, "SUSPICIOUS_PATTERN",
                            f"Reasons: {', '.join(reasons)}", suspicion_score)
        if suspicion_score >= 15:
            auto_block_ip(client_ip, f"High suspicion score: {suspicion_score}")
            response = make_response('', 444)
            response.headers['Connection'] = 'close'
            return response
        elif suspicion_score >= 10:
            response = make_response('', 444)
            response.headers['Connection'] = 'close'
            return response
    if SECURITY_CONFIG['path_traversal_protection']:
        if '../' in request.path or '..\\' in request.path:
            log_security_incident(client_ip, "PATH_TRAVERSAL", request.path)
            auto_block_ip(client_ip, "Path traversal attempt")
            response = make_response('', 444)
            response.headers['Connection'] = 'close'
            return response

def setup_security_logging():
    security_logger = logging.getLogger('security')
    security_handler = RotatingFileHandler(
        os.path.join(LOG_DIR, 'security.log'),
        maxBytes=10*1024*1024,
        backupCount=5,
        encoding='utf-8'
    )
    security_handler.setFormatter(logging.Formatter(
        '[%(asctime)s] %(levelname)s: %(message)s'
    ))
    security_logger.addHandler(security_handler)
    security_logger.setLevel(logging.WARNING)
    security_logger.propagate = False

setup_security_logging()

ACCESS_LOG_PATH = os.path.join(LOG_DIR, 'access.log')
APP_LOG_PATH = os.path.join(LOG_DIR, 'app.log')
IP_BLOCK_LOG_PATH = os.path.join(LOG_DIR, 'ip_block.log')
NAMUBOARD_LOG_PATH = os.path.join(LOG_DIR, 'namuboard.log')
EVENTS_LOG_PATH = os.path.join(LOG_DIR, 'events.log')


class AccessLogFormatter(logging.Formatter):
    def format(self, record):
        record.remote_addr = getattr(record, 'remote_addr', 'N/A')
        record.user_agent = getattr(record, 'user_agent', 'N/A')
        record.device = getattr(record, 'device', 'N/A')
        record.os_name = getattr(record, 'os_name', 'N/A')
        record.browser = getattr(record, 'browser', 'N/A')
        record.crawler = getattr(record, 'crawler', 'N/A')
        record.method = getattr(record, 'method', 'N/A')
        record.path = getattr(record, 'path', 'N/A')
        record.status = getattr(record, 'status', 'N/A')
        record.referrer = getattr(record, 'referrer', 'N/A')
        return super().format(record)

class AppLogFormatter(logging.Formatter):
    def format(self, record):
        try:
            from flask import has_request_context
            if has_request_context():
                client_ip = get_client_ip()
                record.request_info = f"IP: {client_ip}"
            else:
                record.request_info = "No request context"
        except:
            record.request_info = "N/A"
        return super().format(record)

def setup_logging():
    logging.basicConfig(level=logging.INFO)
    app_handler = RotatingFileHandler(
        APP_LOG_PATH,
        maxBytes=10*1024*1024,
        backupCount=5,
        encoding='utf-8'
    )
    app_formatter = AppLogFormatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s - %(request_info)s'
    )
    app_handler.setFormatter(app_formatter)
    access_handler = RotatingFileHandler(
        ACCESS_LOG_PATH,
        maxBytes=10*1024*1024,
        backupCount=5,
        encoding='utf-8'
    )
    access_formatter = AccessLogFormatter(
        '%(asctime)s - IP: %(remote_addr)s - Device: %(device)s - OS: %(os_name)s'
        ' - Browser: %(browser)s - Crawler: %(crawler)s - UA: %(user_agent)s'
        ' - Method: %(method)s - Path: %(path)s - Status: %(status)s - Referrer: %(referrer)s'
    )
    access_handler.setFormatter(access_formatter)
    ip_handler = logging.FileHandler(IP_BLOCK_LOG_PATH, encoding='utf-8')
    ip_handler.setLevel(logging.WARNING)
    ip_handler.setFormatter(logging.Formatter(
            '[%(asctime)s] %(levelname)s: %(message)s'
    ))
    namuboard_handler = RotatingFileHandler(
        NAMUBOARD_LOG_PATH,
        maxBytes=5*1024*1024,
        backupCount=3,
        encoding='utf-8'
    )
    namuboard_formatter = logging.Formatter(
        '%(asctime)s - IP: %(remote_addr)s - UA: %(user_agent)s - Referrer: %(referrer)s'
    )
    namuboard_handler.setFormatter(namuboard_formatter)

    events_handler = RotatingFileHandler(
        EVENTS_LOG_PATH,
        maxBytes=5*1024*1024,
        backupCount=3,
        encoding='utf-8'
    )
    events_handler.setFormatter(logging.Formatter('%(message)s'))
    events_logger = logging.getLogger('events')
    events_logger.setLevel(logging.INFO)
    events_logger.addHandler(events_handler)
    events_logger.propagate = False

    logger = logging.getLogger(__name__)
    logger.addHandler(app_handler)
    logger.addHandler(ip_handler)
    app.logger.addHandler(app_handler)
    app.logger.addHandler(ip_handler)
    access_logger = logging.getLogger('access')
    access_logger.setLevel(logging.INFO)
    access_logger.addHandler(access_handler)
    namuboard_logger = logging.getLogger('namuboard')
    namuboard_logger.setLevel(logging.INFO)
    namuboard_logger.addHandler(namuboard_handler)
    access_logger.propagate = False
    namuboard_logger.propagate = False
    return access_logger, namuboard_logger

access_logger, namuboard_logger = setup_logging()
_load_ipinfo_cache()


def detect_client_type(raw_ua):
    if not raw_ua:
        return True, 'Unknown Bot', 'Unknown', 'Unknown', 'Unknown'

    ua_lower = raw_ua.lower()
    ua_snippet = raw_ua[:80].strip()

    for pattern, name in CRAWLER_NAME_MAP:
        if pattern in ua_lower:
            return True, f"{name} ({ua_snippet})", 'Crawler', 'Crawler', 'Crawler'

    if 'windows nt' in ua_lower:
        nt_ver_map = {'10.0': 'Windows 10/11', '6.3': 'Windows 8.1',
                      '6.2': 'Windows 8', '6.1': 'Windows 7'}
        m = re.search(r'windows nt ([\d.]+)', ua_lower)
        ver = m.group(1) if m else ''
        os_name = nt_ver_map.get(ver, f'Windows NT {ver}')
    elif 'ipad' in ua_lower:
        os_name = 'iPadOS'
    elif 'iphone' in ua_lower or 'ipod' in ua_lower:
        os_name = 'iOS'
    elif 'android' in ua_lower:
        m = re.search(r'android ([\d.]+)', ua_lower)
        ver = m.group(1).rsplit('.', 1)[0] if m else ''
        os_name = f'Android {ver}' if ver else 'Android'
    elif 'mac os x' in ua_lower or 'macos' in ua_lower:
        os_name = 'macOS'
    elif 'cros' in ua_lower:
        os_name = 'ChromeOS'
    elif 'linux' in ua_lower:
        os_name = 'Linux'
    else:
        os_name = 'Unknown OS'

    if 'ipad' in ua_lower or 'tablet' in ua_lower:
        device = 'Tablet'
    elif any(k in ua_lower for k in ('mobile', 'android', 'iphone', 'ipod')):
        device = 'Mobile'
    else:
        device = 'Desktop'

    if 'edg/' in ua_lower or 'edgios' in ua_lower or 'edga/' in ua_lower:
        browser = 'Edge'
    elif 'samsungbrowser' in ua_lower:
        browser = 'Samsung Browser'
    elif 'crios' in ua_lower:
        browser = 'Chrome (iOS)'
    elif 'chrome' in ua_lower:
        browser = 'Chrome'
    elif 'fxios' in ua_lower or 'firefox' in ua_lower:
        browser = 'Firefox'
    elif 'opr/' in ua_lower or 'opera' in ua_lower:
        browser = 'Opera'
    elif 'safari' in ua_lower:
        browser = 'Safari'
    else:
        browser = 'Other'

    return False, '', device, os_name, browser


def clean_user_agent(user_agent_string):
    if not user_agent_string:
        return 'Unknown'
    return user_agent_string[:200]

def log_access_request(status_code=200):
    if request.method in ['GET', 'POST'] and status_code in [200, 206]:
        try:
            real_ip = get_client_ip()
            if is_admin_ip(real_ip):
                return
            raw_ua = request.headers.get('User-Agent', '')
            is_crawler, crawler_label, device, os_name, browser = detect_client_type(raw_ua)
            extra_info = {
                'remote_addr': real_ip or 'Unknown',
                'user_agent': clean_user_agent(raw_ua) or 'Unknown',
                'device': device,
                'os_name': os_name,
                'browser': browser,
                'crawler': crawler_label if is_crawler else 'N',
                'method': request.method,
                'path': request.path,
                'status': status_code,
                'referrer': request.headers.get('Referer', 'N/A')[:100]
            }
            access_logger.info('Access log', extra=extra_info)
        except Exception as e:
            app.logger.error(f"접속 로그 기록 중 오류 발생: {e}")

def log_namuboard_access_request():
    try:
        real_ip = get_client_ip()
        extra_info = {
            'remote_addr': real_ip or 'Unknown',
            'user_agent': clean_user_agent(request.headers.get('User-Agent', 'Unknown')),
            'referrer': request.headers.get('Referer', 'N/A')[:100]
        }
        namuboard_logger.info('NamuBoard Extension Access', extra=extra_info)
    except Exception as e:
        app.logger.error(f"NamuBoard Extension 로그 기록 중 오류 발생: {e}")


def get_ip_info(ip):
    cached = IP_INFO_CACHE.get(ip)
    if cached and time.time() - cached[0] < IP_INFO_CACHE_TTL:
        return cached[1]
    try:
        resp = requests.get(
            f'https://ipinfo.io/{ip}?token={IPINFO_API_KEY}',
            timeout=3
        )
        if resp.status_code == 200:
            data = resp.json()
            result = {
                'org': data.get('org', ''),
                'region': data.get('region', ''),
                'country': data.get('country', ''),
                'city': data.get('city', ''),
            }
            IP_INFO_CACHE[ip] = (time.time(), result)
            _save_ipinfo_cache()
            return result
    except Exception:
        pass
    IP_INFO_CACHE[ip] = (time.time(), {})
    return {}


def parse_logs_for_dashboard(days=30):
    today = datetime.now(KST).date()
    cutoff = today - timedelta(days=days)

    stats = {
        'total_requests': 0,
        'unique_ips': set(),
        'today_requests': 0,
        'requests_by_day': defaultdict(int),
        'status_codes': defaultdict(int),
        'paths': defaultdict(int),
        'school_visits': defaultdict(int),
        'ips': defaultdict(int),
        'referrers': defaultdict(int),
        'crawlers': 0,
        'users': 0,
        'devices': defaultdict(int),
        'os_names': defaultdict(int),
        'browsers': defaultdict(int),
        'crawler_names': defaultdict(int),
        'user_paths': defaultdict(int),
        'bot_paths': defaultdict(int),
        'bot_ips': defaultdict(lambda: {'total': 0, 'paths': defaultdict(int), 'crawler_name': 'Unknown'}),
    }

    log_re = re.compile(
        r'(\d{4}-\d{2}-\d{2}) \d{2}:\d{2}:\d{2}[,.\d]* - '
        r'IP: (\S+) - '
        r'(?:Device: (\S+) - (?:OS: (.*?) - )?Browser: ([^-]+?) - (?:Crawler: (.*?) - )?)?'
        r'UA: (.*?) - '
        r'Method: (\w+) - '
        r'Path: (\S+) - '
        r'Status: (\d+) - '
        r'Referrer: (.*?)$'
    )

    parsed_rows = []
    pending_geo_ips = set()

    if os.path.exists(ACCESS_LOG_PATH):
        with open(ACCESS_LOG_PATH, 'r', encoding='utf-8') as f:
            for line in f:
                m = log_re.match(line.strip())
                if not m:
                    continue
                (date_str, ip, device, os_name, browser,
                 crawler_field, ua, method, path, status, referrer) = m.groups()

                try:
                    log_date = datetime.strptime(date_str, '%Y-%m-%d').date()
                    if log_date < cutoff:
                        continue
                except Exception:
                    continue

                stats['total_requests'] += 1
                stats['unique_ips'].add(ip)
                if log_date == today:
                    stats['today_requests'] += 1
                stats['requests_by_day'][date_str] += 1
                stats['status_codes'][status] += 1

                is_bot = False
                cname = 'Unknown'

                ua_stripped = ua.strip() if ua else ''
                if not ua_stripped or ua_stripped == 'Unknown' or len(ua_stripped) < 10:
                    is_bot = True
                    cname = 'Empty UA'
                elif device:
                    is_crawler_entry = crawler_field is not None and crawler_field.strip() != 'N'
                    if is_crawler_entry:
                        is_bot = True
                        cname = crawler_field.split(' (')[0].strip()
                    elif device == 'Crawler':
                        is_bot = True
                        _, clabel, *_ = detect_client_type(ua_stripped)
                        cname = clabel.split(' (')[0].strip() if clabel else 'Unknown'
                else:
                    is_crawler, crawler_label, *_ = detect_client_type(ua_stripped)
                    if is_crawler:
                        is_bot = True
                        cname = crawler_label.split(' (')[0].strip()

                if not is_bot:
                    cached = IP_INFO_CACHE.get(ip)
                    if not cached or time.time() - cached[0] >= IP_INFO_CACHE_TTL:
                        pending_geo_ips.add(ip)

                parsed_rows.append((
                    date_str, ip, device, os_name, browser,
                    is_bot, cname, path, status, referrer, ua_stripped
                ))

    if pending_geo_ips:
        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = {pool.submit(get_ip_info, ip): ip for ip in pending_geo_ips}
            for future in as_completed(futures):
                future.result()

    for (date_str, ip, device, os_name, browser,
         is_bot, cname, path, status, referrer, ua) in parsed_rows:

        if is_bot:
            stats['crawlers'] += 1
            stats['crawler_names'][cname] += 1
            stats['bot_ips'][ip]['total'] += 1
            stats['bot_ips'][ip]['paths'][path] += 1
            stats['bot_ips'][ip]['crawler_name'] = cname
            stats['bot_paths'][path] += 1
        else:
            geo = IP_INFO_CACHE.get(ip, (0, {}))[1]
            country = geo.get('country', '')
            org_lower = geo.get('org', '').lower()

            geo_bot_name = None
            if country and country != 'KR':
                geo_bot_name = f"Non-KR ({geo.get('org', country)})"
            else:
                for pattern, label in KR_CORP_CRAWLER_PATTERNS:
                    if pattern in org_lower:
                        geo_bot_name = label
                        break

            if geo_bot_name:
                stats['crawlers'] += 1
                stats['crawler_names'][geo_bot_name] += 1
                stats['bot_ips'][ip]['total'] += 1
                stats['bot_ips'][ip]['paths'][path] += 1
                stats['bot_ips'][ip]['crawler_name'] = geo_bot_name
                stats['bot_paths'][path] += 1
            else:
                stats['ips'][ip] += 1
                stats['user_paths'][path] += 1
                school_m = re.match(r'^/meal/(\w+)$', path)
                if school_m:
                    stats['school_visits'][school_m.group(1)] += 1
                if referrer and referrer != 'N/A':
                    ref_m = re.match(r'https?://([^/]+)', referrer)
                    if ref_m:
                        stats['referrers'][ref_m.group(1)] += 1
                stats['users'] += 1
                if device:
                    stats['devices'][device] += 1
                    stats['os_names'][os_name.strip() if os_name else 'Unknown OS'] += 1
                    stats['browsers'][browser.strip() if browser else 'Other'] += 1
                else:
                    _, _, det_device, det_os, det_browser = detect_client_type(ua)
                    stats['devices'][det_device] += 1
                    stats['os_names'][det_os] += 1
                    stats['browsers'][det_browser] += 1

    event_stats = {
        'theme': defaultdict(int),
        'search_method': defaultdict(int),
        'btn_month': 0,
        'btn_nearby': 0,
        'btn_share': 0,
        'btn_notification': 0,
    }
    if os.path.exists(EVENTS_LOG_PATH):
        with open(EVENTS_LOG_PATH, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    event = data.get('event', '')
                    value = data.get('value', '')
                    if event == 'theme':
                        event_stats['theme'][value] += 1
                    elif event == 'search_method':
                        event_stats['search_method'][value] += 1
                    elif event in event_stats:
                        event_stats[event] += 1
                except Exception:
                    continue

    school_names = {}
    for code in list(stats['school_visits'].keys()):
        cached = school_code_cache.get(code)
        if cached:
            school_names[code] = cached[1]['school_name']
        else:
            info = get_school_from_neis(code)
            school_names[code] = info['school_name'] if info else code

    return {
        'total_requests': stats['total_requests'],
        'unique_ips': len(stats['unique_ips']),
        'today_requests': stats['today_requests'],
        'crawlers': stats['crawlers'],
        'users': stats['users'],
        'requests_by_day': dict(sorted(stats['requests_by_day'].items())[-14:]),
        'status_codes': dict(sorted(stats['status_codes'].items())),
        'top_user_paths': sorted(stats['user_paths'].items(), key=lambda x: x[1], reverse=True)[:15],
        'all_user_paths': sorted(stats['user_paths'].items(), key=lambda x: x[1], reverse=True),
        'top_bot_paths': sorted(stats['bot_paths'].items(), key=lambda x: x[1], reverse=True)[:15],
        'all_bot_paths': sorted(stats['bot_paths'].items(), key=lambda x: x[1], reverse=True),
        'top_schools': [
            (school_names.get(c, c), v)
            for c, v in sorted(stats['school_visits'].items(), key=lambda x: x[1], reverse=True)[:10]
        ],
        'all_schools': [
            (school_names.get(c, c), v)
            for c, v in sorted(stats['school_visits'].items(), key=lambda x: x[1], reverse=True)
        ],
        'top_ips': sorted(stats['ips'].items(), key=lambda x: x[1], reverse=True)[:10],
        'all_ips': sorted(stats['ips'].items(), key=lambda x: x[1], reverse=True),
        'top_referrers': sorted(stats['referrers'].items(), key=lambda x: x[1], reverse=True)[:10],
        'all_referrers': sorted(stats['referrers'].items(), key=lambda x: x[1], reverse=True),
        'devices': dict(stats['devices']),
        'os_names': dict(sorted(stats['os_names'].items(), key=lambda x: x[1], reverse=True)),
        'browsers': dict(stats['browsers']),
        'top_crawlers': sorted(stats['crawler_names'].items(), key=lambda x: x[1], reverse=True)[:15],
        'all_crawlers': sorted(stats['crawler_names'].items(), key=lambda x: x[1], reverse=True),
        'bot_ip_list': [
            {
                'ip': ip,
                'total': data['total'],
                'crawler_name': data['crawler_name'],
                'top_paths': sorted(data['paths'].items(), key=lambda x: x[1], reverse=True)[:5],
            }
            for ip, data in sorted(
                stats['bot_ips'].items(), key=lambda x: x[1]['total'], reverse=True
            )
        ],
        'events': {
            'theme': dict(event_stats['theme']),
            'search_method': dict(event_stats['search_method']),
            'btn_month': event_stats['btn_month'],
            'btn_nearby': event_stats['btn_nearby'],
            'btn_share': event_stats['btn_share'],
            'btn_notification': event_stats['btn_notification'],
        },
        'cache_stats': {
            '급식 캐시': len(meal_cache),
            '학교코드 캐시': len(school_code_cache),
            '검색결과 캐시': len(search_result_cache),
            '지역별학교 캐시': len(region_schools_cache),
        },
        'security': {
            'blocked_networks': len(BLOCKED_NETWORKS),
            'temp_blocked_ips': len(blocked_ips),
            'total_failed_attempts': sum(failed_attempts.values()),
        },
        'days': days,
    }


API_KEY = "e309120a7d884eb7b725deaac507a5af"
KST = timezone(timedelta(hours=9))
regions = {
    "서울": "B10", "부산": "C10", "대구": "D10", "인천": "E10", "광주": "F10",
    "대전": "G10", "울산": "H10", "세종": "I10", "경기": "J10", "강원": "K10",
    "충북": "M10", "충남": "N10", "전북": "P10", "전남": "Q10", "경북": "R10",
    "경남": "S10", "제주": "T10"
}

school_levels = {
    "초등학교": ["초등학교"],
    "중학교": ["중학교", "중등학교"],
    "고등학교": ["고등학교", "고등", "고교"],
    "특수학교": ["특수학교"],
    "각종학교": ["각종학교"]
}

def extract_district_from_address(address):
    if not address:
        return None
    district_patterns = [
        r'서울특별시\s+([가-힣]+구)',
        r'부산광역시\s+([가-힣]+구)',
        r'대구광역시\s+([가-힣]+구)',
        r'인천광역시\s+([가-힣]+구)',
        r'광주광역시\s+([가-힣]+구)',
        r'대전광역시\s+([가-힣]+구)',
        r'울산광역시\s+([가-힣]+구)',
        r'경기도\s+([가-힣]+시)',
        r'경기도\s+([가-힣]+군)',
        r'강원[특별자치]*도\s+([가-힣]+시)',
        r'강원[특별자치]*도\s+([가-힣]+군)',
        r'충청북도\s+([가-힣]+시)',
        r'충청북도\s+([가-힣]+군)',
        r'충청남도\s+([가-힣]+시)',
        r'충청남도\s+([가-힣]+군)',
        r'전라북도\s+([가-힣]+시)',
        r'전라북도\s+([가-힣]+군)',
        r'전북특별자치도\s+([가-힣]+시)',
        r'전북특별자치도\s+([가-힣]+군)',
        r'전라남도\s+([가-힣]+시)',
        r'전라남도\s+([가-힣]+군)',
        r'경상북도\s+([가-힣]+시)',
        r'경상북도\s+([가-힣]+군)',
        r'경상남도\s+([가-힣]+시)',
        r'경상남도\s+([가-힣]+군)',
        r'제주특별자치도\s+([가-힣]+시)',
        r'세종특별자치시',
    ]
    for pattern in district_patterns:
        match = re.search(pattern, address)
        if match:
            if pattern == r'세종특별자치시':
                return '세종시'
            return match.group(1)
    return None

def get_school_level_from_name(school_name):
    if '초등학교' in school_name or school_name.endswith('초'):
        return '초등학교'
    elif '중학교' in school_name or school_name.endswith('중'):
        return '중학교'
    elif '고등학교' in school_name or '고교' in school_name or school_name.endswith('고'):
        return '고등학교'
    elif '특수학교' in school_name:
        return '특수학교'
    elif '각종학교' in school_name:
        return '각종학교'
    return None

def _parse_school_row(row):
    address = row.get("ORG_RDNMA", "")
    return {
        "school_code": row["SD_SCHUL_CODE"],
        "school_name": row["SCHUL_NM"],
        "region_code": row["ATPT_OFCDC_SC_CODE"],
        "address": address,
        "district": extract_district_from_address(address),
        "school_level": get_school_level_from_name(row["SCHUL_NM"])
    }

def get_school_from_neis(school_code):
    cached = school_code_cache.get(school_code)
    if cached and time.time() - cached[0] < SCHOOL_CODE_CACHE_TTL:
        return cached[1]

    url = "https://open.neis.go.kr/hub/schoolInfo"
    params = {
        "KEY": API_KEY, "Type": "json", "pIndex": 1, "pSize": 1,
        "SD_SCHUL_CODE": school_code
    }
    try:
        response = requests.get(url, params=params, timeout=5)
        response.raise_for_status()
        data = response.json()
        if "schoolInfo" in data and len(data["schoolInfo"]) >= 2:
            rows = data["schoolInfo"][1].get("row", [])
            if rows:
                school_info = _parse_school_row(rows[0])
                school_code_cache[school_code] = (time.time(), school_info)
                return school_info
    except Exception as e:
        app.logger.error(f"Error fetching school from NEIS API (code={school_code}): {e}")
    return None

def _search_region_cache(query, region_code, limit):
    cached = region_schools_cache.get(region_code)
    if not cached or time.time() - cached[0] > REGION_SCHOOLS_CACHE_TTL:
        prefetch_region_schools_async(region_code)
        return None
    q = query.lower()
    results = []
    for school in cached[1]:
        if q in school["school_name"].lower():
            results.append({
                "school_code": school["school_code"],
                "school_name": school["school_name"],
                "region_code": school["region_code"],
                "address": school.get("address", "")
            })
            if len(results) >= limit:
                break
    return results or None

def search_schools_neis(query, region_code, limit=10):
    cache_key = (query.lower(), region_code)
    cached = search_result_cache.get(cache_key)
    if cached and time.time() - cached[0] < SEARCH_CACHE_TTL:
        return cached[1]

    local_results = _search_region_cache(query, region_code, limit)
    if local_results is not None:
        return local_results

    url = "https://open.neis.go.kr/hub/schoolInfo"
    params = {
        "KEY": API_KEY, "Type": "json", "pIndex": 1, "pSize": limit,
        "ATPT_OFCDC_SC_CODE": region_code, "SCHUL_NM": query
    }
    try:
        response = requests.get(url, params=params, timeout=5)
        response.raise_for_status()
        data = response.json()
        results = []
        if "schoolInfo" in data and len(data["schoolInfo"]) >= 2:
            for row in data["schoolInfo"][1].get("row", []):
                results.append({
                    "school_code": row["SD_SCHUL_CODE"],
                    "school_name": row["SCHUL_NM"],
                    "region_code": row["ATPT_OFCDC_SC_CODE"],
                    "address": row.get("ORG_RDNMA", "")
                })
        search_result_cache[cache_key] = (time.time(), results)
        return results
    except Exception as e:
        app.logger.error(f"Error searching schools from NEIS API (query={query}): {e}")
        return []

def _fetch_all_schools_for_region(region_code):
    url = "https://open.neis.go.kr/hub/schoolInfo"
    all_schools = []
    page = 1
    while page <= 10:
        params = {
            "KEY": API_KEY, "Type": "json",
            "pIndex": page, "pSize": 300,
            "ATPT_OFCDC_SC_CODE": region_code
        }
        try:
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            if "schoolInfo" not in data or len(data["schoolInfo"]) < 2:
                break
            rows = data["schoolInfo"][1].get("row", [])
            if not rows:
                break
            for row in rows:
                all_schools.append(_parse_school_row(row))
            if len(rows) < 300:
                break
            page += 1
            time.sleep(0.3)
        except Exception as e:
            app.logger.error(f"Error fetching region schools (region={region_code}, page={page}): {e}")
            break
    return all_schools

def get_schools_by_region_cached(region_code, school_level=None):
    cached = region_schools_cache.get(region_code)
    if not cached or time.time() - cached[0] > REGION_SCHOOLS_CACHE_TTL:
        app.logger.info(f"Fetching all schools for region {region_code} from NEIS API")
        schools = _fetch_all_schools_for_region(region_code)
        region_schools_cache[region_code] = (time.time(), schools)
    else:
        schools = cached[1]

    if school_level:
        return [s for s in schools if s.get("school_level") == school_level]
    return schools

_region_prefetch_lock = threading.Lock()
_region_prefetch_running = set()
_region_prefetch_last = {}

def prefetch_region_schools_async(region_code):
    cached = region_schools_cache.get(region_code)
    if cached and time.time() - cached[0] <= REGION_SCHOOLS_CACHE_TTL:
        return
    with _region_prefetch_lock:
        if region_code in _region_prefetch_running:
            return
        if time.time() - _region_prefetch_last.get(region_code, 0) < 60:
            return
        _region_prefetch_running.add(region_code)
        _region_prefetch_last[region_code] = time.time()
    thread = threading.Thread(target=_fetch_and_store_region, args=(region_code,), daemon=True)
    thread.start()

def _fetch_and_store_region(region_code):
    try:
        schools = _fetch_all_schools_for_region(region_code)
        if schools:
            region_schools_cache[region_code] = (time.time(), schools)
            app.logger.info(f"Background prefetch complete for region {region_code}: {len(schools)} schools")
    except Exception as e:
        app.logger.error(f"Background prefetch failed for region {region_code}: {e}")
    finally:
        with _region_prefetch_lock:
            _region_prefetch_running.discard(region_code)

def get_month_meals_from_api(school_code, region_code):
    today = datetime.now(KST)
    month_str = today.strftime("%Y%m")
    cache_key = f"{region_code}_{school_code}_{month_str}"

    if cache_key in meal_cache:
        return meal_cache[cache_key]

    url = "https://open.neis.go.kr/hub/mealServiceDietInfo"
    params = {
        "KEY": API_KEY, "Type": "json", "pIndex": 1, "pSize": 100,
        "ATPT_OFCDC_SC_CODE": region_code, "SD_SCHUL_CODE": school_code,
        "MLSV_YMD": month_str
    }

    meals = defaultdict(lambda: {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"})

    try:
        response = requests.get(url, params=params, timeout=5)
        response.raise_for_status()
        data = response.json()

        if "mealServiceDietInfo" in data and data.get("mealServiceDietInfo")[1].get("row"):
            for row in data["mealServiceDietInfo"][1]["row"]:
                date_str = row["MLSV_YMD"]
                menu = row["DDISH_NM"].replace("<br/>", "\n").replace("y ", "").replace("y\n", "\n")
                meal_type = row["MMEAL_SC_CODE"]

                if meal_type == "1": meals[date_str]["breakfast"] = menu
                elif meal_type == "2": meals[date_str]["lunch"] = menu
                elif meal_type == "3": meals[date_str]["dinner"] = menu

        meal_cache[cache_key] = dict(meals)
        return dict(meals)

    except requests.exceptions.Timeout:
        app.logger.error(f"NEIS API timeout for school {school_code}")
        return dict(meals)
    except Exception as e:
        app.logger.error(f"Error fetching meals from API for {school_code}: {e}")
        return dict(meals)

def get_nearby_schools(current_school_info):
    try:
        region_code = current_school_info.get('region_code')
        current_district = current_school_info.get('district')
        current_level = current_school_info.get('school_level')

        if not region_code or not current_district or not current_level:
            return []

        cached = region_schools_cache.get(region_code)
        if not cached:
            return []

        _, all_schools = cached
        nearby = [
            {'code': s['school_code'], 'name': s['school_name'], 'distance_info': current_district}
            for s in all_schools
            if s.get('district') == current_district
            and s.get('school_level') == current_level
            and s['school_code'] != current_school_info['school_code']
        ]
        nearby.sort(key=lambda x: x['name'])
        return nearby
    except Exception as e:
        app.logger.error(f"Error getting nearby schools: {e}")
        return []

def get_week_dates():
    today = datetime.now(KST).date()
    start_of_week = today - timedelta(days=(today.weekday() + 1) % 7)
    return [(start_of_week + timedelta(days=i)).strftime('%Y%m%d') for i in range(7)]

def get_month_dates():
    today = datetime.now(KST).date()
    _, last_day = calendar.monthrange(today.year, today.month)
    return [(date(today.year, today.month, day)).strftime('%Y%m%d') for day in range(1, last_day + 1)]

@app.template_filter('format_date')
def format_date(value):
    try:
        date_obj = datetime.strptime(value, "%Y%m%d")
        korean_day_names = {'Monday': '월', 'Tuesday': '화', 'Wednesday': '수',
                            'Thursday': '목', 'Friday': '금', 'Saturday': '토', 'Sunday': '일'}
        day_name = calendar.day_name[date_obj.weekday()]
        return f"{date_obj.strftime('%Y년 %m월 %d일')} ({korean_day_names[day_name]})"
    except ValueError:
        return value

@app.context_processor
def inject_today_date():
    return dict(today_date=datetime.now(KST).strftime("%Y%m%d"))

@app.route('/wp-<path:filename>')
@app.route('/wp/<path:filename>')
@app.route('/<filename>.php')
@app.route('/upload/<path:filename>')
@app.route('/userfiles/<path:filename>')
@app.route('/assets/<path:filename>')
@app.route('/xmlrpc.php')
@app.route('/wp-admin/<path:filename>')
@app.route('/wp-content/<path:filename>')
@app.route('/wp-includes/<path:filename>')
@app.route('/.well-known/<path:filename>')
@app.route('/cgi-bin')
@app.route('/mini')
@app.route('/plugins')
@app.route('/.well-known')
def silent_spam_block(filename=None):
    response = make_response('', 444)
    response.headers['X-Silent-Block'] = 'true'
    return response

@app.route("/", methods=["GET", "POST"])
def index():
    error_message = request.args.get('error_message')
    region_cookie = request.cookies.get('region_name')
    school_name_encoded = request.cookies.get('school_name')
    school_code_cookie = request.cookies.get('school_code')
    school_name_cookie = unquote(school_name_encoded) if school_name_encoded else None

    if request.method == 'POST':
        region_name = request.form['region']
        school_name_input = request.form['school_name']
        app.logger.info(f"Search request - Region: {region_name}, School: {school_name_input}")

        if not region_name or not school_name_input:
            return render_template('school_meal.html', error_message="지역과 학교명을 모두 입력해주세요.", regions=regions)

        region_code = regions.get(region_name)
        if not region_code:
            return render_template('school_meal.html', error_message="유효하지 않은 지역입니다.", regions=regions)

        schools = search_schools_neis(school_name_input, region_code, limit=1)

        if schools:
            school = schools[0]
            response = make_response(redirect(url_for('school_meal_view', school_code=school['school_code'])))
            response.set_cookie('school_code', school['school_code'], max_age=60*60*24*30)
            response.set_cookie('school_name', quote(school['school_name']), max_age=60*60*24*30)
            response.set_cookie('region_code', school['region_code'], max_age=60*60*24*30)
            response.set_cookie('region_name', region_name, max_age=60*60*24*30)
            return response
        else:
            return render_template('school_meal.html', error_message="학교를 찾을 수 없습니다.", regions=regions, region=region_name, school_name=school_name_input)

    if school_code_cookie and not error_message:
        app.logger.info(f"Redirecting to school meal page for school_code: {school_code_cookie}")
        return redirect(url_for('school_meal_view', school_code=school_code_cookie))

    if error_message:
        return render_template('school_meal.html',
                             regions=regions,
                             error_message=error_message,
                             region=region_cookie,
                             school_name=school_name_cookie)
    return render_template('school_meal.html', regions=regions)

@app.route("/meal/<school_code>")
def school_meal_view(school_code):
    app.logger.info(f"school_meal_view - school_code: {school_code}")

    school_info = get_school_from_neis(school_code)

    if not school_info:
        app.logger.warning(f"School not found via NEIS API: {school_code}")
        return redirect(url_for('index', error_message="존재하지 않거나 유효하지 않은 학교 정보입니다. 다시 검색해주세요."))

    prefetch_region_schools_async(school_info['region_code'])

    month_meals_data = get_month_meals_from_api(school_code, school_info['region_code'])

    today_str = datetime.now(KST).strftime('%Y%m%d')
    today_meal = month_meals_data.get(today_str, {
        "breakfast": "급식 정보 없음",
        "lunch": "급식 정보 없음",
        "dinner": "급식 정보 없음"
    })

    week_dates_list = get_week_dates()
    week_meals_data = {d: month_meals_data.get(d, {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"}) for d in week_dates_list}

    month_dates_list = get_month_dates()
    full_month_meals_data = {d: month_meals_data.get(d, {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"}) for d in month_dates_list}

    nearby_schools = get_nearby_schools(school_info)

    region_name = next((name for name, code in regions.items() if code == school_info['region_code']), None)

    resp = make_response(render_template(
        'school_meal.html',
        regions=regions,
        school_name=school_info['school_name'],
        school_code=school_info['school_code'],
        today_meal=today_meal,
        today_date=today_str,
        week_meals=week_meals_data,
        month_meals=full_month_meals_data,
        nearby_schools=nearby_schools,
        current_school=school_info,
        loading=False,
        region=region_name
    ))

    resp.set_cookie('school_code', school_info['school_code'], max_age=60*60*24*30)
    resp.set_cookie('school_name', quote(school_info['school_name']), max_age=60*60*24*30)
    resp.set_cookie('region_code', school_info['region_code'], max_age=60*60*24*30)
    if region_name:
        resp.set_cookie('region_name', region_name, max_age=60*60*24*30)

    return resp

@app.route('/api/meals/<school_code>/<date>')
def get_school_meal(school_code, date):
    school_info = get_school_from_neis(school_code)
    if not school_info:
        return jsonify({"error": "School not found"}), 404

    try:
        month_meals = get_month_meals_from_api(school_code, school_info['region_code'])
        meal_data = month_meals.get(date, {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"})
        return jsonify(meal_data)
    except Exception as e:
        app.logger.error(f"Error in get_school_meal API: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/schools/search')
def search_schools_autocomplete():
    query = request.args.get('q', '').strip()
    region_name = request.args.get('region', '').strip()

    if not query or len(query) < 2:
        return jsonify([])

    if not region_name or region_name not in regions:
        return jsonify([])

    region_code = regions[region_name]

    try:
        schools = search_schools_neis(query, region_code, limit=10)
        results = [
            {'code': s['school_code'], 'name': s['school_name'], 'region_code': s['region_code']}
            for s in schools
        ]
        return jsonify(results)
    except Exception as e:
        app.logger.error(f"Error in autocomplete search: {e}")
        return jsonify({"error": "검색 중 오류가 발생했습니다."}), 500

@app.route('/api/meals/today/<school_code>')
def get_today_meal(school_code):
    school_info = get_school_from_neis(school_code)
    if not school_info:
        return jsonify({"error": "School not found"}), 404

    try:
        today_str = datetime.now(KST).strftime('%Y%m%d')
        month_meals = get_month_meals_from_api(school_code, school_info['region_code'])
        today_meal = month_meals.get(today_str, {
            "breakfast": "급식 정보 없음",
            "lunch": "급식 정보 없음",
            "dinner": "급식 정보 없음"
        })
        return jsonify({
            "date": today_str,
            "formatted_date": datetime.now(KST).strftime('%Y년 %m월 %d일'),
            "meal": today_meal
        })
    except Exception as e:
        app.logger.error(f"Error in get_today_meal API: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route('/api/track', methods=['POST'])
def track_event():
    data = request.get_json(silent=True)
    if not data:
        return '', 204
    event = data.get('event', '')
    value = str(data.get('value', ''))[:50]
    allowed = {'theme', 'search_method', 'btn_month', 'btn_nearby', 'btn_share', 'btn_notification'}
    if event not in allowed:
        return '', 204
    events_logger = logging.getLogger('events')
    events_logger.info(json.dumps({
        'ts': datetime.now(KST).isoformat(),
        'ip': get_client_ip(),
        'event': event,
        'value': value
    }, ensure_ascii=False))
    return '', 204


@app.route('/current_time')
def current_time():
    return jsonify({'current_time': datetime.now(KST).isoformat()})

@app.route('/schools/<region_name>')
def schools_by_region(region_name):
    try:
        region_name = unquote(region_name)
    except:
        pass

    if region_name not in regions:
        return redirect(url_for('index', error_message="유효하지 않은 지역입니다."))

    region_code = regions[region_name]
    all_schools = get_schools_by_region_cached(region_code)

    schools_by_level = {}
    for level in school_levels.keys():
        level_schools = [
            {'code': s['school_code'], 'name': s['school_name'], 'address': s.get('address', '')}
            for s in all_schools if s.get('school_level') == level
        ]
        if level_schools:
            schools_by_level[level] = level_schools

    log_access_request(200)
    return render_template('schools_by_region.html',
                         region_name=region_name,
                         schools_by_level=schools_by_level,
                         regions=regions)

@app.route('/schools/<region_name>/<school_level>')
def schools_by_region_and_level(region_name, school_level):
    try:
        region_name = unquote(region_name)
        school_level = unquote(school_level)
    except:
        pass

    if region_name not in regions:
        return redirect(url_for('index', error_message="유효하지 않은 지역입니다."))

    if school_level not in school_levels:
        return redirect(url_for('schools_by_region', region_name=region_name))

    region_code = regions[region_name]
    schools_data = get_schools_by_region_cached(region_code, school_level)
    schools = [
        {'code': s['school_code'], 'name': s['school_name'], 'address': s.get('address', '')}
        for s in schools_data
    ]

    log_access_request(200)
    return render_template('schools_by_level.html',
                         region_name=region_name,
                         school_level=school_level,
                         schools=schools,
                         regions=regions)

@app.route('/robots.txt')
def robots_txt():
    return send_from_directory(app.static_folder, 'robots.txt')

@app.route('/favicon.svg')
def favicon():
    return send_from_directory(app.static_folder, 'favicon.svg')

@app.route('/favicon.ico')
def faviconico():
    return send_from_directory(app.static_folder, 'favicon.svg')

@app.route('/manifest.json')
def manifest():
    return send_from_directory('static', 'manifest.json')

@app.route("/It's Christmas Time Again.mp3")
def namufile1():
    return send_file("It's Christmas Time Again.mp3", mimetype="audio/mpeg")

@app.route('/sitemap.xml')
def sitemap():
    try:
        with open('static/sitemap.xml', 'r', encoding='utf-8') as f:
            content = f.read()
        response = make_response(content)
        response.headers['Content-Type'] = 'application/xml; charset=utf-8'
        return response
    except FileNotFoundError:
        abort(404)

STATIC_DIR = app.root_path

@app.route('/namuboardextension.user.js')
def serve_tampermonkey_script():
    log_namuboard_access_request()
    try:
        return send_from_directory(STATIC_DIR, 'namuboardextension.user.js', mimetype='application/javascript')
    except FileNotFoundError:
        return "파일 오류.", 404
    except Exception as e:
        app.logger.error(f"Error serving script: {e}")
        return "서버 오류.", 500

@app.route('/logs/access', methods=['GET', 'POST'])
def view_access_logs():
    auth = _admin_auth_check()
    if auth is not None:
        return auth
    try:
        if os.path.exists(ACCESS_LOG_PATH):
            with open(ACCESS_LOG_PATH, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            return f'<h2>접속 로그</h2><pre>{"".join(lines)}</pre>'
        return '접속 로그 파일이 아직 생성되지 않았습니다.'
    except Exception as e:
        return f'접속 로그 파일 읽기 오류: {e}'

@app.route('/logs/app', methods=['GET', 'POST'])
def view_app_logs():
    auth = _admin_auth_check()
    if auth is not None:
        return auth
    try:
        if os.path.exists(APP_LOG_PATH):
            with open(APP_LOG_PATH, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            return f'<h2>앱 로그</h2><pre>{"".join(lines)}</pre>'
        return '앱 로그 파일이 아직 생성되지 않았습니다.'
    except Exception as e:
        return f'앱 로그 파일 읽기 오류: {e}'

@app.route('/logs/namuboard', methods=['GET', 'POST'])
def view_namuboard_logs():
    auth = _admin_auth_check()
    if auth is not None:
        return auth
    try:
        if os.path.exists(NAMUBOARD_LOG_PATH):
            with open(NAMUBOARD_LOG_PATH, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            return f'<h2>NamuBoard Extension 로그</h2><pre>{"".join(lines)}</pre>'
        return 'NamuBoard Extension 로그 파일이 아직 생성되지 않았습니다.'
    except Exception as e:
        return f'NamuBoard Extension 로그 파일 읽기 오류: {e}'


def _admin_auth_check():
    """관리자 인증 확인. 통과하면 None, 실패하면 Response 반환."""
    client_ip = get_client_ip()
    if is_admin_ip(client_ip):
        return None
    auth_cookie = request.cookies.get('admin_auth', '')
    if ADMIN_PASSWORD_HASH and auth_cookie == ADMIN_PASSWORD_HASH:
        return None
    if request.method == 'POST':
        pw = request.form.get('password', '')
        if ADMIN_PASSWORD_HASH and hashlib.sha256(pw.encode()).hexdigest() == ADMIN_PASSWORD_HASH:
            resp = make_response(redirect(request.url))
            resp.set_cookie('admin_auth', ADMIN_PASSWORD_HASH,
                            max_age=3600 * 8, httponly=True, samesite='Lax')
            return resp
        return make_response(
            '<form method="POST">비밀번호: <input type="password" name="password">'
            '<button type="submit">확인</button>'
            '<p style="color:red">비밀번호가 틀렸습니다.</p></form>',
            401
        )
    return make_response(
        '<form method="POST">비밀번호: <input type="password" name="password">'
        '<button type="submit">확인</button></form>'
    )


@app.route('/admin', methods=['GET', 'POST'])
def admin_index():
    auth = _admin_auth_check()
    if auth is not None:
        return auth
    return (
        '<h2>관리자 메뉴</h2><ul>'
        '<li><a href="/admin/dashboard">📊 대시보드</a></li>'
        '<li><a href="/admin/dashboard?days=7">📊 대시보드 (최근 7일)</a></li>'
        '<li><a href="/admin/dashboard?days=90">📊 대시보드 (최근 90일)</a></li>'
        '<li><a href="/admin/clear/meal-cache" style="color:orange">[POST] 급식 캐시 초기화</a> '
        '— <form style="display:inline" method="POST" action="/admin/clear/meal-cache">'
        '<button type="submit">실행</button></form></li>'
        '<li><a href="/admin/clear/school-cache" style="color:orange">[POST] 학교 캐시 초기화</a> '
        '— <form style="display:inline" method="POST" action="/admin/clear/school-cache">'
        '<button type="submit">실행</button></form></li>'
        '<li><a href="/logs/access">📄 접속 로그</a></li>'
        '<li><a href="/logs/app">📄 앱 로그</a></li>'
        '<li><a href="/logs/namuboard">📄 NamuBoard 로그</a></li>'
        '<li><a href="/security/status">🔒 보안 상태 (JSON)</a></li>'
        '<li><a href="/stats">📈 간단 통계</a></li>'
        '</ul>'
    )


@app.route('/admin/dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    auth = _admin_auth_check()
    if auth is not None:
        return auth

    try:
        days = max(1, min(int(request.args.get('days', 30)), 90))
    except (ValueError, TypeError):
        days = 30

    stats = parse_logs_for_dashboard(days)

    top_bots = stats['bot_ip_list'][:50]
    missing_ips = [
        e['ip'] for e in top_bots
        if e['ip'] not in IP_INFO_CACHE
        or time.time() - IP_INFO_CACHE[e['ip']][0] >= IP_INFO_CACHE_TTL
    ]
    if missing_ips:
        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = {pool.submit(get_ip_info, ip): ip for ip in missing_ips}
            for f in as_completed(futures):
                f.result()

    enriched_bot_ips = []
    for entry in top_bots:
        info = IP_INFO_CACHE.get(entry['ip'], (0, {}))[1]
        enriched_bot_ips.append({**entry, 'info': info})
    stats['bot_ip_list_enriched'] = enriched_bot_ips

    return render_template('admin_dashboard.html', stats=stats)


@app.route('/stats', methods=['GET', 'POST'])
def view_stats():
    auth = _admin_auth_check()
    if auth is not None:
        return auth
    try:
        if not os.path.exists(ACCESS_LOG_PATH):
            return '접속 로그 파일이 없습니다.'

        stats = {
            'total_requests': 0,
            'unique_ips': set(),
            'status_codes': {},
            'popular_paths': {},
        }

        with open(ACCESS_LOG_PATH, 'r', encoding='utf-8') as f:
            for line in f:
                if 'IP:' in line:
                    stats['total_requests'] += 1
                    try:
                        ip_start = line.find('IP: ') + 4
                        ip_end = line.find(' -', ip_start)
                        if ip_end > ip_start:
                            stats['unique_ips'].add(line[ip_start:ip_end])
                    except:
                        pass
                    try:
                        status_start = line.find('Status: ') + 8
                        status_end = line.find(' -', status_start)
                        if status_end == -1:
                            status_end = len(line)
                        status = line[status_start:status_end].strip()
                        stats['status_codes'][status] = stats['status_codes'].get(status, 0) + 1
                    except:
                        pass
                    try:
                        path_start = line.find('Path: ') + 6
                        path_end = line.find(' -', path_start)
                        if path_end > path_start:
                            path = line[path_start:path_end]
                            stats['popular_paths'][path] = stats['popular_paths'].get(path, 0) + 1
                    except:
                        pass

        unique_ip_count = len(stats['unique_ips'])

        return f'''
        <h2>접속 통계</h2>
        <p>총 요청 수: {stats['total_requests']}</p>
        <p>고유 IP 수: {unique_ip_count}</p>
        <h3>상태 코드별 통계:</h3>
        <ul>{"".join([f"<li>{k}: {v}회</li>" for k, v in stats['status_codes'].items()])}</ul>
        <h3>인기 경로 (Top 10):</h3>
        <ul>{"".join([f"<li>{k}: {v}회</li>" for k, v in sorted(stats['popular_paths'].items(), key=lambda x: x[1], reverse=True)[:10]])}</ul>
        <h2>캐시 현황</h2>
        <p>급식 캐시: {len(meal_cache)}건</p>
        <p>학교 코드 캐시: {len(school_code_cache)}건</p>
        <p>검색 결과 캐시: {len(search_result_cache)}건</p>
        <p>지역별 학교 캐시: {len(region_schools_cache)}개 지역</p>
        '''
    except Exception as e:
        return f'통계 생성 오류: {e}'

@app.route('/security/status', methods=['GET', 'POST'])
def security_status():
    auth = _admin_auth_check()
    if auth is not None:
        return auth
    status = {
        'blocked_networks_count': len(BLOCKED_NETWORKS),
        'temporarily_blocked_ips': len(blocked_ips),
        'failed_attempts': dict(failed_attempts),
        'active_connections': len(request_counts),
        'security_config': SECURITY_CONFIG
    }
    return jsonify(status)

@app.route("/health")
def health():
    return "ok", 200

@app.route('/admin/clear/meal-cache', methods=['POST'])
def admin_clear_meal_cache():
    auth = _admin_auth_check()
    if auth is not None:
        return auth

    global meal_cache
    cache_size = len(meal_cache)
    meal_cache = {}

    return jsonify({
        'status': 'success',
        'message': f'급식 캐시 초기화 완료. {cache_size}개 항목이 삭제되었습니다.'
    })

@app.route('/admin/clear/school-cache', methods=['POST'])
def admin_clear_school_cache():
    auth = _admin_auth_check()
    if auth is not None:
        return auth

    global school_code_cache, search_result_cache, region_schools_cache
    counts = (len(school_code_cache), len(search_result_cache), len(region_schools_cache))
    school_code_cache = {}
    search_result_cache = {}
    region_schools_cache = {}

    return jsonify({
        'status': 'success',
        'message': f'학교 캐시 초기화 완료. 코드:{counts[0]}, 검색:{counts[1]}, 지역:{counts[2]}건 삭제.'
    })

@app.route('/security/blacklist/add', methods=['POST'])
def add_to_blacklist():
    auth = _admin_auth_check()
    if auth is not None:
        return auth

    data = request.get_json()
    ip_or_cidr = data.get('ip_or_cidr')
    reason = data.get('reason', 'Manual addition')

    if not ip_or_cidr:
        return jsonify({'error': 'IP or CIDR required'}), 400

    try:
        ipaddress.ip_network(ip_or_cidr, strict=False)
        save_to_blacklist(ip_or_cidr, reason)
        refresh_blacklist()
        synced, sync_error = sync_blacklist_to_github()
        return jsonify({
            'success': True,
            'message': f'Added {ip_or_cidr} to blacklist',
            'github_synced': synced,
            'github_error': sync_error,
        })
    except ValueError as e:
        return jsonify({'error': f'Invalid IP/CIDR format: {e}'}), 400

@app.route('/admin/blocklist', methods=['GET', 'POST'])
def admin_blocklist():
    auth = _admin_auth_check()
    if auth is not None:
        return auth

    message = None
    error = None

    if request.method == 'POST':
        cidr_input = request.form.get('cidr', '').strip()
        reason = request.form.get('reason', '').strip() or 'Manual addition (admin page)'
        try:
            ipaddress.ip_network(cidr_input, strict=False)
            save_to_blacklist(cidr_input, reason)
            refresh_blacklist()
            synced, sync_error = sync_blacklist_to_github()
            if synced:
                message = f'{cidr_input} 차단 완료 (GitHub 동기화됨)'
            elif sync_error:
                message = f'{cidr_input} 차단 완료 (로컬만 적용, GitHub 동기화 실패: {sync_error})'
            else:
                message = f'{cidr_input} 차단 완료'
        except ValueError as e:
            error = f'잘못된 IP/CIDR 형식입니다: {e}'

    with open(BLACKLIST_FILE, 'r', encoding='utf-8') as f:
        recent_lines = [l.rstrip('\n') for l in f if l.strip() and not l.strip().startswith('#')][-30:]
    recent_lines.reverse()

    return render_template(
        'admin_blocklist.html',
        message=message,
        error=error,
        recent_lines=recent_lines,
        total_networks=len(BLOCKED_NETWORKS),
        github_configured=github_sync_configured(),
    )

@app.after_request
def after_request_func(response):
    if response.headers.get('X-Silent-Block'):
        return response

    request_path = request.path
    request_method = request.method
    status_code = response.status_code

    if should_log_request(request_path, request_method):
        if status_code in [200, 206]:
            log_access_request(status_code)
        elif status_code >= 400:
            app.logger.warning(f"Error - Method: {request_method}, Path: {request_path}, Status: {status_code}")

    return response

_error_info = {
    400: ('Bad Request', '요청하신 URL을 이 서버에서 찾을 수 없습니다.'),
    401: ('Unauthorized', '인증되지 않았습니다.'),
    403: ('Forbidden', '이 페이지에 접근할 권한이 없습니다.'),
    404: ('Not Found', '요청하신 페이지가 존재하지 않습니다.'),
    405: ('Method Not Allowed', '이 페이지는 해당 요청 방식을 지원하지 않습니다.'),
    406: ('Not Acceptable', '요청한 형식으로는 리소스를 제공할 수 없습니다.'),
    408: ('Request Timeout', '요청 시간이 초과되었습니다.'),
    409: ('Conflict', '요청이 서버의 현재 상태와 충돌합니다.'),
    410: ('Gone', '요청한 리소스는 더 이상 사용할 수 없습니다.'),
    411: ('Length Required', 'Content-Length 헤더가 필요합니다.'),
    412: ('Precondition Failed', '요청의 사전 조건이 충족되지 않았습니다.'),
    413: ('Payload Too Large', '요청 데이터의 크기가 허용 범위를 초과합니다.'),
    414: ('URI Too Long', '요청한 URI의 길이가 너무 깁니다.'),
    415: ('Unsupported Media Type', '지원되지 않는 미디어 타입입니다.'),
    416: ('Range Not Satisfiable', '요청한 범위를 처리할 수 없습니다.'),
    417: ('Expectation Failed', '요청의 Expect 헤더를 충족할 수 없습니다.'),
    422: ('Unprocessable Entity', '요청을 처리할 수 없습니다.'),
    423: ('Locked', '요청한 리소스가 잠겨 있습니다.'),
    424: ('Failed Dependency', '이전 요청의 실패로 인해 처리할 수 없습니다.'),
    431: ('Request Header Fields Too Large', '요청 헤더의 크기가 너무 큽니다.'),
    451: ('Unavailable For Legal Reasons', '법적 사유로 접근이 제한되었습니다.'),
    500: ('서버 내부 오류', '서버에서 예기치 않은 오류가 발생했습니다. 잠시 후 다시 시도해 주세요.')
}

def _render_error(code):
    title, desc = _error_info.get(code, ('오류', '알 수 없는 오류가 발생했습니다.'))
    return render_template('error.html',
                           error_code=code,
                           error_title=title,
                           error_description=desc), code

@app.errorhandler(400)
def error_401(e): return _render_error(400)

@app.errorhandler(401)
def error_401(e): return _render_error(401)

@app.errorhandler(403)
def error_401(e): return _render_error(403)

@app.errorhandler(404)
def error_401(e): return _render_error(404)

@app.errorhandler(405)
def error_401(e): return _render_error(405)

@app.errorhandler(406)
def error_406(e): return _render_error(406)

@app.errorhandler(408)
def error_408(e): return _render_error(408)

@app.errorhandler(409)
def error_409(e): return _render_error(409)

@app.errorhandler(410)
def error_410(e): return _render_error(410)

@app.errorhandler(411)
def error_411(e): return _render_error(411)

@app.errorhandler(412)
def error_412(e): return _render_error(412)

@app.errorhandler(413)
def error_413(e): return _render_error(413)

@app.errorhandler(414)
def error_414(e): return _render_error(414)

@app.errorhandler(415)
def error_415(e): return _render_error(415)

@app.errorhandler(416)
def error_416(e): return _render_error(416)

@app.errorhandler(417)
def error_417(e): return _render_error(417)

@app.errorhandler(422)
def error_422(e): return _render_error(422)

@app.errorhandler(423)
def error_423(e): return _render_error(423)

@app.errorhandler(424)
def error_424(e): return _render_error(424)

@app.errorhandler(431)
def error_431(e): return _render_error(431)

@app.errorhandler(451)
def error_451(e): return _render_error(451)

@app.errorhandler(500)
def error_451(e): return _render_error(500)

def _warm_region_caches():
    for region_code in list(regions.values()):
        cached = region_schools_cache.get(region_code)
        if cached and time.time() - cached[0] <= REGION_SCHOOLS_CACHE_TTL:
            continue
        _fetch_and_store_region(region_code)
        time.sleep(1)

threading.Thread(target=_warm_region_caches, daemon=True).start()

if __name__ == "__main__":
    app.logger.info(f"LOG_DIR: {LOG_DIR}")
    app.logger.info(f"접속 로그 파일 경로: {ACCESS_LOG_PATH}")
    app.logger.info(f"앱 로그 파일 경로: {APP_LOG_PATH}")
    app.logger.info(f"IP 차단 로그 파일 경로: {IP_BLOCK_LOG_PATH}")
    app.logger.info(f"NamuBoard Extension 로그 파일 경로: {NAMUBOARD_LOG_PATH}")
    app.logger.info(f"이벤트 로그 파일 경로: {EVENTS_LOG_PATH}")
    app.logger.info(f"관리자 화이트리스트: {ADMIN_WHITELIST}")

    if not os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, 'w', encoding='utf-8') as f:
            f.write("# IP Blacklist - CIDR format\n")
            f.write("# Example: 192.168.1.0/24\n")

    app.logger.info(f"Security blacklist loaded: {len(BLOCKED_NETWORKS)} networks")
    app.logger.info(f"Security config: {SECURITY_CONFIG}")

    app.run(debug=False)
