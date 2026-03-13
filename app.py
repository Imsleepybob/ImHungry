from flask import Flask, render_template, request, send_file, make_response, jsonify, redirect, url_for, send_from_directory, abort
from datetime import datetime, timedelta, date, timezone
from collections import defaultdict, deque
import calendar
import requests
import logging
from logging.handlers import RotatingFileHandler
import ipaddress
from urllib.parse import quote, unquote
import os
import re
import time
import json
import threading

app = Flask(__name__)

meal_cache = {}

school_code_cache = {}
search_result_cache = {}
region_schools_cache = {}

SCHOOL_CODE_CACHE_TTL = 86400
SEARCH_CACHE_TTL = 3600
REGION_SCHOOLS_CACHE_TTL = 86400

# [수정] LOG_DIR: Render Persistent Disk 경로를 환경변수로 지정 가능
# Render 대시보드 > Environment에서 LOG_DIR=/var/data 설정 후 Persistent Disk를 /var/data에 마운트
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
    # [수정] /admin 하위 경로 및 이벤트 트래킹은 통계에서 제외
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

# [수정] 크롤러 판별 + 이름 추출용 맵 (구체적인 것부터 순서 중요)
CRAWLER_NAME_MAP = [
    ('googlebot',           'Googlebot'),
    ('bingbot',             'Bingbot'),
    ('yandexbot',           'YandexBot'),
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
    ('twitterbot',          'TwitterBot'),
    ('linkedinbot',         'LinkedInBot'),
    ('slurp',               'Yahoo Slurp'),
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

BLOCKED_NETWORKS = load_ip_blacklist()

ADMIN_WHITELIST = [
    '210.94.23.150/32',
    '118.221.147.88/32',
]

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
        if ip_address in blocked_ips:
            return True
        for blocked_network in BLOCKED_NETWORKS:
            network = ipaddress.ip_network(blocked_network, strict=False)
            if client_ip in network:
                return True
        return False
    except ValueError:
        app.logger.error(f"Invalid IP address detected: {ip_address}")
        return True

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

@app.before_request
def security_check():
    client_ip = get_client_ip()
    if is_admin_ip(client_ip):
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

# [수정] 로그 경로: LOG_DIR 기반으로 변경
ACCESS_LOG_PATH = os.path.join(LOG_DIR, 'access.log')
APP_LOG_PATH = os.path.join(LOG_DIR, 'app.log')
IP_BLOCK_LOG_PATH = os.path.join(LOG_DIR, 'ip_block.log')
NAMUBOARD_LOG_PATH = os.path.join(LOG_DIR, 'namuboard.log')
EVENTS_LOG_PATH = os.path.join(LOG_DIR, 'events.log')


class AccessLogFormatter(logging.Formatter):
    def format(self, record):
        record.remote_addr = getattr(record, 'remote_addr', 'N/A')
        record.user_agent = getattr(record, 'user_agent', 'N/A')
        # [수정] Device, OS, Browser, Crawler 필드 추가
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
    # [수정] OS, Crawler 필드 추가
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

    # [수정] events 로거 추가 - JSON Lines 형식
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


# [수정] UA 분석: 반환값 (is_crawler, crawler_label, device, os_name, browser)
# 크롤러인 경우 crawler_label = "Googlebot (Mozilla/5.0 (compatible; ...))" 형태
def detect_client_type(raw_ua):
    if not raw_ua:
        return True, 'Unknown Bot', 'Unknown', 'Unknown', 'Unknown'

    ua_lower = raw_ua.lower()
    # UA 앞 80자를 snippet으로 보존 (크롤러 식별에 활용)
    ua_snippet = raw_ua[:80].strip()

    # 크롤러 판별: 이름을 추출하고 UA snippet 병기
    for pattern, name in CRAWLER_NAME_MAP:
        if pattern in ua_lower:
            return True, f"{name} ({ua_snippet})", 'Crawler', 'Crawler', 'Crawler'

    # OS 탐지
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

    # 디바이스 탐지
    if 'ipad' in ua_lower or 'tablet' in ua_lower:
        device = 'Tablet'
    elif any(k in ua_lower for k in ('mobile', 'android', 'iphone', 'ipod')):
        device = 'Mobile'
    else:
        device = 'Desktop'

    # 브라우저 탐지 (순서 중요)
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
    cleaned_ua = re.sub(r'^(Mozilla/\d\.\d\s\(.*\)|AppleWebKit/\d+\.\d+\s\(.*\)|KHTML,\s*like\s*Gecko\s*|Chrome/\d+\.\d+\.\d+\.\d+\s*|Safari/\d+\.\d+\s*|Edge/\d+\.\d+\s*|Firefox/\d+\.\d+\s*)+', '', user_agent_string).strip()
    return cleaned_ua[:200]

def log_access_request(status_code=200):
    if request.method in ['GET', 'POST'] and status_code in [200, 206]:
        try:
            real_ip = get_client_ip()
            # [수정] 관리자 IP는 통계에서 제외
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
                # 크롤러면 "Googlebot (UA...)" 형태, 일반 사용자면 'N'
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


# [수정] 대시보드용 로그 파싱 함수
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
    }

    # 신규 포맷: ... - Device: X - OS: X - Browser: X - Crawler: X - UA: ...
    # 구 포맷:   ... - Device: X - Browser: X - UA: ...  (OS/Crawler 필드 없음)
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
                stats['paths'][path] += 1
                stats['ips'][ip] += 1

                school_m = re.match(r'^/meal/(\w+)$', path)
                if school_m:
                    stats['school_visits'][school_m.group(1)] += 1

                if referrer and referrer != 'N/A':
                    ref_m = re.match(r'https?://([^/]+)', referrer)
                    if ref_m:
                        stats['referrers'][ref_m.group(1)] += 1

                # 신규 포맷 (Crawler 필드 존재)
                if device:
                    is_crawler_entry = crawler_field is not None and crawler_field.strip() != 'N'
                    if is_crawler_entry:
                        stats['crawlers'] += 1
                        # "Googlebot (UA snippet)" → "Googlebot"
                        cname = crawler_field.split(' (')[0].strip()
                        stats['crawler_names'][cname] += 1
                    elif device == 'Crawler':
                        # 구 포맷 크롤러 (OS 필드 없던 시절)
                        stats['crawlers'] += 1
                        is_c, clabel, *_ = detect_client_type(ua)
                        cname = clabel.split(' (')[0].strip() if clabel else 'Unknown'
                        stats['crawler_names'][cname] += 1
                    else:
                        stats['users'] += 1
                        stats['devices'][device] += 1
                        stats['os_names'][os_name.strip() if os_name else 'Unknown OS'] += 1
                        stats['browsers'][browser.strip() if browser else 'Other'] += 1
                else:
                    # 구 포맷 (Device 필드 자체 없음) → UA 재탐지
                    is_crawler, crawler_label, det_device, det_os, det_browser = detect_client_type(ua)
                    if is_crawler:
                        stats['crawlers'] += 1
                        cname = crawler_label.split(' (')[0].strip()
                        stats['crawler_names'][cname] += 1
                    else:
                        stats['users'] += 1
                        stats['devices'][det_device] += 1
                        stats['os_names'][det_os] += 1
                        stats['browsers'][det_browser] += 1

    # events.log 파싱
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

    # school_code → 학교명 변환 (메모리 캐시에 있는 경우만)
    school_names = {}
    for code in list(stats['school_visits'].keys()):
        cached = school_code_cache.get(code)
        school_names[code] = cached[1]['school_name'] if cached else code

    return {
        'total_requests': stats['total_requests'],
        'unique_ips': len(stats['unique_ips']),
        'today_requests': stats['today_requests'],
        'crawlers': stats['crawlers'],
        'users': stats['users'],
        'requests_by_day': dict(sorted(stats['requests_by_day'].items())[-14:]),
        'status_codes': dict(sorted(stats['status_codes'].items())),
        'top_paths': sorted(stats['paths'].items(), key=lambda x: x[1], reverse=True)[:15],
        'top_schools': [
            (school_names.get(c, c), v)
            for c, v in sorted(stats['school_visits'].items(), key=lambda x: x[1], reverse=True)[:10]
        ],
        'top_ips': sorted(stats['ips'].items(), key=lambda x: x[1], reverse=True)[:10],
        'top_referrers': sorted(stats['referrers'].items(), key=lambda x: x[1], reverse=True)[:10],
        'devices': dict(stats['devices']),
        'os_names': dict(sorted(stats['os_names'].items(), key=lambda x: x[1], reverse=True)),
        'browsers': dict(stats['browsers']),
        'top_crawlers': sorted(stats['crawler_names'].items(), key=lambda x: x[1], reverse=True)[:15],
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

def search_schools_neis(query, region_code, limit=10):
    cache_key = (query.lower(), region_code)
    cached = search_result_cache.get(cache_key)
    if cached and time.time() - cached[0] < SEARCH_CACHE_TTL:
        return cached[1]

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

def prefetch_region_schools_async(region_code):
    cached = region_schools_cache.get(region_code)
    if not cached or time.time() - cached[0] > REGION_SCHOOLS_CACHE_TTL:
        thread = threading.Thread(
            target=_fetch_and_store_region,
            args=(region_code,),
            daemon=True
        )
        thread.start()

def _fetch_and_store_region(region_code):
    try:
        schools = _fetch_all_schools_for_region(region_code)
        region_schools_cache[region_code] = (time.time(), schools)
        app.logger.info(f"Background prefetch complete for region {region_code}: {len(schools)} schools")
    except Exception as e:
        app.logger.error(f"Background prefetch failed for region {region_code}: {e}")

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


# [수정] 클라이언트 이벤트 트래킹 엔드포인트
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

@app.route('/logs/access')
def view_access_logs():
    client_ip = get_client_ip()
    if not (is_admin_ip(client_ip) or (app.debug and os.environ.get('ENABLE_LOG_VIEW') == 'true')):
        app.logger.warning(f"Unauthorized access attempt to logs from IP: {client_ip}")
        return "접근 권한이 없습니다.", 403
    try:
        if os.path.exists(ACCESS_LOG_PATH):
            with open(ACCESS_LOG_PATH, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            return f'<h2>접속 로그</h2><pre>{"".join(lines)}</pre>'
        return '접속 로그 파일이 아직 생성되지 않았습니다.'
    except Exception as e:
        return f'접속 로그 파일 읽기 오류: {e}'

@app.route('/logs/app')
def view_app_logs():
    client_ip = get_client_ip()
    if not (is_admin_ip(client_ip) or (app.debug and os.environ.get('ENABLE_LOG_VIEW') == 'true')):
        app.logger.warning(f"Unauthorized access attempt to logs from IP: {client_ip}")
        return "접근 권한이 없습니다.", 403
    try:
        if os.path.exists(APP_LOG_PATH):
            with open(APP_LOG_PATH, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            return f'<h2>앱 로그</h2><pre>{"".join(lines)}</pre>'
        return '앱 로그 파일이 아직 생성되지 않았습니다.'
    except Exception as e:
        return f'앱 로그 파일 읽기 오류: {e}'

@app.route('/logs/namuboard')
def view_namuboard_logs():
    client_ip = get_client_ip()
    if not (is_admin_ip(client_ip) or (app.debug and os.environ.get('ENABLE_LOG_VIEW') == 'true')):
        app.logger.warning(f"Unauthorized access attempt to namuboard logs from IP: {client_ip}")
        return "접근 권한이 없습니다.", 403
    try:
        if os.path.exists(NAMUBOARD_LOG_PATH):
            with open(NAMUBOARD_LOG_PATH, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            return f'<h2>NamuBoard Extension 로그</h2><pre>{"".join(lines)}</pre>'
        return 'NamuBoard Extension 로그 파일이 아직 생성되지 않았습니다.'
    except Exception as e:
        return f'NamuBoard Extension 로그 파일 읽기 오류: {e}'


# [수정] 시각화 대시보드 - 관리자 전용
@app.route('/admin/dashboard')
def admin_dashboard():
    client_ip = get_client_ip()
    if not is_admin_ip(client_ip):
        abort(403)
    try:
        days = max(1, min(int(request.args.get('days', 30)), 90))
    except (ValueError, TypeError):
        days = 30
    stats = parse_logs_for_dashboard(days)
    return render_template('admin_dashboard.html', stats=stats)


@app.route('/stats')
def view_stats():
    client_ip = get_client_ip()
    if not (is_admin_ip(client_ip) or (app.debug and os.environ.get('ENABLE_STATS') == 'true')):
        app.logger.warning(f"Unauthorized access attempt to stats from IP: {client_ip}")
        return "접근 권한이 없습니다.", 403
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

@app.route('/security/status')
def security_status():
    client_ip = get_client_ip()
    if not is_admin_ip(client_ip):
        abort(403)
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
    client_ip = get_client_ip()
    if not is_admin_ip(client_ip):
        abort(403)

    global meal_cache
    cache_size = len(meal_cache)
    meal_cache = {}

    return jsonify({
        'status': 'success',
        'message': f'급식 캐시 초기화 완료. {cache_size}개 항목이 삭제되었습니다.'
    })

@app.route('/admin/clear/school-cache', methods=['POST'])
def admin_clear_school_cache():
    client_ip = get_client_ip()
    if not is_admin_ip(client_ip):
        abort(403)

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
    client_ip = get_client_ip()
    if not is_admin_ip(client_ip):
        abort(403)

    data = request.get_json()
    ip_or_cidr = data.get('ip_or_cidr')
    reason = data.get('reason', 'Manual addition')

    if not ip_or_cidr:
        return jsonify({'error': 'IP or CIDR required'}), 400

    try:
        ipaddress.ip_network(ip_or_cidr, strict=False)
        save_to_blacklist(ip_or_cidr, reason)
        global BLOCKED_NETWORKS
        BLOCKED_NETWORKS = load_ip_blacklist()
        return jsonify({'success': True, 'message': f'Added {ip_or_cidr} to blacklist'})
    except ValueError as e:
        return jsonify({'error': f'Invalid IP/CIDR format: {e}'}), 400

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
