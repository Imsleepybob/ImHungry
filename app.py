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
from functools import wraps

app = Flask(__name__)

# --- 보안 설정 ---
# IP 블랙리스트 파일 경로
BLACKLIST_FILE = os.path.join(os.getcwd(), 'ip_blacklist.txt')
SUSPICIOUS_PATTERNS_FILE = os.path.join(os.getcwd(), 'suspicious_patterns.json')

# Rate limiting을 위한 메모리 저장소 (프로덕션에서는 Redis 권장)
request_counts = defaultdict(deque)
failed_attempts = defaultdict(int)
blocked_ips = set()

# 보안 설정
SECURITY_CONFIG = {
    'rate_limit_window': 3,  # 3초
    'rate_limit_requests': 25,  # 25개 요청까지
    'failed_attempt_threshold': 1,  # 1회 실패시 차단
    'auto_block_duration': 864000,  # 240시간 자동 차단
    'suspicious_ua_block': True,  # 의심스러운 User-Agent 차단
    'path_traversal_protection': True,  # 경로 탐색 공격 차단
}

# 로그를 남기지 않을 경로들 정의
NO_LOG_PATHS = [
    '/wp-', '/wp/', 'wordpress', '.php', '/userfiles', '/upload', '/assets',
    'xmlrpc.php', 'wp-admin', 'wp-content', 'wp-includes',
    '/logs/', '/stats', '/security/',  # 관리자 페이지들도 로그에서 제외
    '/favicon', '/robots.txt', '/manifest.json', '/sitemap.xml'  # 정적 파일들
]

# 조용히 차단할 패턴들 (로그도 남기지 않음)
SILENT_BLOCK_PATTERNS = [
    '/wp-', '/wp/', 'wordpress', '.php', '/userfiles', '/upload', '/assets',
    'xmlrpc.php', 'wp-admin', 'wp-content', 'wp-includes', '.env', 'config',
    '.git', '.sql', 'backup', 'shell', 'cmd', 'eval', '.asp', '.jsp', '.cgi',
    '/user', '/users', '/client', '/clients', '/order', '/orders',
    '/invoice', '/refund', '/statement', '/card', '/authorization',
    '/authorize', '/private-data', '/archives', '/saving', '/savings',
    '/ebank', '/ebanking', '/balance'
]

# 의심스러운 패턴들
SUSPICIOUS_PATTERNS = {
    'paths': [
        r'\.php$', r'wp-', r'admin', r'login', r'\.env', r'config',
        r'\.git', r'\.sql', r'backup', r'shell', r'cmd', r'eval',
        r'xmlrpc', r'\.asp', r'\.jsp', r'\.cgi'
    ],
    'user_agents': [
        r'spider', r'scanner', r'nikto',
        r'sqlmap', r'nmap', r'masscan', r'zap', r'burp'
    ],
    'parameters': [
        r'union.*select', r'<script', r'javascript:', r'eval\(',
        r'exec\(', r'system\(', r'\.\./', r'etc/passwd'
    ]
}

def load_ip_blacklist():
    """IP 블랙리스트 파일에서 CIDR 목록 로드"""
    blacklist = []
    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                # 1) 앞뒤 공백 제거
                line = line.strip()
                # 2) 빈 줄 또는 주석(#로 시작)은 건너뜀
                if not line or line.startswith('#'):
                    continue
                # 3) '#' 뒤 주석 제거
                cidr_part = line.split('#', 1)[0].strip()
                try:
                    ipaddress.ip_network(cidr_part, strict=False)
                    blacklist.append(cidr_part)
                except ValueError:
                    app.logger.warning(f"Invalid CIDR format in blacklist: {line}")
    return blacklist


def save_to_blacklist(ip_or_cidr, reason="Automatic detection"):
    """새로운 IP/CIDR을 블랙리스트에 추가"""
    try:
        with open(BLACKLIST_FILE, 'a', encoding='utf-8') as f:
            f.write(f"{ip_or_cidr}  # {reason} - {datetime.now()}\n")
        app.logger.info(f"Added to blacklist: {ip_or_cidr} - {reason}")
    except Exception as e:
        app.logger.error(f"Error saving to blacklist: {e}")

# 블랙리스트 로드
BLOCKED_NETWORKS = load_ip_blacklist()

# --- 관리자 IP 화이트리스트 ---
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
    """로그를 남길지 판단하는 함수"""
    # 스팸/공격성 요청들 필터링
    if any(pattern in path.lower() for pattern in NO_LOG_PATHS):
        return False

    # HEAD 요청 제외
    if method == 'HEAD':
        return False

    return True

def should_silent_block(path):
    """조용히 차단할지 판단하는 함수"""
    return any(pattern in path.lower() for pattern in SILENT_BLOCK_PATTERNS)

def is_ip_blocked(ip_address):
    """IP가 차단 목록에 있는지 확인"""
    try:
        client_ip = ipaddress.ip_address(ip_address)

        # 동적 차단 목록 확인
        if ip_address in blocked_ips:
            return True

        # 정적 블랙리스트 확인
        for blocked_network in BLOCKED_NETWORKS:
            network = ipaddress.ip_network(blocked_network, strict=False)
            if client_ip in network:
                return True
        return False
    except ValueError:
        app.logger.error(f"Invalid IP address detected: {ip_address}")
        return True  # 잘못된 IP는 차단

def is_admin_ip(ip_address):
    """관리자 IP 화이트리스트 확인"""
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
    """Rate limiting 확인"""
    now = time.time()
    window_start = now - SECURITY_CONFIG['rate_limit_window']

    # 오래된 요청 제거
    while request_counts[ip_address] and request_counts[ip_address][0] < window_start:
        request_counts[ip_address].popleft()

    # 현재 요청 추가
    request_counts[ip_address].append(now)

    # Rate limit 확인
    if len(request_counts[ip_address]) > SECURITY_CONFIG['rate_limit_requests']:
        return True

    return False

def is_suspicious_request():
    """의심스러운 요청 패턴 탐지"""
    suspicion_score = 0
    reasons = []

    # 1. 경로 검사
    path = request.path.lower()
    for pattern in SUSPICIOUS_PATTERNS['paths']:
        if re.search(pattern, path, re.IGNORECASE):
            suspicion_score += 10
            reasons.append(f"Suspicious path: {pattern}")

    # 2. User-Agent 검사
    user_agent = request.headers.get('User-Agent', '').lower()
    if not user_agent or len(user_agent) < 10:
        suspicion_score += 5
        reasons.append("Missing or short User-Agent")

    for pattern in SUSPICIOUS_PATTERNS['user_agents']:
        if re.search(pattern, user_agent, re.IGNORECASE):
            suspicion_score += 15
            reasons.append(f"Suspicious User-Agent: {pattern}")

    # 3. 쿼리 파라미터 검사
    query_string = request.query_string.decode('utf-8', errors='ignore').lower()
    for pattern in SUSPICIOUS_PATTERNS['parameters']:
        if re.search(pattern, query_string, re.IGNORECASE):
            suspicion_score += 20
            reasons.append(f"Suspicious parameter: {pattern}")

    # 4. HTTP 메소드 검사 (웹사이트 특성상 GET, POST만 허용)
    if request.method not in ['GET', 'POST', 'HEAD']:
        suspicion_score += 10
        reasons.append(f"Suspicious method: {request.method}")

    # 5. 존재하지 않는 확장자 요청
    if path.endswith(('.php', '.asp', '.jsp', '.cgi')) and not path.startswith('/api/'):
        suspicion_score += 15
        reasons.append("Non-existent extension request")

    return suspicion_score >= 10, suspicion_score, reasons

def log_security_incident(ip, incident_type, details, suspicion_score=0):
    """보안 사고 로깅"""
    security_logger = logging.getLogger('security')
    security_logger.warning(
        f"SECURITY INCIDENT - IP: {ip}, Type: {incident_type}, "
        f"Score: {suspicion_score}, Details: {details}, "
        f"UA: {request.headers.get('User-Agent', 'N/A')[:100]}, "
        f"Path: {request.path}, Method: {request.method}"
    )

def auto_block_ip(ip, reason, duration=None):
    """IP를 자동으로 일정 시간 차단"""
    if duration is None:
        duration = SECURITY_CONFIG['auto_block_duration']

    blocked_ips.add(ip)
    log_security_incident(ip, "AUTO_BLOCK", f"{reason} - Duration: {duration}s")

    # 영구 블랙리스트에 추가 (높은 위험도인 경우)
    failed_attempts[ip] += 1
    if failed_attempts[ip] >= SECURITY_CONFIG['failed_attempt_threshold']:
        save_to_blacklist(f"{ip}/32", f"Auto-blocked: {reason}")

@app.before_request
def security_check():
    """종합 보안 검사"""
    client_ip = get_client_ip()

    # 1. 관리자 IP는 모든 검사 통과
    if is_admin_ip(client_ip):
        return

    # 2. 스팸 요청은 조용히 차단 (444로 변경)
    if should_silent_block(request.path):
        response = make_response('', 444)
        response.headers['Connection'] = 'close'
        return response

    # 3. IP 차단 확인 (444로 변경)
    if is_ip_blocked(client_ip):
        log_security_incident(client_ip, "BLOCKED_IP", "IP in blacklist")
        response = make_response('', 444)
        response.headers['Connection'] = 'close'
        return response

    # 4. Rate limiting 확인 (444로 변경)
    if is_rate_limited(client_ip):
        log_security_incident(client_ip, "RATE_LIMIT", "Too many requests")
        auto_block_ip(client_ip, "Rate limit exceeded", 864000)  # 24시간으로 변경
        response = make_response('', 444)
        response.headers['Connection'] = 'close'
        return response

    # 5. 의심스러운 요청 패턴 확인
    is_suspicious, suspicion_score, reasons = is_suspicious_request()
    if is_suspicious:
        log_security_incident(client_ip, "SUSPICIOUS_PATTERN",
                            f"Reasons: {', '.join(reasons)}", suspicion_score)

        # 점수가 높으면 자동 차단 (444로 변경)
        if suspicion_score >= 15:  # 20 → 15로 더 엄격하게
            auto_block_ip(client_ip, f"High suspicion score: {suspicion_score}")
            response = make_response('', 444)
            response.headers['Connection'] = 'close'
            return response
        elif suspicion_score >= 10:  # 15 → 10으로 더 엄격하게
            # 중간 점수도 444로 응답
            response = make_response('', 444)
            response.headers['Connection'] = 'close'
            return response

    # 6. 경로 탐색 공격 방지 (444로 변경)
    if SECURITY_CONFIG['path_traversal_protection']:
        if '../' in request.path or '..\\' in request.path:
            log_security_incident(client_ip, "PATH_TRAVERSAL", request.path)
            auto_block_ip(client_ip, "Path traversal attempt")
            response = make_response('', 444)
            response.headers['Connection'] = 'close'
            return response

# 보안 로거 설정
def setup_security_logging():
    security_logger = logging.getLogger('security')
    security_handler = RotatingFileHandler(
        os.path.join(os.getcwd(), 'security.log'),
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

# 로깅 설정
setup_security_logging()

# --- 로깅 설정 (확장) ---
# 로그 파일 경로 설정 (프로젝트 루트 디렉토리)
ACCESS_LOG_PATH = os.path.join(os.getcwd(), 'access.log')
APP_LOG_PATH = os.path.join(os.getcwd(), 'app.log')
IP_BLOCK_LOG_PATH = os.path.join(os.getcwd(), 'ip_block.log')
NAMUBOARD_LOG_PATH = os.path.join(os.getcwd(), 'namuboard.log') # New log file for namuboardextension

# 커스텀 로그 포맷터
class AccessLogFormatter(logging.Formatter):
    def format(self, record):
        # request 객체에서 정보 추출
        record.remote_addr = getattr(record, 'remote_addr', 'N/A')
        record.user_agent = getattr(record, 'user_agent', 'N/A')
        record.method = getattr(record, 'method', 'N/A')
        record.path = getattr(record, 'path', 'N/A')
        record.status = getattr(record, 'status', 'N/A')
        record.referrer = getattr(record, 'referrer', 'N/A')
        return super().format(record)

def setup_logging():
    """로깅 시스템 초기화"""
    # 기본 로거 설정
    logging.basicConfig(level=logging.INFO)

    # 1. 앱 로그 핸들러 (기본 앱 로그)
    app_handler = RotatingFileHandler(
        APP_LOG_PATH,
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    app_handler.setFormatter(logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
    ))

    # 2. 접속 로그 핸들러
    access_handler = RotatingFileHandler(
        ACCESS_LOG_PATH,
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    access_formatter = AccessLogFormatter(
        '%(asctime)s - IP: %(remote_addr)s - UA: %(user_agent)s - Method: %(method)s - Path: %(path)s - Status: %(status)s - Referrer: %(referrer)s'
    )
    access_handler.setFormatter(access_formatter)

    # 3. IP 차단 로그 핸들러
    ip_handler = logging.FileHandler(IP_BLOCK_LOG_PATH, encoding='utf-8')
    ip_handler.setLevel(logging.WARNING)
    ip_handler.setFormatter(logging.Formatter(
            '[%(asctime)s] %(levelname)s: %(message)s'
    ))

    # 4. NamuBoard Extension 전용 로그 핸들러 (새로 추가)
    namuboard_handler = RotatingFileHandler(
        NAMUBOARD_LOG_PATH,
        maxBytes=5*1024*1024, # 5MB
        backupCount=3,
        encoding='utf-8'
    )
    namuboard_formatter = logging.Formatter(
        '%(asctime)s - IP: %(remote_addr)s - UA: %(user_agent)s - Referrer: %(referrer)s'
    )
    namuboard_handler.setFormatter(namuboard_formatter)

    # 로거들 설정
    logger = logging.getLogger(__name__)
    logger.addHandler(app_handler)
    logger.addHandler(ip_handler)

    # Flask 기본 로거에 핸들러 추가
    app.logger.addHandler(app_handler)
    app.logger.addHandler(ip_handler)

    # 접속 로그용 별도 로거 생성
    access_logger = logging.getLogger('access')
    access_logger.setLevel(logging.INFO)
    access_logger.addHandler(access_handler)

    # NamuBoard Extension 로그용 별도 로거 생성
    namuboard_logger = logging.getLogger('namuboard')
    namuboard_logger.setLevel(logging.INFO)
    namuboard_logger.addHandler(namuboard_handler)

    # 중복 로그 방지
    access_logger.propagate = False
    namuboard_logger.propagate = False # Prevent duplicate logging for namuboard

    return access_logger, namuboard_logger

# 접속 로거 초기화
access_logger, namuboard_logger = setup_logging()

# User-Agent 클리닝 함수
def clean_user_agent(user_agent_string):
    if not user_agent_string:
        return 'Unknown'
    # Remove common prefixes like "Mozilla/5.0", "AppleWebKit/" etc.
    cleaned_ua = re.sub(r'^(Mozilla/\d\.\d\s\(.*\)|AppleWebKit/\d+\.\d+\s\(.*\)|KHTML,\s*like\s*Gecko\s*|Chrome/\d+\.\d+\.\d+\.\d+\s*|Safari/\d+\.\d+\s*|Edge/\d+\.\d+\s*|Firefox/\d+\.\d+\s*)+', '', user_agent_string).strip()
    return cleaned_ua[:200] # Ensure it's still capped at 200 characters

# 접속 로그 기록 함수
def log_access_request(status_code=200):
    """접속 로그를 기록합니다."""
    # Only log GET and POST requests with status 200 or 206
    if request.method in ['GET', 'POST'] and status_code in [200, 206]:
        try:
            real_ip = get_client_ip()

            extra_info = {
                'remote_addr': real_ip or 'Unknown',
                'user_agent': clean_user_agent(request.headers.get('User-Agent', 'Unknown')),
                'method': request.method,
                'path': request.path,
                'status': status_code,
                'referrer': request.headers.get('Referer', 'N/A')[:100]
            }

            access_logger.info('Access log', extra=extra_info)

        except Exception as e:
            app.logger.error(f"접속 로그 기록 중 오류 발생: {e}")

# NamuBoard Extension 접속 로그 기록 함수
def log_namuboard_access_request():
    """/namuboardextension.user.js 접근 로그를 기록합니다."""
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


# --- NEIS API 및 기본 설정 ---
API_KEY = "4e2c538d90ef493c94c6e2d943e756d9" # 실제 운영 시에는 환경 변수 등으로 관리하는 것이 좋습니다.
KST = timezone(timedelta(hours=9))
regions = {
    "서울": "B10", "부산": "C10", "대구": "D10", "인천": "E10", "광주": "F10",
    "대전": "G10", "울산": "H10", "세종": "I10", "경기": "J10", "강원": "K10",
    "충북": "M10", "충남": "N10", "전북": "P10", "전남": "Q10", "경북": "R10",
    "경남": "S10", "제주": "T10"
}
school_cache = {}
meal_cache = {}

def expand_school_name(school_name):
    """학교명 축약어를 풀어서 반환합니다."""
    expansions = {
        '여고': '여자고등학교',
        '남고': '남자고등학교',
        '외고': '외국어고등학교',
        '과고': '과학고등학교',
        '예고': '예술고등학교',
        '체고': '체육고등학교',
        '공고': '공업고등학교',
        '상고': '상업고등학교',
        '농고': '농업고등학교',
        '마이스터고': '마이스터고등학교',
        '특성화고': '특성화고등학교',
        '여중': '여자중학교',
        '남중': '남자중학교',
        '초등': '초등학교',
        '초': '초등학교'
    }

    expanded_name = school_name
    for abbr, full in expansions.items():
        if expanded_name.endswith(abbr):
            expanded_name = expanded_name[:-len(abbr)] + full
            break

    return expanded_name

school_levels = {
    "초등학교": ["초등학교"],
    "중학교": ["중학교", "중등학교"],
    "고등학교": ["고등학교", "고등", "고교"],
    "특수학교": ["특수학교"],
    "각종학교": ["각종학교"]
}

def get_schools_by_region_and_level(region_code, school_level=None):
    """지역별, 학교급별 학교 목록을 NEIS API에서 가져옵니다. (최적화된 버전)"""
    cache_key = f"schools_{region_code}_{school_level or 'all'}"

    # 캐시 확인
    if hasattr(get_schools_by_region_and_level, 'cache'):
        if cache_key in get_schools_by_region_and_level.cache:
            return get_schools_by_region_and_level.cache[cache_key]
    else:
        get_schools_by_region_and_level.cache = {}

    # 전체 학교 목록이 캐시에 있으면 필터링만 수행
    all_schools_key = f"schools_{region_code}_all"
    if school_level and all_schools_key in get_schools_by_region_and_level.cache:
        all_schools = get_schools_by_region_and_level.cache[all_schools_key]
        filtered_schools = []
        level_keywords = school_levels.get(school_level, [])

        for school in all_schools:
            if any(keyword in school['name'] for keyword in level_keywords):
                filtered_schools.append(school)

        get_schools_by_region_and_level.cache[cache_key] = filtered_schools
        return filtered_schools

    url = "https://open.neis.go.kr/hub/schoolInfo"
    schools = []

    try:
        # 첫 번째 요청으로 전체 데이터 수 확인
        params = {
            "KEY": API_KEY,
            "Type": "json",
            "pIndex": 1,
            "pSize": 300,  # 더 큰 크기로 요청
            "ATPT_OFCDC_SC_CODE": region_code
        }

        response = requests.get(url, params=params, timeout=15)  # 타임아웃 증가
        response.raise_for_status()
        data = response.json()

        if "schoolInfo" not in data or len(data["schoolInfo"]) < 2:
            app.logger.warning(f"No schools found for region {region_code}")
            get_schools_by_region_and_level.cache[cache_key] = []
            return []

        # 첫 페이지 처리
        rows = data["schoolInfo"][1].get("row", [])
        for school_data in rows:
            try:
                school_name = school_data["SCHUL_NM"]
                school_code = school_data["SD_SCHUL_CODE"]

                schools.append({
                    'code': school_code,
                    'name': school_name,
                    'region_code': region_code
                })
            except KeyError:
                continue

        # 추가 페이지가 있는지 확인 (300개 이상인 경우에만)
        if len(rows) >= 300:
            page = 2
            while page <= 10:  # 최대 10페이지까지만 (3000개 학교)
                params["pIndex"] = page
                try:
                    response = requests.get(url, params=params, timeout=10)
                    response.raise_for_status()
                    data = response.json()

                    if "schoolInfo" not in data or len(data["schoolInfo"]) < 2:
                        break

                    rows = data["schoolInfo"][1].get("row", [])
                    if not rows:
                        break

                    for school_data in rows:
                        try:
                            school_name = school_data["SCHUL_NM"]
                            school_code = school_data["SD_SCHUL_CODE"]

                            schools.append({
                                'code': school_code,
                                'name': school_name,
                                'region_code': region_code
                            })
                        except KeyError:
                            continue

                    if len(rows) < 300:
                        break

                    page += 1
                except:
                    break

        # 학교명으로 정렬
        schools.sort(key=lambda x: x['name'])

        # 전체 목록 캐시 저장 (학교급 필터링 전)
        if not school_level:
            get_schools_by_region_and_level.cache[all_schools_key] = schools

        # 학교급 필터링
        if school_level:
            level_keywords = school_levels.get(school_level, [])
            filtered_schools = []
            for school in schools:
                if any(keyword in school['name'] for keyword in level_keywords):
                    filtered_schools.append(school)
            schools = filtered_schools

        # 결과 캐시 저장
        get_schools_by_region_and_level.cache[cache_key] = schools

        app.logger.info(f"Fetched {len(schools)} schools for {region_code}, level: {school_level}")
        return schools

    except Exception as e:
        app.logger.error(f"Error fetching schools for region {region_code}, level {school_level}: {e}")
        get_schools_by_region_and_level.cache[cache_key] = []
        return []

# --- 핵심 함수 ---
def get_school_code(school_name, region_code):
    """학교 이름과 지역 코드로 NEIS API에서 학교 코드와 전체 이름을 조회합니다."""
    # 축약어 확장 처리 추가
    expanded_name = expand_school_name(school_name)

    # 캐시 확인 (원래 이름과 확장된 이름 모두)
    cache_keys = [f"{region_code}_{school_name}", f"{region_code}_{expanded_name}"]
    for cache_key in cache_keys:
        if cache_key in school_cache:
            return school_cache[cache_key]

    # API 요청 시도 (원래 이름 먼저, 그 다음 확장된 이름)
    search_terms = [school_name]
    if expanded_name != school_name:
        search_terms.append(expanded_name)

    api_error = False
    for search_term in search_terms:
        url = "https://open.neis.go.kr/hub/schoolInfo"
        params = {
            "KEY": API_KEY, "Type": "json", "pIndex": 1, "pSize": 100,
            "ATPT_OFCDC_SC_CODE": region_code, "SCHUL_NM": search_term
        }
        try:
            response = requests.get(url, params=params, timeout=5)
            response.raise_for_status()
            data = response.json()

            if "schoolInfo" in data and data.get("schoolInfo")[1].get("row"):
                school_data = data["schoolInfo"][1]["row"][0]
                school_code_val = school_data["SD_SCHUL_CODE"]
                full_school_name = school_data["SCHUL_NM"]

                school_info_result = {
                    'code': school_code_val,
                    'name': full_school_name,
                    'region_code': region_code
                }

                # 모든 검색어로 캐시 저장
                for term in [school_name, expanded_name, full_school_name]:
                    school_cache[f"{region_code}_{term}"] = school_info_result
                school_cache[school_code_val] = school_info_result

                return school_info_result
        except requests.exceptions.Timeout:
            app.logger.error(f"Error fetching school code (Timeout) for {search_term}: API timeout")
            api_error = True
        except requests.exceptions.RequestException as e:
            app.logger.error(f"Error fetching school code (Request) for {search_term}: {e}")
            api_error = True
        except Exception as e:
            app.logger.error(f"Error fetching school code (General) for {search_term}: {e}")

    # API 오류가 발생한 경우 특별한 반환값
    if api_error:
        return "API_ERROR"

    return None

def find_school_by_code(school_code):
    """학교 코드로 학교 정보를 찾습니다. (캐시 우선, 없으면 모든 지역 API 탐색)"""
    if school_code in school_cache:
        return school_cache[school_code]

    url = "https://open.neis.go.kr/hub/schoolInfo"
    for region_name, region_code in regions.items():
        params = {
            "KEY": API_KEY, "Type": "json", "pIndex": 1, "pSize": 1,
            "ATPT_OFCDC_SC_CODE": region_code, "SD_SCHUL_CODE": school_code
        }
        try:
            response = requests.get(url, params=params, timeout=1) # 타임아웃을 짧게 설정
            response.raise_for_status()
            data = response.json()
            if "schoolInfo" in data and data.get("schoolInfo")[1].get("row"):
                school_data = data["schoolInfo"][1]["row"][0]
                school_info = {
                    'code': school_data["SD_SCHUL_CODE"],
                    'name': school_data["SCHUL_NM"],
                    'region_code': school_data["ATPT_OFCDC_SC_CODE"]
                }
                school_cache[school_code] = school_info # 찾았으면 캐시에 저장
                return school_info
        except requests.exceptions.RequestException:
             # 타임아웃 등 일반적인 오류는 다음 지역으로 계속 진행
            continue
        except Exception as e:
            app.logger.error(f"Error finding school by code {school_code} in region {region_code}: {e}")
    return None


def get_month_dates():
    """현재 KST 기준 월의 모든 날짜를 YYYYMMDD 형식으로 반환합니다."""
    today = datetime.now(KST).date()
    _, last_day = calendar.monthrange(today.year, today.month)
    return [(date(today.year, today.month, day)).strftime('%Y%m%d') for day in range(1, last_day + 1)]

def get_week_dates():
    """현재 KST 기준 주의 모든 날짜(일~토)를 YYYYMMDD 형식으로 반환합니다."""
    today = datetime.now(KST).date()
    start_of_week = today - timedelta(days=(today.weekday() + 1) % 7)
    return [(start_of_week + timedelta(days=i)).strftime('%Y%m%d') for i in range(7)]

def get_month_meals(school_code, region_code):
    """NEIS API에서 해당 월의 급식 정보를 가져옵니다."""
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
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error fetching meals (Request) for {school_code}: {e}")
    except Exception as e:
        app.logger.error(f"Error fetching meals (General) for {school_code}: {e}")
    return dict(meals) # 오류 발생 시에도 빈 dict 반환


# --- 템플릿 필터 및 컨텍스트 프로세서 ---
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

# --- 스팸 요청 처리용 조용한 라우트들 ---
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
def silent_spam_block(filename=None):
    """스팸 요청들을 조용히 차단 (로그 없이)"""
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

    # POST 요청 (학교 검색) 처리
    if request.method == 'POST':
        region_name = request.form['region']
        school_name_input = request.form['school_name']
        app.logger.info(f"Search request - Region: {region_name}, School: {school_name_input}")

        if not region_name or not school_name_input:
            return render_template('school_meal.html', error_message="지역과 학교명을 모두 입력해주세요.", regions=regions)

        region_code = regions.get(region_name)
        if not region_code:
            return render_template('school_meal.html', error_message="유효하지 않은 지역입니다.", regions=regions)

        school_info = get_school_code(school_name_input, region_code)

        # API 오류 처리
        if school_info == "API_ERROR":
            return render_template('school_meal.html',
                                 error_message="NEIS API에 오류가 발생했습니다. 잠시 후 다시 시도해주세요.",
                                 regions=regions,
                                 region=region_name,
                                 school_name=school_name_input)
        elif school_info:
            response = make_response(redirect(url_for('school_meal_view', school_code=school_info['code'])))
            # 쿠키 설정 시 quote 사용
            response.set_cookie('school_code', school_info['code'], max_age=60*60*24*30)
            response.set_cookie('school_name', quote(school_info['name']), max_age=60*60*24*30)
            response.set_cookie('region_code', school_info['region_code'], max_age=60*60*24*30)
            response.set_cookie('region_name', region_name, max_age=60*60*24*30)
            return response
        else:
            return render_template('school_meal.html', error_message="학교를 찾을 수 없습니다.", regions=regions, region=region_name, school_name=school_name_input)

    # GET 요청 처리
    # 1. 쿠키에 학교 정보가 있고 error_message가 없으면 해당 학교 페이지로 리다이렉트
    if school_code_cookie and not error_message:
        app.logger.info(f"Redirecting to school meal page for school_code: {school_code_cookie}")
        return redirect(url_for('school_meal_view', school_code=school_code_cookie))

    # 2. error_message가 있거나 쿠키가 없으면 검색 페이지 표시
    # error_message가 있는 경우에만 기존 쿠키 값들을 폼에 미리 채워넣음
    if error_message:
        return render_template('school_meal.html',
                             regions=regions,
                             error_message=error_message,
                             region=region_cookie,
                             school_name=school_name_cookie)
    else:
        # 일반적인 첫 방문 또는 쿠키가 없는 경우 - 깨끗한 검색 페이지
        return render_template('school_meal.html', regions=regions)

@app.route("/meal/<school_code>")
def school_meal_view(school_code):
    # school_code를 기반으로 학교 정보를 조회 (캐시 또는 API)
    school_info = find_school_by_code(school_code)

    # 학교 정보를 찾지 못한 경우
    if not school_info:
        app.logger.warning(f"Failed to find school info for code: {school_code}")
        return redirect(url_for('index', error_message="존재하지 않거나 유효하지 않은 학교 정보입니다. 다시 검색해주세요."))

    # 급식 정보 가져오기
    month_meals_data = get_month_meals(school_code, school_info['region_code'])

    # 오늘 급식 데이터 추가
    today_str = datetime.now(KST).strftime('%Y%m%d')
    today_meal = month_meals_data.get(today_str, {
        "breakfast": "급식 정보 없음",
        "lunch": "급식 정보 없음",
        "dinner": "급식 정보 없음"
    })

    # 주간/월간 급식 데이터 가공
    week_dates_list = get_week_dates()
    week_meals_data = {date_str: month_meals_data.get(date_str, {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"}) for date_str in week_dates_list}
    month_dates_list = get_month_dates()
    full_month_meals_data = {date_str: month_meals_data.get(date_str, {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"}) for date_str in month_dates_list}

    # 해당 지역의 이름 찾기
    region_name = next((name for name, code in regions.items() if code == school_info['region_code']), None)

    # 템플릿 렌더링
    resp = make_response(render_template(
        'school_meal.html',
        regions=regions,
        school_name=school_info['name'],
        school_code=school_info['code'],
        today_meal=today_meal,  # 오늘 급식 데이터 추가
        today_date=today_str,   # 오늘 날짜 추가
        week_meals=week_meals_data,
        month_meals=full_month_meals_data,
        loading=False,
        region=region_name
    ))

    # 방문 기록을 쿠키에 저장 (사용자 편의성)
    resp.set_cookie('school_code', school_info['code'], max_age=60*60*24*30)
    resp.set_cookie('school_name', quote(school_info['name']), max_age=60*60*24*30)
    resp.set_cookie('region_code', school_info['region_code'], max_age=60*60*24*30)
    if region_name:
        resp.set_cookie('region_name', region_name, max_age=60*60*24*30)

    return resp

@app.route('/api/meals/<school_code>/<date>')
def get_school_meal(school_code, date):
    """API: 특정 학교, 특정 날짜의 급식 정보를 반환합니다."""
    # API 요청 시에는 school_code로 학교 정보를 찾아 region_code를 획득
    school_info = find_school_by_code(school_code)
    if not school_info:
        return jsonify({"error": "School not found"}), 404

    region_code = school_info['region_code']

    try:
        month_meals = get_month_meals(school_code, region_code)
        meal_data = month_meals.get(date, {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"})
        return jsonify(meal_data)
    except Exception as e:
        app.logger.error(f"Error in get_school_meal API: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/schools/search')
def search_schools_autocomplete():
    """학교 검색 자동완성 API"""
    query = request.args.get('q', '').strip()
    region_name = request.args.get('region', '').strip()

    if not query or len(query) < 2:
        return jsonify([])

    if not region_name or region_name not in regions:
        return jsonify([])

    region_code = regions[region_name]

    # 원래 검색어와 축약어 확장 버전 모두 시도
    search_terms = [query]
    expanded_query = expand_school_name(query)
    if expanded_query != query:
        search_terms.append(expanded_query)

    schools = []
    api_error = False

    for search_term in search_terms:
        url = "https://open.neis.go.kr/hub/schoolInfo"
        params = {
            "KEY": API_KEY,
            "Type": "json",
            "pIndex": 1,
            "pSize": 10,  # 최대 10개까지
            "ATPT_OFCDC_SC_CODE": region_code,
            "SCHUL_NM": search_term
        }

        try:
            response = requests.get(url, params=params, timeout=3)
            response.raise_for_status()
            data = response.json()

            if "schoolInfo" in data and data.get("schoolInfo")[1].get("row"):
                for school_data in data["schoolInfo"][1]["row"]:
                    school_info = {
                        'code': school_data["SD_SCHUL_CODE"],
                        'name': school_data["SCHUL_NM"],
                        'region_code': school_data["ATPT_OFCDC_SC_CODE"]
                    }

                    # 중복 제거
                    if not any(s['code'] == school_info['code'] for s in schools):
                        schools.append(school_info)

                        # 캐시에도 저장
                        cache_key = f"{region_code}_{school_data['SCHUL_NM']}"
                        school_cache[cache_key] = school_info
                        school_cache[school_data["SD_SCHUL_CODE"]] = school_info

            if len(schools) >= 10:  # 충분한 결과가 있으면 중단
                break

        except requests.exceptions.Timeout:
            app.logger.error(f"Error in autocomplete search for '{search_term}': API timeout")
            api_error = True
            continue
        except Exception as e:
            app.logger.error(f"Error in autocomplete search for '{search_term}': {e}")
            api_error = True
            continue

    # API 오류가 발생하고 결과가 없는 경우 오류 응답
    if api_error and len(schools) == 0:
        return jsonify({"error": "NEIS API에 오류가 발생했습니다. 잠시 후 다시 시도해주세요."}), 500

    return jsonify(schools[:10])  # 최대 10개 반환

@app.route('/api/meals/today/<school_code>')
def get_today_meal(school_code):
    """오늘의 급식 정보를 반환합니다."""
    school_info = find_school_by_code(school_code)
    if not school_info:
        return jsonify({"error": "School not found"}), 404

    try:
        today_str = datetime.now(KST).strftime('%Y%m%d')
        month_meals = get_month_meals(school_code, school_info['region_code'])
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

@app.route('/current_time')
def current_time():
    """KST 기준 현재 시간을 반환합니다."""
    return jsonify({'current_time': datetime.now(KST).isoformat()})

@app.route('/schools/<region_name>')
def schools_by_region(region_name):
    """지역별 학교 목록 페이지"""
    # URL 디코딩 처리
    try:
        from urllib.parse import unquote
        region_name = unquote(region_name)
    except:
        pass

    if region_name not in regions:
        return redirect(url_for('index', error_message="유효하지 않은 지역입니다."))

    region_code = regions[region_name]

    # 학교급별로 학교 목록 가져오기 (비동기적으로 처리)
    schools_by_level = {}

    # 전체 학교 목록을 먼저 가져오기
    all_schools = get_schools_by_region_and_level(region_code)

    # 메모리에서 필터링 (빠름)
    for level, keywords in school_levels.items():
        level_schools = []
        for school in all_schools:
            if any(keyword in school['name'] for keyword in keywords):
                level_schools.append(school)
        if level_schools:
            schools_by_level[level] = level_schools

    # 접속 로그 기록
    log_access_request(200)

    return render_template('schools_by_region.html',
                         region_name=region_name,
                         schools_by_level=schools_by_level,
                         regions=regions)

@app.route('/schools/<region_name>/<school_level>')
def schools_by_region_and_level(region_name, school_level):
    """지역별, 학교급별 학교 목록 페이지"""
    # URL 디코딩 처리
    try:
        from urllib.parse import unquote
        region_name = unquote(region_name)
        school_level = unquote(school_level)
    except:
        pass

    if region_name not in regions:
        return redirect(url_for('index', error_message="유효하지 않은 지역입니다."))

    if school_level not in school_levels:
        return redirect(url_for('schools_by_region', region_name=region_name))

    region_code = regions[region_name]

    # 캐시된 전체 목록에서 필터링 (매우 빠름)
    all_schools = get_schools_by_region_and_level(region_code)
    schools = []
    keywords = school_levels.get(school_level, [])

    for school in all_schools:
        if any(keyword in school['name'] for keyword in keywords):
            schools.append(school)

    # 접속 로그 기록
    log_access_request(200)

    return render_template('schools_by_level.html',
                         region_name=region_name,
                         school_level=school_level,
                         schools=schools,
                         regions=regions)

# 3. 백그라운드에서 캐시 미리 로드하는 함수 추가
def preload_school_cache():
    """백그라운드에서 주요 지역의 학교 목록을 미리 캐시"""
    import threading

    def load_region(region_name, region_code):
        try:
            app.logger.info(f"Preloading schools for {region_name}")
            get_schools_by_region_and_level(region_code)
            app.logger.info(f"Completed preloading for {region_name}")
        except Exception as e:
            app.logger.error(f"Failed to preload {region_name}: {e}")

    # 주요 지역부터 우선 로드
    priority_regions = ["서울", "부산", "경기", "부산", "대구", "인천", "광주", "대전", "광주", "울산", "세종", "강원", "충북", "충남", "전북", "전남", "경북", "경남", "제주"]

    for region_name in priority_regions:
        if region_name in regions:
            region_code = regions[region_name]
            thread = threading.Thread(target=load_region, args=(region_name, region_code))
            thread.daemon = True
            thread.start()


# --- 정적 파일 및 기타 라우트 ---
@app.route('/robots.txt')
def robots_txt():
    return send_from_directory(app.static_folder, 'robots.txt')

@app.route('/favicon.svg')
def favicon():
    return send_from_directory(app.static_folder, 'favicon.svg')

@app.route('/favicon.ico')
def faviconico():
    return send_from_directory(app.static_folder, 'favicon.svg') # svg로 통일 또는 ico 파일 준비

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

# --- 탬퍼몽키 스크립트 ---
STATIC_DIR = app.root_path

@app.route('/namuboardextension.user.js')
def serve_tampermonkey_script():
    log_namuboard_access_request() # Log this specific access
    try:
        return send_from_directory(STATIC_DIR, 'namuboardextension.user.js', mimetype='application/javascript')
    except FileNotFoundError:
        return "파일 오류.", 404
    except Exception as e:
        app.logger.error(f"Error serving script: {e}")
        return "서버 오류.", 500

# --- 로그 확인용 엔드포인트 (개발/디버깅용) ---
@app.route('/logs/access')
def view_access_logs():
    """접속 로그 확인 (관리자 IP만 허용)"""
    client_ip = get_client_ip()

    # 관리자 IP 확인 또는 개발 모드 + 환경 변수 확인
    if not (is_admin_ip(client_ip) or (app.debug and os.environ.get('ENABLE_LOG_VIEW') == 'true')):
        app.logger.warning(f"Unauthorized access attempt to logs from IP: {client_ip}")
        return "접근 권한이 없습니다.", 403

    try:
        if os.path.exists(ACCESS_LOG_PATH):
            with open(ACCESS_LOG_PATH, 'r', encoding='utf-8') as f:
                lines = f.readlines() # 모든 줄 표시
            return f'<h2>접속 로그</h2><pre>{"".join(lines)}</pre>'
        else:
            return '접속 로그 파일이 아직 생성되지 않았습니다.'
    except Exception as e:
        return f'접속 로그 파일 읽기 오류: {e}'

@app.route('/logs/app')
def view_app_logs():
    """앱 로그 확인 (관리자 IP만 허용)"""
    client_ip = get_client_ip()

    # 관리자 IP 확인 또는 개발 모드 + 환경 변수 확인
    if not (is_admin_ip(client_ip) or (app.debug and os.environ.get('ENABLE_LOG_VIEW') == 'true')):
        app.logger.warning(f"Unauthorized access attempt to logs from IP: {client_ip}")
        return "접근 권한이 없습니다.", 403

    try:
        if os.path.exists(APP_LOG_PATH):
            with open(APP_LOG_PATH, 'r', encoding='utf-8') as f:
                lines = f.readlines() # 모든 줄 표시
            return f'<h2>앱 로그</h2><pre>{"".join(lines)}</pre>'
        else:
            return '앱 로그 파일이 아직 생성되지 않았습니다.'
    except Exception as e:
        return f'앱 로그 파일 읽기 오류: {e}'

@app.route('/logs/namuboard')
def view_namuboard_logs():
    """NamuBoard Extension 로그 확인 (관리자 IP만 허용)"""
    client_ip = get_client_ip()

    # 관리자 IP 확인 또는 개발 모드 + 환경 변수 확인
    if not (is_admin_ip(client_ip) or (app.debug and os.environ.get('ENABLE_LOG_VIEW') == 'true')):
        app.logger.warning(f"Unauthorized access attempt to namuboard logs from IP: {client_ip}")
        return "접근 권한이 없습니다.", 403

    try:
        if os.path.exists(NAMUBOARD_LOG_PATH):
            with open(NAMUBOARD_LOG_PATH, 'r', encoding='utf-8') as f:
                lines = f.readlines() # 모든 줄 표시
            return f'<h2>NamuBoard Extension 로그</h2><pre>{"".join(lines)}</pre>'
        else:
            return 'NamuBoard Extension 로그 파일이 아직 생성되지 않았습니다.'
    except Exception as e:
        return f'NamuBoard Extension 로그 파일 읽기 오류: {e}'

@app.route('/stats')
def view_stats():
    """접속 통계 (관리자 IP만 허용)"""
    client_ip = get_client_ip()

    # 관리자 IP 확인 또는 개발 모드 + 환경 변수 확인
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
            'user_agents': {}
        }

        with open(ACCESS_LOG_PATH, 'r', encoding='utf-8') as f:
            for line in f:
                if 'IP:' in line:
                    stats['total_requests'] += 1

                    # IP 추출
                    try:
                        ip_start = line.find('IP: ') + 4
                        ip_end = line.find(' -', ip_start)
                        if ip_end > ip_start:
                            ip = line[ip_start:ip_end]
                            stats['unique_ips'].add(ip)
                    except:
                        pass

                    # 상태 코드 추출
                    try:
                        status_start = line.find('Status: ') + 8
                        status_end = line.find(' -', status_start)
                        if status_end == -1:
                            status_end = len(line)
                        status = line[status_start:status_end].strip()
                        stats['status_codes'][status] = stats['status_codes'].get(status, 0) + 1
                    except:
                        pass

                    # 경로 추출
                    try:
                        path_start = line.find('Path: ') + 6
                        path_end = line.find(' -', path_start)
                        if path_end > path_start:
                            path = line[path_start:path_end]
                            stats['popular_paths'][path] = stats['popular_paths'].get(path, 0) + 1
                    except:
                        pass

        stats['unique_ips'] = len(stats['unique_ips'])

        return f'''
        <h2>접속 통계</h2>
        <p>총 요청 수: {stats['total_requests']}</p>
        <p>고유 IP 수: {stats['unique_ips']}</p>

        <h3>상태 코드별 통계:</h3>
        <ul>{"".join([f"<li>{k}: {v}회</li>" for k, v in stats['status_codes'].items()])}</ul>

        <h3>인기 경로 (Top 10):</h3>
        <ul>{"".join([f"<li>{k}: {v}회</li>" for k, v in sorted(stats['popular_paths'].items(), key=lambda x: x[1], reverse=True)[:10]])}</ul>
        '''

    except Exception as e:
        return f'통계 생성 오류: {e}'

@app.route('/security/status')
def security_status():
    """보안 상태 확인 (관리자만)"""
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

# 블랙리스트 관리 엔드포인트
@app.route('/security/blacklist/add', methods=['POST'])
def add_to_blacklist():
    """블랙리스트에 IP/CIDR 추가 (관리자만)"""
    client_ip = get_client_ip()
    if not is_admin_ip(client_ip):
        abort(403)

    data = request.get_json()
    ip_or_cidr = data.get('ip_or_cidr')
    reason = data.get('reason', 'Manual addition')

    if not ip_or_cidr:
        return jsonify({'error': 'IP or CIDR required'}), 400

    try:
        # 형식 검증
        ipaddress.ip_network(ip_or_cidr, strict=False)
        save_to_blacklist(ip_or_cidr, reason)

        # 메모리 목록도 업데이트
        global BLOCKED_NETWORKS
        BLOCKED_NETWORKS = load_ip_blacklist()

        return jsonify({'success': True, 'message': f'Added {ip_or_cidr} to blacklist'})
    except ValueError as e:
        return jsonify({'error': f'Invalid IP/CIDR format: {e}'}), 400

# --- 응답 로깅 (개선된 버전) ---
@app.after_request
def after_request_func(response):
    # Silent block 표시가 있으면 로그 안 남김
    if response.headers.get('X-Silent-Block'):
        return response

    client_ip = get_client_ip()
    request_path = request.path
    request_method = request.method
    status_code = response.status_code

    # 로그를 남길지 판단
    if should_log_request(request_path, request_method):
        # 기존 앱 로그
        log_entry = (
            f"IP: {client_ip}, "
            f"Method: {request_method}, "
            f"URL: {request.url}, "
            f"Status: {status_code}"
        )
        app.logger.info(log_entry)

        # 접속 로그 (200/206 상태 코드만)
        if status_code in [200, 206]:
            log_access_request(status_code)

    return response

# --- 앱 실행 ---
if __name__ == "__main__":
    # 로그 파일 경로 정보 출력
    app.logger.info(f"접속 로그 파일 경로: {ACCESS_LOG_PATH}")
    app.logger.info(f"앱 로그 파일 경로: {APP_LOG_PATH}")
    app.logger.info(f"IP 차단 로그 파일 경로: {IP_BLOCK_LOG_PATH}")
    app.logger.info(f"NamuBoard Extension 로그 파일 경로: {NAMUBOARD_LOG_PATH}")
    app.logger.info(f"관리자 화이트리스트: {ADMIN_WHITELIST}")

    # 블랙리스트 파일 생성 (없는 경우)
    if not os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, 'w', encoding='utf-8') as f:
            f.write("# IP Blacklist - CIDR format\n")
            f.write("# Example: 192.168.1.0/24\n")
            f.write("# 52.178.178.217/32  # Example blocked IP\n")

    app.logger.info(f"Security blacklist loaded: {len(BLOCKED_NETWORKS)} networks")
    app.logger.info(f"Security config: {SECURITY_CONFIG}")
    app.logger.info(f"Silent block patterns: {len(SILENT_BLOCK_PATTERNS)} patterns loaded")
    app.logger.info(f"No-log paths: {len(NO_LOG_PATHS)} paths configured")

    import threading
    preload_thread = threading.Thread(target=preload_school_cache)
    preload_thread.daemon = True
    preload_thread.start()

    app.logger.info("Starting school cache preload in background...")

    app.run(debug=False)
