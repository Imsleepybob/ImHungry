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

# 학교명 축약어 처리 함수
def expand_school_abbreviations(school_name):
    """학교명 축약어를 전체 이름으로 확장합니다."""
    school_name = school_name.strip()
    
    # 축약어 변환 규칙
    abbreviations = {
        '여고': '여자고등학교',
        '남고': '남자고등학교',
        '공고': '공업고등학교',
        '상고': '상업고등학교',
        '농고': '농업고등학교',
        '예고': '예술고등학교',
        '체고': '체육고등학교',
        '외고': '외국어고등학교',
        '과고': '과학고등학교',
        '국제고': '국제고등학교',
        '자사고': '자율사립고등학교',
        '특목고': '특수목적고등학교',
        '특성화고': '특성화고등학교',
        '마이스터고': '마이스터고등학교',
        '중': '중학교',
        '고': '고등학교',
        '초': '초등학교'
    }
    
    # 축약어를 전체 이름으로 변환
    for abbr, full in abbreviations.items():
        if school_name.endswith(abbr) and not school_name.endswith(full):
            # 중복 변환 방지 (이미 전체 이름인 경우)
            return school_name[:-len(abbr)] + full
    
    return school_name

# --- 핵심 함수 ---
def get_school_code(school_name, region_code):
    """학교 이름과 지역 코드로 NEIS API에서 학교 코드와 전체 이름을 조회합니다."""
    # 축약어 확장 처리
    expanded_name = expand_school_abbreviations(school_name)
    
    cache_key = f"{region_code}_{school_name}"
    expanded_cache_key = f"{region_code}_{expanded_name}"
    
    # 원래 이름과 확장된 이름 모두 캐시 확인
    if cache_key in school_cache:
        return school_cache[cache_key]
    if expanded_cache_key in school_cache:
        return school_cache[expanded_cache_key]

    url = "https://open.neis.go.kr/hub/schoolInfo"
    
    # 원래 이름으로 먼저 시도
    for search_name in [school_name, expanded_name]:
        params = {
            "KEY": API_KEY, "Type": "json", "pIndex": 1, "pSize": 100,
            "ATPT_OFCDC_SC_CODE": region_code, "SCHUL_NM": search_name
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
                # 다양한 키로 캐시 저장
                school_cache[cache_key] = school_info_result
                school_cache[expanded_cache_key] = school_info_result
                school_cache[f"{region_code}_{full_school_name}"] = school_info_result
                school_cache[school_code_val] = school_info_result # 학교 코드로도 캐시
                return school_info_result
        except requests.exceptions.RequestException as e:
            app.logger.error(f"Error fetching school code (Request) for {search_name}: {e}")
        except Exception as e:
            app.logger.error(f"Error fetching school code (General) for {search_name}: {e}")
    
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

def search_schools(query, region_code):
    """학교 검색 자동완성을 위한 함수"""
    if not query or len(query) < 1:
        return []
    
    # 축약어 확장
    expanded_query = expand_school_abbreviations(query)
    
    url = "https://open.neis.go.kr/hub/schoolInfo"
    results = []
    
    # 원본 쿼리와 확장된 쿼리 모두로 검색
    for search_query in [query, expanded_query]:
        if search_query in [q for q, _ in [(query, None), (expanded_query, None)]]:  # 중복 방지
            params = {
                "KEY": API_KEY, "Type": "json", "pIndex": 1, "pSize": 20,
                "ATPT_OFCDC_SC_CODE": region_code, "SCHUL_NM": search_query
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
                        if not any(s['code'] == school_info['code'] for s in results):
                            results.append(school_info)
                            # 캐시에도 저장
                            school_cache[school_info['code']] = school_info
                            school_cache[f"{region_code}_{school_info['name']}"] = school_info
                            
            except requests.exceptions.RequestException as e:
                app.logger.error(f"Error searching schools for {search_query}: {e}")
            except Exception as e:
                app.logger.error(f"Error in school search for {search_query}: {e}")
    
    # 결과를 이름 순으로 정렬
    results.sort(key=lambda x: x['name'])
    return results[:10]  # 최대 10개 결과만 반환
