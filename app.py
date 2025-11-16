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
BLACKLIST_FILE = os.path.join(os.getcwd(), 'ip_blacklist.txt')
SUSPICIOUS_PATTERNS_FILE = os.path.join(os.getcwd(), 'suspicious_patterns.json')

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
    '/favicon', '/robots.txt', '/manifest.json', '/sitemap.xml'
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

setup_security_logging()

ACCESS_LOG_PATH = os.path.join(os.getcwd(), 'access.log')
APP_LOG_PATH = os.path.join(os.getcwd(), 'app.log')
IP_BLOCK_LOG_PATH = os.path.join(os.getcwd(), 'ip_block.log')
NAMUBOARD_LOG_PATH = os.path.join(os.getcwd(), 'namuboard.log')

class AccessLogFormatter(logging.Formatter):
    def format(self, record):
        record.remote_addr = getattr(record, 'remote_addr', 'N/A')
        record.user_agent = getattr(record, 'user_agent', 'N/A')
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
        '%(asctime)s - IP: %(remote_addr)s - UA: %(user_agent)s - Method: %(method)s - Path: %(path)s - Status: %(status)s - Referrer: %(referrer)s'
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

def clean_user_agent(user_agent_string):
    if not user_agent_string:
        return 'Unknown'
    cleaned_ua = re.sub(r'^(Mozilla/\d\.\d\s\(.*\)|AppleWebKit/\d+\.\d+\s\(.*\)|KHTML,\s*like\s*Gecko\s*|Chrome/\d+\.\d+\.\d+\.\d+\s*|Safari/\d+\.\d+\s*|Edge/\d+\.\d+\s*|Firefox/\d+\.\d+\s*)+', '', user_agent_string).strip()
    return cleaned_ua[:200]

def log_access_request(status_code=200):
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


API_KEY = "4e2c538d90ef493c94c6e2d943e756d9"
KST = timezone(timedelta(hours=9))
regions = {
    "서울": "B10", "부산": "C10", "대구": "D10", "인천": "E10", "광주": "F10",
    "대전": "G10", "울산": "H10", "세종": "I10", "경기": "J10", "강원": "K10",
    "충북": "M10", "충남": "N10", "전북": "P10", "전남": "Q10", "경북": "R10",
    "경남": "S10", "제주": "T10"
}

from threading import Lock
import pickle

school_cache = {}
meal_cache = {}
autocomplete_cache = {}
autocomplete_cache_lock = Lock()

CACHE_DIR = os.path.join(os.getcwd(), 'cache')
if not os.path.exists(CACHE_DIR):
    os.makedirs(CACHE_DIR)

def save_cache_to_file(cache_name, data):
    try:
        cache_file = os.path.join(CACHE_DIR, f"{cache_name}.cache")
        with open(cache_file, 'wb') as f:
            pickle.dump(data, f)
    except Exception as e:
        app.logger.error(f"Failed to save cache {cache_name}: {e}")

def load_cache_from_file(cache_name):
    try:
        cache_file = os.path.join(CACHE_DIR, f"{cache_name}.cache")
        if os.path.exists(cache_file):
            file_age = time.time() - os.path.getmtime(cache_file)
            if file_age < 86400:
                with open(cache_file, 'rb') as f:
                    return pickle.load(f)
    except Exception as e:
        app.logger.error(f"Failed to load cache {cache_name}: {e}")
    return None

def expand_school_name(school_name):
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
    cache_key = f"schools_{region_code}_{school_level or 'all'}"
    if hasattr(get_schools_by_region_and_level, 'cache'):
        if cache_key in get_schools_by_region_and_level.cache:
            return get_schools_by_region_and_level.cache[cache_key]
    else:
        get_schools_by_region_and_level.cache = {}
    cached_data = load_cache_from_file(cache_key)
    if cached_data:
        get_schools_by_region_and_level.cache[cache_key] = cached_data
        return cached_data
    all_schools_key = f"schools_{region_code}_all"
    if school_level and all_schools_key in get_schools_by_region_and_level.cache:
        all_schools = get_schools_by_region_and_level.cache[all_schools_key]
        filtered_schools = []
        level_keywords = school_levels.get(school_level, [])
        for school in all_schools:
            if any(keyword in school['name'] for keyword in level_keywords):
                filtered_schools.append(school)
        get_schools_by_region_and_level.cache[cache_key] = filtered_schools
        save_cache_to_file(cache_key, filtered_schools)
        return filtered_schools
    url = "https://open.neis.go.kr/hub/schoolInfo"
    schools = []
    try:
        params = {
            "KEY": API_KEY,
            "Type": "json",
            "pIndex": 1,
            "pSize": 300,
            "ATPT_OFCDC_SC_CODE": region_code
        }
        response = requests.get(url, params=params, timeout=8)
        response.raise_for_status()
        data = response.json()
        if "schoolInfo" not in data or len(data["schoolInfo"]) < 2:
            app.logger.warning(f"No schools found for region {region_code}")
            get_schools_by_region_and_level.cache[cache_key] = []
            return []
        rows = data["schoolInfo"][1].get("row", [])
        for school_data in rows:
            try:
                school_name = school_data["SCHUL_NM"]
                school_code = school_data["SD_SCHUL_CODE"]
                address = school_data.get("ORG_RDNMA", "")
                district = extract_district_from_address(address)
                schools.append({
                    'code': school_code,
                    'name': school_name,
                    'region_code': region_code,
                    'address': address,
                    'district': district
                })
            except KeyError:
                continue
        if len(rows) >= 300:
            page = 2
            while page <= 10:
                params["pIndex"] = page
                try:
                    response = requests.get(url, params=params, timeout=5)
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
                            address = school_data.get("ORG_RDNMA", "")
                            district = extract_district_from_address(address)
                            schools.append({
                                'code': school_code,
                                'name': school_name,
                                'region_code': region_code,
                                'address': address,
                                'district': district
                            })
                        except KeyError:
                            continue
                    if len(rows) < 300:
                        break
                    page += 1
                except:
                    break
        schools.sort(key=lambda x: x['name'])
        if not school_level:
            get_schools_by_region_and_level.cache[all_schools_key] = schools
            save_cache_to_file(all_schools_key, schools)
        if school_level:
            level_keywords = school_levels.get(school_level, [])
            filtered_schools = []
            for school in schools:
                if any(keyword in school['name'] for keyword in level_keywords):
                    filtered_schools.append(school)
            schools = filtered_schools
        get_schools_by_region_and_level.cache[cache_key] = schools
        save_cache_to_file(cache_key, schools)
        app.logger.info(f"Fetched {len(schools)} schools for {region_code}, level: {school_level}")
        return schools
    except Exception as e:
        app.logger.error(f"Error fetching schools for region {region_code}, level {school_level}: {e}")
        get_schools_by_region_and_level.cache[cache_key] = []
        return []

# 수정: region_code를 파라미터로 받아 불필요한 API 호출 제거
def get_school_code(school_name, region_code):
    expanded_name = expand_school_name(school_name)
    cache_keys = [f"{region_code}_{school_name}", f"{region_code}_{expanded_name}"]
    for cache_key in cache_keys:
        if cache_key in school_cache:
            return school_cache[cache_key]
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
            response = requests.get(url, params=params, timeout=3)
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
    if api_error:
        return "API_ERROR"
    return None

# 수정: timeout 처리 개선 및 폴백 메커니즘 강화
def find_school_by_code(school_code, region_code=None):
    """
    수정: timeout 발생 시에도 폴백 작동하도록 개선
    """
    if school_code in school_cache:
        cached_info = school_cache[school_code]
        if 'address' in cached_info and 'district' in cached_info:
            return cached_info
    
    # region_code가 있으면 해당 지역에서만 조회 (최적화)
    if region_code:
        url = "https://open.neis.go.kr/hub/schoolInfo"
        params = {
            "KEY": API_KEY, "Type": "json", "pIndex": 1, "pSize": 1,
            "ATPT_OFCDC_SC_CODE": region_code, "SD_SCHUL_CODE": school_code
        }
        try:
            response = requests.get(url, params=params, timeout=5)
            response.raise_for_status()
            data = response.json()
            if "schoolInfo" in data and data.get("schoolInfo")[1].get("row"):
                school_data = data["schoolInfo"][1]["row"][0]
                address = school_data.get("ORG_RDNMA", "")
                district = extract_district_from_address(address)
                school_info = {
                    'code': school_data["SD_SCHUL_CODE"],
                    'name': school_data["SCHUL_NM"],
                    'region_code': school_data["ATPT_OFCDC_SC_CODE"],
                    'address': address,
                    'district': district
                }
                school_cache[school_code] = school_info
                return school_info
        except requests.exceptions.Timeout:
            app.logger.warning(f"Timeout finding school {school_code} in region {region_code}, trying fallback")
        except Exception as e:
            app.logger.warning(f"Error finding school {school_code} in region {region_code}: {e}, trying fallback")
    
    # region_code가 없거나 위에서 실패한 경우 폴백: 모든 지역 순회
    app.logger.info(f"Fallback: Searching school {school_code} across all regions")
    url = "https://open.neis.go.kr/hub/schoolInfo"
    for region_name, region_code_iter in regions.items():
        params = {
            "KEY": API_KEY, "Type": "json", "pIndex": 1, "pSize": 1,
            "ATPT_OFCDC_SC_CODE": region_code_iter, "SD_SCHUL_CODE": school_code
        }
        try:
            response = requests.get(url, params=params, timeout=5)
            response.raise_for_status()
            data = response.json()
            if "schoolInfo" in data and data.get("schoolInfo")[1].get("row"):
                school_data = data["schoolInfo"][1]["row"][0]
                address = school_data.get("ORG_RDNMA", "")
                district = extract_district_from_address(address)
                school_info = {
                    'code': school_data["SD_SCHUL_CODE"],
                    'name': school_data["SCHUL_NM"],
                    'region_code': school_data["ATPT_OFCDC_SC_CODE"],
                    'address': address,
                    'district': district
                }
                school_cache[school_code] = school_info
                app.logger.info(f"Found school {school_code} in region {region_name} via fallback")
                return school_info
        except requests.exceptions.Timeout:
            app.logger.debug(f"Timeout in region {region_name}, continuing...")
            continue
        except:
            continue
    
    app.logger.error(f"Failed to find school {school_code} in all regions")
    return None

def get_schools_by_region_and_level_with_location(region_code, school_level=None):
    cache_key = f"schools_with_location_{region_code}_{school_level or 'all'}"
    if hasattr(get_schools_by_region_and_level_with_location, 'cache'):
        if cache_key in get_schools_by_region_and_level_with_location.cache:
            return get_schools_by_region_and_level_with_location.cache[cache_key]
    else:
        get_schools_by_region_and_level_with_location.cache = {}
    cached_data = load_cache_from_file(cache_key)
    if cached_data:
        get_schools_by_region_and_level_with_location.cache[cache_key] = cached_data
        return cached_data
    url = "https://open.neis.go.kr/hub/schoolInfo"
    schools = []
    try:
        params = {
            "KEY": API_KEY,
            "Type": "json",
            "pIndex": 1,
            "pSize": 300,
            "ATPT_OFCDC_SC_CODE": region_code
        }
        response = requests.get(url, params=params, timeout=8)
        response.raise_for_status()
        data = response.json()
        if "schoolInfo" not in data or len(data["schoolInfo"]) < 2:
            app.logger.warning(f"No schools found for region {region_code}")
            get_schools_by_region_and_level_with_location.cache[cache_key] = []
            return []
        rows = data["schoolInfo"][1].get("row", [])
        for school_data in rows:
            try:
                school_name = school_data["SCHUL_NM"]
                school_code = school_data["SD_SCHUL_CODE"]
                address = school_data.get("ORG_RDNMA", "")
                district = extract_district_from_address(address)
                schools.append({
                    'code': school_code,
                    'name': school_name,
                    'region_code': region_code,
                    'address': address,
                    'district': district
                })
            except KeyError:
                continue
        if len(rows) >= 300:
            page = 2
            while page <= 10:
                params["pIndex"] = page
                try:
                    response = requests.get(url, params=params, timeout=5)
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
                            address = school_data.get("ORG_RDNMA", "")
                            district = extract_district_from_address(address)
                            schools.append({
                                'code': school_code,
                                'name': school_name,
                                'region_code': region_code,
                                'address': address,
                                'district': district
                            })
                        except KeyError:
                            continue
                    if len(rows) < 300:
                        break
                    page += 1
                except:
                    break
        schools.sort(key=lambda x: x['name'])
        if school_level:
            level_keywords = school_levels.get(school_level, [])
            filtered_schools = []
            for school in schools:
                if any(keyword in school['name'] for keyword in level_keywords):
                    filtered_schools.append(school)
            schools = filtered_schools
        get_schools_by_region_and_level_with_location.cache[cache_key] = schools
        save_cache_to_file(cache_key, schools)
        app.logger.info(f"Fetched {len(schools)} schools with district info for {region_code}, level: {school_level}")
        return schools
    except Exception as e:
        app.logger.error(f"Error fetching schools with district for region {region_code}, level {school_level}: {e}")
        get_schools_by_region_and_level_with_location.cache[cache_key] = []
        return []

def find_school_by_code_with_location(school_code, region_code=None):
    """수정: region_code 파라미터 추가 + 폴백 메커니즘"""
    if school_code in school_cache:
        cached_info = school_cache[school_code]
        if 'district' in cached_info:
            return cached_info
    
    # region_code가 있으면 해당 지역에서만 조회
    if region_code:
        url = "https://open.neis.go.kr/hub/schoolInfo"
        params = {
            "KEY": API_KEY, "Type": "json", "pIndex": 1, "pSize": 1,
            "ATPT_OFCDC_SC_CODE": region_code, "SD_SCHUL_CODE": school_code
        }
        try:
            response = requests.get(url, params=params, timeout=2)
            response.raise_for_status()
            data = response.json()
            if "schoolInfo" in data and data.get("schoolInfo")[1].get("row"):
                school_data = data["schoolInfo"][1]["row"][0]
                address = school_data.get("ORG_RDNMA", "")
                district = extract_district_from_address(address)
                school_info = {
                    'code': school_data["SD_SCHUL_CODE"],
                    'name': school_data["SCHUL_NM"],
                    'region_code': school_data["ATPT_OFCDC_SC_CODE"],
                    'address': address,
                    'district': district
                }
                school_cache[school_code] = school_info
                return school_info
        except Exception as e:
            app.logger.warning(f"Error finding school by code {school_code} in region {region_code}: {e}")
    
    # 폴백: 모든 지역 순회
    url = "https://open.neis.go.kr/hub/schoolInfo"
    for region_name, region_code_iter in regions.items():
        params = {
            "KEY": API_KEY, "Type": "json", "pIndex": 1, "pSize": 1,
            "ATPT_OFCDC_SC_CODE": region_code_iter, "SD_SCHUL_CODE": school_code
        }
        try:
            response = requests.get(url, params=params, timeout=2)
            response.raise_for_status()
            data = response.json()
            if "schoolInfo" in data and data.get("schoolInfo")[1].get("row"):
                school_data = data["schoolInfo"][1]["row"][0]
                address = school_data.get("ORG_RDNMA", "")
                district = extract_district_from_address(address)
                school_info = {
                    'code': school_data["SD_SCHUL_CODE"],
                    'name': school_data["SCHUL_NM"],
                    'region_code': school_data["ATPT_OFCDC_SC_CODE"],
                    'address': address,
                    'district': district
                }
                school_cache[school_code] = school_info
                return school_info
        except:
            continue
    
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

def extract_district_from_address(address):
    if not address:
        return None
    import re
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
            else:
                return match.group(1)
    return None

def get_nearby_schools(current_school_info):
    try:
        # 수정: region_code를 파라미터로 전달
        current_school_detailed = find_school_by_code(
            current_school_info['code'], 
            current_school_info.get('region_code')
        )
        if not current_school_detailed:
            app.logger.warning(f"Cannot get detailed info for {current_school_info['name']}")
            return []
        current_school_name = current_school_detailed['name']
        current_region_code = current_school_detailed['region_code']
        current_district = current_school_detailed.get('district', '')
        current_address = current_school_detailed.get('address', '')
        current_level = get_school_level_from_name(current_school_name)
        app.logger.info(f"Finding nearby schools for: {current_school_name}")
        app.logger.info(f"Current address: {current_address}")
        app.logger.info(f"Extracted district: {current_district}")
        app.logger.info(f"School level: {current_level}")
        if not current_level:
            app.logger.warning(f"Cannot determine school level for {current_school_name}")
            return []
        if not current_district:
            app.logger.warning(f"No district extracted from address for {current_school_name}")
            return []
        all_schools = get_schools_by_region_and_level(current_region_code, current_level)
        app.logger.info(f"Total schools in region with same level: {len(all_schools)}")
        nearby_schools = []
        for school in all_schools:
            if school['code'] == current_school_info['code']:
                continue
            school_district = school.get('district', '')
            if school_district and current_district == school_district:
                nearby_schools.append({
                    'code': school['code'],
                    'name': school['name'],
                    'distance_info': f"{current_district}"
                })
        nearby_schools.sort(key=lambda x: x['name'])
        app.logger.info(f"Found {len(nearby_schools)} nearby schools in {current_district}")
        return nearby_schools
    except Exception as e:
        app.logger.error(f"Error getting nearby schools: {e}")
        return []

def get_month_dates():
    today = datetime.now(KST).date()
    _, last_day = calendar.monthrange(today.year, today.month)
    return [(date(today.year, today.month, day)).strftime('%Y%m%d') for day in range(1, last_day + 1)]

def get_week_dates():
    today = datetime.now(KST).date()
    start_of_week = today - timedelta(days=(today.weekday() + 1) % 7)
    return [(start_of_week + timedelta(days=i)).strftime('%Y%m%d') for i in range(7)]

def get_month_meals(school_code, region_code):
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
        response = requests.get(url, params=params, timeout=3)
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
    return dict(meals)

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
        school_info = get_school_code(school_name_input, region_code)
        if school_info == "API_ERROR":
            return render_template('school_meal.html',
                                 error_message="NEIS API에 오류가 발생하여 일시적으로 급식 정보를 불러올 수 없습니다. 잠시 후 다시 시도해주세요.",
                                 regions=regions,
                                 region=region_name,
                                 school_name=school_name_input)
        elif school_info:
            response = make_response(redirect(url_for('school_meal_view', school_code=school_info['code'])))
            response.set_cookie('school_code', school_info['code'], max_age=60*60*24*30)
            response.set_cookie('school_name', quote(school_info['name']), max_age=60*60*24*30)
            response.set_cookie('region_code', school_info['region_code'], max_age=60*60*24*30)
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
    else:
        return render_template('school_meal.html', regions=regions)

@app.route("/meal/<school_code>")
def school_meal_view(school_code):
    # 수정: 쿠키에서 region_code 가져와서 사용 + 디버깅 강화
    region_code_cookie = request.cookies.get('region_code')
    
    app.logger.info(f"school_meal_view called - school_code: {school_code}, region_code_cookie: {region_code_cookie}")
    
    school_info = find_school_by_code(school_code, region_code_cookie)
    
    app.logger.info(f"school_info result: {school_info}")
    
    if not school_info:
        app.logger.warning(f"Failed to find school info for code: {school_code}, region_code: {region_code_cookie}")
        return redirect(url_for('index', error_message="존재하지 않거나 유효하지 않은 학교 정보입니다. 다시 검색해주세요."))
    
    # school_info에 region_code가 있는지 확인
    if 'region_code' not in school_info:
        app.logger.error(f"school_info missing region_code: {school_info}")
        return redirect(url_for('index', error_message="학교 정보에 오류가 있습니다. 다시 검색해주세요."))
    
    month_meals_data = get_month_meals(school_code, school_info['region_code'])
    today_str = datetime.now(KST).strftime('%Y%m%d')
    today_meal = month_meals_data.get(today_str, {
        "breakfast": "급식 정보 없음",
        "lunch": "급식 정보 없음",
        "dinner": "급식 정보 없음"
    })
    week_dates_list = get_week_dates()
    week_meals_data = {date_str: month_meals_data.get(date_str, {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"}) for date_str in week_dates_list}
    month_dates_list = get_month_dates()
    full_month_meals_data = {date_str: month_meals_data.get(date_str, {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"}) for date_str in month_dates_list}
    nearby_schools = get_nearby_schools(school_info)
    region_name = next((name for name, code in regions.items() if code == school_info['region_code']), None)
    resp = make_response(render_template(
        'school_meal.html',
        regions=regions,
        school_name=school_info['name'],
        school_code=school_info['code'],
        today_meal=today_meal,
        today_date=today_str,
        week_meals=week_meals_data,
        month_meals=full_month_meals_data,
        nearby_schools=nearby_schools,
        current_school=school_info,
        loading=False,
        region=region_name
    ))
    resp.set_cookie('school_code', school_info['code'], max_age=60*60*24*30)
    resp.set_cookie('school_name', quote(school_info['name']), max_age=60*60*24*30)
    resp.set_cookie('region_code', school_info['region_code'], max_age=60*60*24*30)
    if region_name:
        resp.set_cookie('region_name', region_name, max_age=60*60*24*30)
    return resp

@app.route('/api/meals/<school_code>/<date>')
def get_school_meal(school_code, date):
    # 수정: 쿠키에서 region_code 가져오기
    region_code_cookie = request.cookies.get('region_code')
    school_info = find_school_by_code(school_code, region_code_cookie)
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
    """수정: 자동완성 기능 복구 - region_code 파라미터 활용"""
    query = request.args.get('q', '').strip()
    region_name = request.args.get('region', '').strip()
    if not query or len(query) < 2:
        return jsonify([])
    if not region_name or region_name not in regions:
        return jsonify([])
    region_code = regions[region_name]
    search_terms = [query]
    expanded_query = expand_school_name(query)
    if expanded_query != query:
        search_terms.append(expanded_query)
    schools = []
    api_error = False
    cache_key = f"search_{region_code}_{query}"
    if hasattr(search_schools_autocomplete, 'cache'):
        if cache_key in search_schools_autocomplete.cache:
            return jsonify(search_schools_autocomplete.cache[cache_key][:10])
    else:
        search_schools_autocomplete.cache = {}
    all_schools_key = f"schools_{region_code}_all"
    if hasattr(get_schools_by_region_and_level, 'cache') and all_schools_key in get_schools_by_region_and_level.cache:
        all_schools = get_schools_by_region_and_level.cache[all_schools_key]
        for school in all_schools:
            if any(search_term.lower() in school['name'].lower() for search_term in search_terms):
                schools.append({
                    'code': school['code'],
                    'name': school['name'],
                    'region_code': school['region_code']
                })
                if len(schools) >= 10:
                    break
        if schools:
            search_schools_autocomplete.cache[cache_key] = schools
            import time
            import threading
            def clear_cache():
                time.sleep(300)
                if cache_key in search_schools_autocomplete.cache:
                    del search_schools_autocomplete.cache[cache_key]
            threading.Thread(target=clear_cache, daemon=True).start()
            return jsonify(schools[:10])
    for search_term in search_terms:
        url = "https://open.neis.go.kr/hub/schoolInfo"
        params = {
            "KEY": API_KEY,
            "Type": "json",
            "pIndex": 1,
            "pSize": 10,
            "ATPT_OFCDC_SC_CODE": region_code,
            "SCHUL_NM": search_term
        }
        try:
            response = requests.get(url, params=params, timeout=2)
            response.raise_for_status()
            data = response.json()
            if "schoolInfo" in data and data.get("schoolInfo")[1].get("row"):
                for school_data in data["schoolInfo"][1]["row"]:
                    school_info = {
                        'code': school_data["SD_SCHUL_CODE"],
                        'name': school_data["SCHUL_NM"],
                        'region_code': school_data["ATPT_OFCDC_SC_CODE"]
                    }
                    if not any(s['code'] == school_info['code'] for s in schools):
                        schools.append(school_info)
                        cache_key_school = f"{region_code}_{school_data['SCHUL_NM']}"
                        school_cache[cache_key_school] = school_info
                        school_cache[school_data["SD_SCHUL_CODE"]] = school_info
            if len(schools) >= 10:
                break
        except requests.exceptions.Timeout:
            app.logger.error(f"Error in autocomplete search for '{search_term}': API timeout")
            api_error = True
            continue
        except Exception as e:
            app.logger.error(f"Error in autocomplete search for '{search_term}': {e}")
            api_error = True
            continue
    if schools:
        search_schools_autocomplete.cache[cache_key] = schools
        import time
        import threading
        def clear_cache():
            time.sleep(300)
            if cache_key in search_schools_autocomplete.cache:
                del search_schools_autocomplete.cache[cache_key]
        threading.Thread(target=clear_cache, daemon=True).start()
    if api_error and len(schools) == 0:
        return jsonify({"error": "NEIS API에 오류가 발생하여 일시적으로 급식 정보를 불러올 수 없습니다. 잠시 후 다시 시도해주세요."}), 500
    return jsonify(schools[:10])

@app.route('/api/schools/region/<region_code>')
def get_all_schools_in_region(region_code):
    try:
        if region_code not in regions.values():
            return jsonify({"error": "Invalid region code"}), 400
        schools = get_schools_by_region_and_level(region_code)
        simplified_schools = [
            {
                'code': school['code'],
                'name': school['name']
            }
            for school in schools
        ]
        response = make_response(jsonify(simplified_schools))
        response.headers['Cache-Control'] = 'public, max-age=3600'
        return response
    except Exception as e:
        app.logger.error(f"Error in get_all_schools_in_region: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/meals/today/<school_code>')
def get_today_meal(school_code):
    region_code_cookie = request.cookies.get('region_code')
    school_info = find_school_by_code(school_code, region_code_cookie)
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
    return jsonify({'current_time': datetime.now(KST).isoformat()})

@app.route('/schools/<region_name>')
def schools_by_region(region_name):
    try:
        from urllib.parse import unquote
        region_name = unquote(region_name)
    except:
        pass
    if region_name not in regions:
        return redirect(url_for('index', error_message="유효하지 않은 지역입니다."))
    region_code = regions[region_name]
    schools_by_level = {}
    all_schools = get_schools_by_region_and_level(region_code)
    for level, keywords in school_levels.items():
        level_schools = []
        for school in all_schools:
            if any(keyword in school['name'] for keyword in keywords):
                level_schools.append(school)
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
    all_schools = get_schools_by_region_and_level(region_code)
    schools = []
    keywords = school_levels.get(school_level, [])
    for school in all_schools:
        if any(keyword in school['name'] for keyword in keywords):
            schools.append(school)
    log_access_request(200)
    return render_template('schools_by_level.html',
                         region_name=region_name,
                         school_level=school_level,
                         schools=schools,
                         regions=regions)

def preload_school_cache():
    import threading
    def load_region(region_name, region_code):
        try:
            app.logger.info(f"Preloading schools for {region_name}")
            get_schools_by_region_and_level(region_code)
            app.logger.info(f"Completed preloading for {region_name}")
        except Exception as e:
            app.logger.error(f"Failed to preload {region_name}: {e}")
    priority_regions = ["서울", "부산", "경기", "부산", "대구", "인천", "광주", "대전", "광주", "울산", "세종", "강원", "충북", "충남", "전북", "전남", "경북", "경남", "제주"]
    for region_name in priority_regions:
        if region_name in regions:
            region_code = regions[region_name]
            thread = threading.Thread(target=load_region, args=(region_name, region_code))
            thread.daemon = True
            thread.start()

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
        else:
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
        else:
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
        else:
            return 'NamuBoard Extension 로그 파일이 아직 생성되지 않았습니다.'
    except Exception as e:
        return f'NamuBoard Extension 로그 파일 읽기 오류: {e}'

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
            'user_agents': {}
        }
        with open(ACCESS_LOG_PATH, 'r', encoding='utf-8') as f:
            for line in f:
                if 'IP:' in line:
                    stats['total_requests'] += 1
                    try:
                        ip_start = line.find('IP: ') + 4
                        ip_end = line.find(' -', ip_start)
                        if ip_end > ip_start:
                            ip = line[ip_start:ip_end]
                            stats['unique_ips'].add(ip)
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
    client_ip = get_client_ip()
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
    app.logger.info(f"접속 로그 파일 경로: {ACCESS_LOG_PATH}")
    app.logger.info(f"앱 로그 파일 경로: {APP_LOG_PATH}")
    app.logger.info(f"IP 차단 로그 파일 경로: {IP_BLOCK_LOG_PATH}")
    app.logger.info(f"NamuBoard Extension 로그 파일 경로: {NAMUBOARD_LOG_PATH}")
    app.logger.info(f"관리자 화이트리스트: {ADMIN_WHITELIST}")
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
