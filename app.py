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
import json # Removed in app_edited.py, but needed for security/blacklist/add endpoint's request.get_json()

app = Flask(__name__)

# --- 보안 설정 (원본 전체 복구) ---
BLACKLIST_FILE = os.path.join(os.getcwd(), 'ip_blacklist.txt')
SUSPICIOUS_PATTERNS_FILE = os.path.join(os.getcwd(), 'suspicious_patterns.json') # Currently unused, but kept for consistency
request_counts = defaultdict(deque)
failed_attempts = defaultdict(int)
blocked_ips = set()
SECURITY_CONFIG = {
    'rate_limit_window': 60, 'rate_limit_requests': 60,
    'failed_attempt_threshold': 5, 'auto_block_duration': 3600,
    'suspicious_ua_block': True, 'path_traversal_protection': True,
}
SUSPICIOUS_PATTERNS = {
    'paths': [r'\.php$', r'wp-', r'admin', r'login', r'\.env', r'config', r'\.git', r'\.sql', r'backup', r'shell', r'cmd', r'eval', r'\.xml$', r'xmlrpc', r'\.asp', r'\.jsp', r'\.cgi'],
    'user_agents': [r'spider', r'scanner', r'nikto', r'sqlmap', r'nmap', r'masscan', r'zap', r'burp'],
    'parameters': [r'union.*select', r'<script', r'javascript:', r'eval\(', r'exec\(', r'system\(', r'\.\./', r'etc/passwd']
}
ADMIN_WHITELIST = ['210.94.23.150/32', '118.221.147.88/32']

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

BLOCKED_NETWORKS = load_ip_blacklist()

# --- 로깅 설정 (요청사항 반영 및 복구) ---
LOG_DIR = 'logs'
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

# app_edited.py의 로그 파일 경로 설정 유지
APP_LOG_PATH = os.path.join(LOG_DIR, 'app.log')
ERROR_403_LOG_PATH = os.path.join(LOG_DIR, '403_errors.log')
SECURITY_LOG_PATH = os.path.join(LOG_DIR, 'security.log')
NAMUBOARD_LOG_PATH = os.path.join(LOG_DIR, 'namuboard.log') # 원본 유지

def clean_user_agent(ua_string):
    """로그용 User-Agent 정리 함수"""
    if not ua_string: return 'N/A'
    # Mozilla/5.0 등 파일 크기를 늘리는 부분 제외 로직 유지
    ua = re.sub(r'^(Mozilla/\d\.\d\s*\(.*?\)|AppleWebKit/[\d\.]+\s*\(KHTML, like Gecko\)\s*|Chrome/\d+\.\d+\.\d+\.\d+\s*|Safari/\d+\.\d+\s*|Edge/\d+\.\d+\s*|Firefox/\d+\.\d+\s*)+', '', ua_string).strip()
    return ua if ua else ua_string[:200] # Cap at 200 characters

# 요청에 따라 로거들을 분리하여 설정
def setup_loggers():
    # 403 에러 로거
    error_403_logger = logging.getLogger('403_logger')
    error_403_logger.setLevel(logging.WARNING)
    if not error_403_logger.handlers:
        handler_403 = RotatingFileHandler(ERROR_403_LOG_PATH, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8')
        formatter_403 = logging.Formatter('[%(asctime)s] 403 FORBIDDEN - IP: %(ip)s - UA: %(user_agent)s - "%(method)s %(path)s"')
        handler_403.setFormatter(formatter_403)
        error_403_logger.addHandler(handler_403)
    error_403_logger.propagate = False

    # 보안 사고 로거
    security_logger = logging.getLogger('security')
    security_logger.setLevel(logging.WARNING)
    if not security_logger.handlers:
        security_handler = RotatingFileHandler(SECURITY_LOG_PATH, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
        security_handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s'))
        security_logger.addHandler(security_handler)
    security_logger.propagate = False
    
    # 통합 앱 로거 (werkzeug 로그 포함, 403 제외, HEAD 제외)
    app_logger = logging.getLogger()
    app_logger.setLevel(logging.INFO)
    # 기존 핸들러 제거 (중복 방지)
    for h in app_logger.handlers[:]: app_logger.removeHandler(h)
        
    app_handler = RotatingFileHandler(APP_LOG_PATH, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
    # Custom formatter to include IP, UA, Method, Path, Status
    app_formatter = logging.Formatter('[%(asctime)s] IP: %(ip)s - UA: %(user_agent)s - "%(method)s %(path)s" - Status: %(status)s - %(levelname)s: %(message)s')
    app_handler.setFormatter(app_formatter)
    app_logger.addHandler(app_handler)

    # NamuBoard Extension 전용 로그 핸들러 (새로 추가)
    namuboard_logger = logging.getLogger('namuboard')
    namuboard_logger.setLevel(logging.INFO)
    if not namuboard_logger.handlers: # Prevent adding multiple handlers
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
        namuboard_logger.addHandler(namuboard_handler)
    namuboard_logger.propagate = False

setup_loggers()

# NamuBoard Extension 접속 로그 기록 함수 - 복구
def log_namuboard_access_request():
    """/namuboardextension.user.js 접근 로그를 기록합니다."""
    try:
        real_ip = get_client_ip()
        extra_info = {
            'remote_addr': real_ip or 'Unknown',
            'user_agent': clean_user_agent(request.headers.get('User-Agent', 'Unknown')),
            'referrer': request.headers.get('Referer', 'N/A')[:100]
        }
        logging.getLogger('namuboard').info('NamuBoard Extension Access', extra=extra_info)
    except Exception as e:
        app.logger.error(f"NamuBoard Extension 로그 기록 중 오류 발생: {e}")

# --- 보안 관련 함수 (원본 전체 복구) ---
def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    # app.py 원본에 access_route fallback이 있었음
    elif request.access_route:
        return request.access_route[0]
    return request.remote_addr

def is_ip_blocked(ip):
    try:
        addr = ipaddress.ip_address(ip)
        if ip in blocked_ips: return True
        return any(addr in ipaddress.ip_network(net, strict=False) for net in BLOCKED_NETWORKS)
    except ValueError: return True

def is_admin_ip(ip):
    try:
        return any(ipaddress.ip_address(ip) in ipaddress.ip_network(net, strict=False) for net in ADMIN_WHITELIST)
    except ValueError: return False

def is_rate_limited(ip):
    now = time.time()
    while request_counts[ip] and request_counts[ip][0] < now - SECURITY_CONFIG['rate_limit_window']:
        request_counts[ip].popleft()
    request_counts[ip].append(now)
    return len(request_counts[ip]) > SECURITY_CONFIG['rate_limit_requests']

def is_suspicious_request():
    score, reasons = 0, []
    path = request.path.lower()
    ua = request.headers.get('User-Agent', '').lower()
    qs = request.query_string.decode('utf-8', errors='ignore').lower()
    if any(re.search(p, path, re.I) for p in SUSPICIOUS_PATTERNS['paths']): score, reasons = score+10, reasons+["Path"]
    if any(re.search(p, ua, re.I) for p in SUSPICIOUS_PATTERNS['user_agents']): score, reasons = score+15, reasons+["UA"]
    if any(re.search(p, qs, re.I) for p in SUSPICIOUS_PATTERNS['parameters']): score, reasons = score+20, reasons+["Param"]
    
    # HTTP 메소드 검사 (웹사이트 특성상 GET, POST, HEAD만 허용) - 원본 로직 복구
    if request.method not in ['GET', 'POST', 'HEAD']:
        score += 10
        reasons.append(f"Suspicious method: {request.method}")

    # 존재하지 않는 확장자 요청 - 원본 로직 복구
    if path.endswith(('.php', '.asp', '.jsp', '.cgi')) and not path.startswith('/api/'):
        score += 15
        reasons.append("Non-existent extension request")

    return score >= 10, score, reasons

def log_security_incident(ip, incident_type, details, score=0):
    """보안 사고 로깅"""
    security_logger = logging.getLogger('security')
    security_logger.warning(
        f"SECURITY INCIDENT - IP: {ip}, Type: {incident_type}, "
        f"Score: {score}, Details: {details}, "
        f"UA: {request.headers.get('User-Agent', 'N/A')[:100]}, "
        f"Path: {request.path}, Method: {request.method}"
    )

def auto_block_ip(ip, reason, duration=None): # 원본의 duration=None 유지
    """IP를 자동으로 일정 시간 차단"""
    if duration is None: # duration 처리 원본 로직 유지
        duration = SECURITY_CONFIG['auto_block_duration']
    blocked_ips.add(ip)
    log_security_incident(ip, "AUTO_BLOCK", f"{reason} - Duration: {duration}s")
    failed_attempts[ip] += 1
    if failed_attempts[ip] >= SECURITY_CONFIG['failed_attempt_threshold']:
        save_to_blacklist(f"{ip}/32", f"Auto-blocked: {reason}")

@app.before_request
def security_check():
    """종합 보안 검사"""
    ip = get_client_ip()
    if is_admin_ip(ip): return
    if is_ip_blocked(ip): 
        log_security_incident(ip, "BLOCKED_IP", "IP in blacklist") # 원본 로깅 추가
        abort(403)
    if is_rate_limited(ip):
        log_security_incident(ip, "RATE_LIMIT", "Too many requests")
        auto_block_ip(ip, "Rate limit exceeded", 300)
        abort(429)
    is_suspicious, score, reasons = is_suspicious_request()
    if is_suspicious:
        log_security_incident(ip, "SUSPICIOUS_PATTERN", f"Reasons: {', '.join(reasons)}", score) # 원본 로깅 포맷 복구
        if score >= 20: auto_block_ip(ip, f"High suspicion score: {score}"); abort(403)
        elif score >= 15: abort(404)
    if SECURITY_CONFIG['path_traversal_protection'] and ('../' in request.path or '..\\' in request.path):
        log_security_incident(ip, "PATH_TRAVERSAL", request.path)
        auto_block_ip(ip, "Path traversal attempt")
        abort(403)

# --- NEIS API 및 기본 설정 ---
API_KEY = "4e2c538d90ef493c94c6e2d943e756d9"
KST = timezone(timedelta(hours=9))
regions = {"서울":"B10", "부산":"C10", "대구":"D10", "인천":"E10", "광주":"F10", "대전":"G10", "울산":"H10", "세종":"I10", "경기":"J10", "강원":"K10", "충북":"M10", "충남":"N10", "전북":"P10", "전남":"Q10", "경북":"R10", "경남":"S10", "제주":"T10"}
school_cache = {}
meal_cache = {}
school_code_cache = {} # 요청사항 반영 (유지)

# --- 핵심 함수 ---
def get_school_code(school_name, region_code):
    """학교 이름과 지역 코드로 NEIS API에서 학교 코드와 전체 이름을 조회합니다."""
    cache_key = f"{region_code}_{school_name}"
    if cache_key in school_cache:
        # school_code_cache 업데이트도 함께 진행
        school_info = school_cache[cache_key]
        school_code_cache[school_info['code']] = school_info
        return school_info

    url = "https://open.neis.go.kr/hub/schoolInfo"
    params = {
        "KEY": API_KEY, "Type": "json", "pIndex": 1, "pSize": 100,
        "ATPT_OFCDC_SC_CODE": region_code, "SCHUL_NM": school_name
    }
    try:
        response = requests.get(url, params=params, timeout=5)
        response.raise_for_status()
        data = response.json()

        if "schoolInfo" in data and data.get("schoolInfo")[1].get("row"):
            school_data = data["schoolInfo"][1]["row"][0]
            school_code_val = school_data["SD_SCHUL_CODE"]
            full_school_name = school_data["SCHUL_NM"]
            school_info = {
                'code': school_code_val,
                'name': full_school_name,
                'region_code': region_code
            }
            school_cache[cache_key] = school_info
            # 입력 이름과 다른 경우에도 캐시 (예: 양정고 -> 양정고등학교)
            school_cache[f"{region_code}_{full_school_name}"] = school_info
            school_code_cache[school_code_val] = school_info # school_code_cache 업데이트
            return school_info
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error fetching school code (Request) for {school_name}: {e}")
    except Exception as e:
        app.logger.error(f"Error fetching school code (General) for {school_name}: {e}")
    return None

def get_school_info_by_code(school_code):
    """학교 코드를 사용하여 학교 정보를 캐시에서 조회합니다."""
    # 먼저 school_code_cache에서 찾기
    if school_code in school_code_cache:
        return school_code_cache[school_code]
    
    # school_cache를 역방향으로 순회하며 찾기 (효율적이지 않으므로 school_code_cache 사용 권장)
    # 하지만 만약을 위해 유지
    for info in school_cache.values():
        if info.get('code') == school_code:
            school_code_cache[school_code] = info # 찾았으면 school_code_cache에 추가
            return info
    return None

def get_month_dates():
    """현재 KST 기준 월의 모든 날짜를 YYYYMMDD 형식으로 반환합니다."""
    today = datetime.now(KST).date()
    _, last_day = calendar.monthrange(today.year, today.month)
    return [(date(today.year, today.month, day)).strftime('%Y%m%d') for day in range(1, last_day + 1)]

def get_week_dates():
    """현재 KST 기준 주의 모든 날짜(일~토)를 YYYYMMDD 형식으로 반환합니다."""
    today = datetime.now(KST).date()
    # 주의 시작을 일요일 (0)로 맞추기 위해 (today.weekday() + 1) % 7 사용
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

# --- 라우트 (Routes) ---
@app.route("/", methods=["GET", "POST"])
def index():
    error_message = request.args.get('error_message')
    region_cookie = request.cookies.get('region_name')
    school_name_encoded = request.cookies.get('school_name')
    school_name_cookie = unquote(school_name_encoded) if school_name_encoded else None

    if request.method == 'GET':
        # 이전 요청에서 '강제 이동' 문제 해결을 위해 school_code 쿠키를 직접 사용한 리다이렉션 로직 제거됨.
        # school_name과 region_name 쿠키가 있다면 학교 정보를 다시 조회하여 유효성 검사를 시도.
        if school_name_cookie and region_cookie:
            region_code_from_cookie = regions.get(region_cookie)
            if region_code_from_cookie:
                school_info_from_cookie = get_school_code(school_name_cookie, region_code_from_cookie)
                if school_info_from_cookie:
                    app.logger.info(f"Redirecting to saved school: {school_info_from_cookie['name']} ({school_info_from_cookie['code']})")
                    return redirect(url_for('school_meal_view', school_code=school_info_from_cookie['code']))
            # 쿠키가 있으나 유효한 학교 정보를 찾지 못한 경우 (문제 3 해결 노력의 일부)
            # 이 경우 에러 메시지를 표시하거나 초기 화면으로 진행

    elif request.method == 'POST':
        region_name = request.form['region']
        school_name_input = request.form['school_name']
        app.logger.info(f"Search request - Region: {region_name}, School: {school_name_input}")

        if not region_name or not school_name_input:
            return render_template('school_meal.html', error_message="지역과 학교명을 모두 입력해주세요.", regions=regions)

        region_code = regions.get(region_name)
        if not region_code:
            return render_template('school_meal.html', error_message="유효하지 않은 지역입니다.", regions=regions)

        school_info = get_school_code(school_name_input, region_code)
        if school_info:
            response = make_response(redirect(url_for('school_meal_view', school_code=school_info['code'])))
            # 쿠키 설정: school_name, region_code, region_name 모두 저장
            response.set_cookie('school_name', quote(school_info['name']), max_age=60*60*24*30, samesite='Lax') # samesite 추가됨
            response.set_cookie('region_code', school_info['region_code'], max_age=60*60*24*30, samesite='Lax')
            response.set_cookie('region_name', region_name, max_age=60*60*24*30, samesite='Lax')
            return response
        else:
            return render_template('school_meal.html', error_message="학교를 찾을 수 없습니다.", regions=regions, region=region_name, school_name=school_name_input)

    return render_template('school_meal.html', regions=regions, error_message=error_message, region=region_cookie, school_name=school_name_cookie)

@app.route("/meal/<school_code>")
def school_meal_view(school_code):
    school_name_encoded = request.cookies.get('school_name')
    region_code_cookie = request.cookies.get('region_code') # 쿠키에서 region_code를 가져옴

    # 학교 정보가 없거나 만료된 경우 (문제 3 해결 노력의 일부)
    if not school_name_encoded or not region_code_cookie:
        return redirect(url_for('index', error_message="학교 정보가 만료되었거나 없습니다. 다시 검색해주세요."))

    school_name = unquote(school_name_encoded)
    school_info = get_school_info_by_code(school_code) # school_code_cache를 먼저 확인

    # 캐시에 없으면, 쿠키의 학교 이름과 지역 코드로 API 호출 시도
    if not school_info:
        school_info = get_school_code(school_name, region_code_cookie) # 쿠키의 region_code 사용

    # API 호출도 실패하면 쿠키 정보로 최소 구성 (fallback)
    if not school_info:
        school_info = {'code': school_code, 'name': school_name, 'region_code': region_code_cookie}
        app.logger.warning(f"Using fallback school info for {school_code}. Data might be incomplete.")

    month_meals_data = get_month_meals(school_code, school_info['region_code'])
    week_dates_list = get_week_dates()
    week_meals_data = {date_str: month_meals_data.get(date_str, {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"}) for date_str in week_dates_list}
    month_dates_list = get_month_dates()
    full_month_meals_data = {date_str: month_meals_data.get(date_str, {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"}) for date_str in month_dates_list}

    # HTML title 변경 요청 반영 (문제 4)
    title = f"{school_info['name']} 급식 정보 - ImHungry - 간편한 급식 사이트"
    region_name = next((name for name, code in regions.items() if code == school_info['region_code']), None)


    resp = make_response(render_template(
        'school_meal.html',
        regions=regions,
        school_name=school_info['name'],
        school_code=school_code,
        week_meals=week_meals_data,
        month_meals=full_month_meals_data,
        loading=False,
        region=region_name,
        title=title
    ))

    # 쿠키 갱신 (인코딩) - 원본 로직 복구 및 samesite 추가
    resp.set_cookie('school_name', quote(school_info['name']), max_age=60*60*24*30, samesite='Lax')
    resp.set_cookie('region_code', school_info['region_code'], max_age=60*60*24*30, samesite='Lax')
    if region_name: # region_name도 갱신
        resp.set_cookie('region_name', region_name, max_age=60*60*24*30, samesite='Lax')

    return resp

@app.route('/api/meals/<school_code>/<date>')
def api_get_meal(school_code, date):
    """API: 특정 학교, 특정 날짜의 급식 정보를 반환합니다."""
    # region_code는 school_info에서 얻는 것이 더 신뢰성 있음
    school_info = get_school_info_by_code(school_code)
    if not school_info:
        # 캐시에 없으면, 쿠키에서 region_code를 가져와 시도
        region_code_from_cookie = request.cookies.get('region_code')
        if region_code_from_cookie:
            # school_name을 알 수 없으므로, 이 시점에서 school_info를 NEIS API로 조회하는 것은 비효율적.
            # 클라이언트가 school_info를 제공하지 않는 한, 캐시된 정보에 의존.
            # 이 API는 주로 NamuBoard 확장 등에서 사용되므로, 이미 검색된 학교 정보가 있을 것으로 가정.
            app.logger.warning(f"API request for unknown school_code {school_code}. Attempting with region from cookie.")
            # 임시 school_info 생성 (급식 조회만 목적)
            school_info = {'code': school_code, 'name': 'Unknown School', 'region_code': region_code_from_cookie}
        else:
            return jsonify({"error": "School information not found and region code missing"}), 400

    try:
        month_meals = get_month_meals(school_code, school_info['region_code'])
        meal_data = month_meals.get(date, {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"})
        return jsonify(meal_data)
    except Exception as e:
        app.logger.error(f"Error in get_school_meal API for {school_code}, {date}: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/current_time')
def current_time(): return jsonify({'current_time': datetime.now(KST).isoformat()})
@app.route('/robots.txt')
def robots_txt(): return send_from_directory(app.static_folder, 'robots.txt')
@app.route('/favicon.svg')
def favicon(): return send_from_directory(app.static_folder, 'favicon.svg')
@app.route('/favicon.ico')
def faviconico(): return send_from_directory(app.static_folder, 'favicon.svg')
@app.route('/manifest.json')
def manifest(): return send_from_directory('static', 'manifest.json')
@app.route("/It's Christmas Time Again.mp3")
def namufile1(): return send_file("It's Christmas Time Again.mp3", mimetype="audio/mpeg")
@app.route('/namuboardextension.user.js')
def serve_tampermonkey_script():
    log_namuboard_access_request() # Log this specific access - 복구
    try:
        return send_from_directory(app.root_path, 'namuboardextension.user.js', mimetype='application/javascript')
    except FileNotFoundError:
        return "파일 오류. 사토 발제 바랍니다.", 404
    except Exception as e:
        app.logger.error(f"Error serving script: {e}")
        return "서버 오류. 사토 발제 바랍니다.", 500

# --- 로그 확인용 엔드포인트 (기존 통합 로그 뷰어 유지) ---
@app.route('/logs/<log_type>')
def view_logs(log_type):
    if not is_admin_ip(get_client_ip()): abort(403)
    # app_edited.py의 통합 로그 맵핑 유지
    log_map = {'app': APP_LOG_PATH, '403': ERROR_403_LOG_PATH, 'security': SECURITY_LOG_PATH, 'namuboard': NAMUBOARD_LOG_PATH} # namuboard 로그 추가
    log_file = log_map.get(log_type)
    if not log_file or not os.path.exists(log_file): return "Log not found.", 404
    with open(log_file, 'r', encoding='utf-8') as f: content = f.read()
    return f'<h2>{log_type.upper()} Log</h2><pre>{content}</pre>'

# --- 접속 통계 엔드포인트 (복구) ---
@app.route('/stats')
def view_stats():
    """접속 통계 (관리자 IP만 허용)"""
    client_ip = get_client_ip()
    
    # 관리자 IP 확인 또는 개발 모드 + 환경 변수 확인
    if not (is_admin_ip(client_ip) or (app.debug and os.environ.get('ENABLE_STATS') == 'true')):
        app.logger.warning(f"Unauthorized access attempt to stats from IP: {client_ip}")
        return "접근 권한이 없습니다.", 403
    
    try:
        # 이 부분은 ACCESS_LOG_PATH를 가정합니다. 현재 APP_LOG_PATH가 통합 로그 역할을 합니다.
        # 실제 사용 시 APP_LOG_PATH를 파싱하도록 수정하거나, ACCESS_LOG_PATH를 다시 활성화해야 합니다.
        if not os.path.exists(APP_LOG_PATH): # APP_LOG_PATH를 확인하도록 변경
            return '앱 로그 파일이 없습니다.'
        
        stats = {
            'total_requests': 0,
            'unique_ips': set(),
            'status_codes': {},
            'popular_paths': {},
            'user_agents': {}
        }
        
        with open(APP_LOG_PATH, 'r', encoding='utf-8') as f: # APP_LOG_PATH를 열도록 변경
            for line in f:
                # APP_LOG_PATH의 새 포맷에 맞춰 파싱 로직 조정 필요
                # 예: '[2023-10-27 10:00:00,123] IP: 1.2.3.4 - UA: Chrome - "GET /path" - Status: 200 - INFO: Request handled'
                if 'IP:' in line:
                    stats['total_requests'] += 1
                    
                    # IP 추출
                    try:
                        ip_match = re.search(r'IP: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                        if ip_match:
                            ip = ip_match.group(1)
                            stats['unique_ips'].add(ip)
                    except:
                        pass
                    
                    # 상태 코드 추출
                    try:
                        status_match = re.search(r'Status: (\d{3})', line)
                        if status_match:
                            status = status_match.group(1)
                            stats['status_codes'][status] = stats['status_codes'].get(status, 0) + 1
                    except:
                        pass
                    
                    # 경로 추출
                    try:
                        path_match = re.search(r'"(GET|POST|HEAD|PUT|DELETE) (\S+)"', line)
                        if path_match:
                            path = path_match.group(2).split('?')[0] # 쿼리 스트링 제거
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

# --- 보안 상태 확인 엔드포인트 (복구) ---
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

# 블랙리스트 관리 엔드포인트 (복구)
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
        
# --- 응답 로깅 (요청사항 반영) ---
@app.after_request
def after_request_logging(response):
    if request.method == 'HEAD': # HEAD 요청은 기록하지 않음 (요청사항 반영)
        return response

    log_extra = {
        'ip': get_client_ip(),
        'user_agent': clean_user_agent(request.headers.get('User-Agent')),
        'method': request.method,
        'path': request.full_path,
        'status': response.status_code
    }
    
    if response.status_code == 403:
        logging.getLogger('403_logger').warning("Forbidden", extra=log_extra) # 403은 별도로 기록 (요청사항 반영)
    else:
        # werkzeug 로그를 캡처하기 위해 info 레벨로 일반 로그 기록 (접속 로그 통합)
        # app_logger는 이미 여기에 연결된 핸들러가 있으므로 getLogger().info 호출
        logging.getLogger().info("Request handled", extra=log_extra)
        
    return response

# --- 앱 실행 (원본 복구) ---
if __name__ == "__main__":
    # 블랙리스트 파일 생성 (없는 경우) - app_edited.py에도 존재
    if not os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, 'w', encoding='utf-8') as f:
            f.write("# IP Blacklist\n")
            f.write("# Example: 192.168.1.0/24\n")
            f.write("# 52.178.178.217/32  # Example blocked IP\n") # app.py 원본에 있던 예시 추가
    
    # 로그 파일 경로 정보 출력 - 복구 및 현재 경로 반영
    app.logger.info(f"앱 로그 파일 경로: {os.path.abspath(APP_LOG_PATH)}")
    app.logger.info(f"403 에러 로그 파일 경로: {os.path.abspath(ERROR_403_LOG_PATH)}")
    app.logger.info(f"보안 로그 파일 경로: {os.path.abspath(SECURITY_LOG_PATH)}")
    app.logger.info(f"NamuBoard Extension 로그 파일 경로: {os.path.abspath(NAMUBOARD_LOG_PATH)}")
    app.logger.info(f"관리자 화이트리스트: {ADMIN_WHITELIST}") # 원본 복구
    app.logger.info(f"Security blacklist loaded: {len(BLOCKED_NETWORKS)} networks") # 원본 복구
    app.logger.info(f"Security config: {SECURITY_CONFIG}") # 원본 복구

    app.run(debug=False)
