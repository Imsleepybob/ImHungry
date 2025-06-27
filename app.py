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

# --- 캐시 설정 ---
# 서버 재시작 시 초기화되는 인메모리 캐시
# key: school_code, value: {'name': '학교명', 'region_code': '지역코드'}
school_code_to_info_cache = {}
school_search_cache = {} # 기존 school_cache
meal_cache = {}

# --- 보안 설정 ---
BLACKLIST_FILE = os.path.join(os.getcwd(), 'ip_blacklist.txt')
request_counts = defaultdict(deque)
failed_attempts = defaultdict(int)
blocked_ips = set()

SECURITY_CONFIG = {
    'rate_limit_window': 60,
    'rate_limit_requests': 60,
    'failed_attempt_threshold': 5,
    'auto_block_duration': 3600,
}

SUSPICIOUS_PATTERNS = {
    'paths': [r'\.php$', r'wp-', r'admin', r'login', r'\.env', r'\.git', r'\.sql'],
    'user_agents': [r'spider', r'scanner', r'nikto', r'sqlmap', r'nmap'],
    'parameters': [r'union.*select', r'<script', r'javascript:', r'\.\./']
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
                    app.logger.warning(f"블랙리스트에 잘못된 CIDR 형식이 있습니다: {line}")
    return blacklist

def save_to_blacklist(ip_or_cidr, reason="Automatic detection"):
    try:
        with open(BLACKLIST_FILE, 'a', encoding='utf-8') as f:
            f.write(f"{ip_or_cidr}  # {reason} - {datetime.now(KST)}\n")
        app.logger.info(f"블랙리스트에 추가됨: {ip_or_cidr} - {reason}")
    except Exception as e:
        app.logger.error(f"블랙리스트 저장 오류: {e}")

BLOCKED_NETWORKS = load_ip_blacklist()
ADMIN_WHITELIST = ['210.94.23.150/32', '118.221.147.88/32']
KST = timezone(timedelta(hours=9))

def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    return request.remote_addr

def is_ip_blocked(ip_address):
    try:
        client_ip = ipaddress.ip_address(ip_address)
        if ip_address in blocked_ips: return True
        for blocked_network in BLOCKED_NETWORKS:
            if client_ip in ipaddress.ip_network(blocked_network, strict=False):
                return True
        return False
    except ValueError:
        return True

def is_admin_ip(ip_address):
    try:
        client_ip = ipaddress.ip_address(ip_address)
        for admin_network in ADMIN_WHITELIST:
            if client_ip in ipaddress.ip_network(admin_network, strict=False):
                return True
        return False
    except ValueError:
        return False

def log_security_incident(ip, incident_type, details):
    security_logger = logging.getLogger('security')
    security_logger.warning(
        f"SECURITY INCIDENT - IP: {ip}, Type: {incident_type}, Details: {details}, "
        f"UA: {request.headers.get('User-Agent', 'N/A')}, Path: {request.path}"
    )

def auto_block_ip(ip, reason):
    blocked_ips.add(ip)
    log_security_incident(ip, "AUTO_BLOCK", reason)
    failed_attempts[ip] += 1
    if failed_attempts[ip] >= SECURITY_CONFIG['failed_attempt_threshold']:
        save_to_blacklist(f"{ip}/32", f"Auto-blocked: {reason}")

@app.before_request
def security_check():
    client_ip = get_client_ip()
    if is_admin_ip(client_ip): return

    if is_ip_blocked(client_ip):
        log_security_incident(client_ip, "BLOCKED_IP", "IP in blacklist")
        abort(403)

    # ... 기타 보안 검사 로직 ...

# --- 로깅 설정 (개선됨) ---
LOG_PATH = os.path.join(os.getcwd(), 'logs')
if not os.path.exists(LOG_PATH):
    os.makedirs(LOG_PATH)

APP_LOG_FILE = os.path.join(LOG_PATH, 'app.log')
SECURITY_LOG_FILE = os.path.join(LOG_PATH, 'security.log')

def clean_user_agent(user_agent_string):
    """로그 가독성을 위해 User-Agent 문자열을 정리합니다."""
    if not user_agent_string:
        return 'Unknown'
    # Mozilla/5.0 (...) 부분을 제거하고 주요 정보만 남깁니다.
    cleaned = re.sub(r'Mozilla/[0-9]\.[0-9] \([^)]+\) ?', '', user_agent_string)
    # 주요 브라우저 및 시스템 정보만 추출
    parts = re.findall(r'([a-zA-Z]+(?:/[0-9\.]+)?(?:\s\w+)?(?:\s\([^)]+\))?)', cleaned)
    short_ua = ' '.join(parts[:4]) # 주요 4개 파트만 사용
    return short_ua.strip() if short_ua else user_agent_string

def setup_logging():
    """통합 로깅 시스템을 설정합니다."""
    # 1. 앱 로그 핸들러 (모든 일반 로그)
    app_handler = RotatingFileHandler(
        APP_LOG_FILE, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'
    )
    # User-Agent를 포함하는 새 포맷
    app_formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s - %(message)s'
    )
    app_handler.setFormatter(app_formatter)

    # 2. 보안 로그 핸들러 (403 및 기타 보안 이벤트)
    security_handler = RotatingFileHandler(
        SECURITY_LOG_FILE, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8'
    )
    security_formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
    security_handler.setFormatter(security_formatter)

    # Flask 기본 로거에 앱 핸들러 추가
    app.logger.handlers = [] # 기본 핸들러 제거
    app.logger.addHandler(app_handler)
    app.logger.setLevel(logging.INFO)

    # 보안용 별도 로거 생성
    security_logger = logging.getLogger('security')
    security_logger.addHandler(security_handler)
    security_logger.setLevel(logging.WARNING)
    security_logger.propagate = False

setup_logging()

# --- NEIS API 및 기본 설정 ---
API_KEY = "4e2c538d90ef493c94c6e2d943e756d9"
regions = {
    "서울": "B10", "부산": "C10", "대구": "D10", "인천": "E10", "광주": "F10",
    "대전": "G10", "울산": "H10", "세종": "I10", "경기": "J10", "강원": "K10",
    "충북": "M10", "충남": "N10", "전북": "P10", "전남": "Q10", "경북": "R10",
    "경남": "S10", "제주": "T10"
}

# --- 핵심 함수 (개선됨) ---
def get_school_info(school_name, region_code):
    """학교 이름과 지역 코드로 NEIS API에서 학교 정보를 조회하고 캐시합니다."""
    cache_key = f"{region_code}_{school_name}"
    if cache_key in school_search_cache:
        return school_search_cache[cache_key]

    url = "https://open.neis.go.kr/hub/schoolInfo"
    params = {
        "KEY": API_KEY, "Type": "json", "pIndex": 1, "pSize": 10,
        "ATPT_OFCDC_SC_CODE": region_code, "SCHUL_NM": school_name
    }
    try:
        response = requests.get(url, params=params, timeout=5)
        response.raise_for_status()
        data = response.json()

        if "schoolInfo" in data and data.get("schoolInfo")[1].get("row"):
            school_data = data["schoolInfo"][1]["row"][0]
            school_info = {
                'code': school_data["SD_SCHUL_CODE"],
                'name': school_data["SCHUL_NM"],
                'region_code': region_code,
                'region_name': next((name for name, code in regions.items() if code == region_code), None)
            }
            # 두 종류의 캐시에 모두 저장
            school_search_cache[cache_key] = school_info
            school_code_to_info_cache[school_info['code']] = school_info
            return school_info
    except requests.exceptions.RequestException as e:
        app.logger.error(f"학교 정보 조회 오류 (Request) for {school_name}: {e}")
    except Exception as e:
        app.logger.error(f"학교 정보 조회 오류 (General) for {school_name}: {e}")
    return None

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
                menu = row["DDISH_NM"].replace("<br/>", "\n").strip()
                meal_type = row["MMEAL_SC_CODE"]

                if meal_type == "1": meals[date_str]["breakfast"] = menu
                elif meal_type == "2": meals[date_str]["lunch"] = menu
                elif meal_type == "3": meals[date_str]["dinner"] = menu

        meal_cache[cache_key] = dict(meals)
        return dict(meals)
    except requests.exceptions.RequestException as e:
        app.logger.error(f"급식 정보 조회 오류 (Request) for {school_code}: {e}")
    return dict(meals)

def get_week_dates():
    today = datetime.now(KST).date()
    start_of_week = today - timedelta(days=(today.weekday() + 1) % 7)
    return [(start_of_week + timedelta(days=i)).strftime('%Y%m%d') for i in range(7)]

def get_month_dates():
    today = datetime.now(KST).date()
    _, last_day = calendar.monthrange(today.year, today.month)
    return [date(today.year, today.month, day).strftime('%Y%m%d') for day in range(1, last_day + 1)]

# --- 템플릿 필터 ---
@app.template_filter('format_date')
def format_date_filter(value):
    try:
        date_obj = datetime.strptime(value, "%Y%m%d")
        day_name = ["월", "화", "수", "목", "금", "토", "일"][date_obj.weekday()]
        return f"{date_obj.strftime('%m월 %d일')} ({day_name})"
    except ValueError:
        return value

# --- 라우트 (Routes) (개선됨) ---
@app.route("/", methods=["GET", "POST"])
def index():
    # POST 요청 (학교 검색)
    if request.method == 'POST':
        region_name = request.form.get('region')
        school_name_input = request.form.get('school_name')
        
        if not region_name or not school_name_input:
            return render_template('school_meal.html', error_message="지역과 학교명을 모두 입력해주세요.", regions=regions)

        region_code = regions.get(region_name)
        if not region_code:
            return render_template('school_meal.html', error_message="유효하지 않은 지역입니다.", regions=regions)

        school_info = get_school_info(school_name_input, region_code)
        if school_info:
            # 검색 성공 시 해당 학교 페이지로 리다이렉트
            return redirect(url_for('school_meal_view', school_code=school_info['code']))
        else:
            return render_template('school_meal.html', error_message="학교를 찾을 수 없습니다. 다시 시도해주세요.", regions=regions, region=region_name, school_name=school_name_input)

    # GET 요청 (메인 페이지)
    # 더 이상 쿠키 기반으로 리다이렉트하지 않음.
    error_message = request.args.get('error_message')
    region_cookie = request.cookies.get('region_name')
    school_name_encoded = request.cookies.get('school_name')
    school_name_cookie = unquote(school_name_encoded) if school_name_encoded else None
    
    return render_template('school_meal.html', regions=regions, error_message=error_message, region=region_cookie, school_name=school_name_cookie)

@app.route("/meal/<school_code>")
def school_meal_view(school_code):
    # 1. 서버 캐시에서 학교 정보 조회
    school_info = school_code_to_info_cache.get(school_code)

    # 2. 캐시에 없으면, 외부 링크로 직접 들어온 경우로 간주하고 처리
    if not school_info:
        # 모든 지역을 순회하며 학교 정보를 탐색 (API 한계로 인한 차선책)
        found = False
        for region_name, region_code in regions.items():
            # 급식 정보 요청을 보내서 응답이 오는지 확인
            meals = get_month_meals(school_code, region_code)
            if any(m != {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"} for m in meals.values()):
                # 급식 정보가 있으면, 해당 지역으로 학교 정보를 다시 조회하여 캐시에 저장
                # 이 때, 학교 이름이 없으므로 임시 이름으로 검색 시도 (한계점)
                # 이 부분은 개선의 여지가 있음. 우선 급식표 표시는 가능.
                # school_info = get_school_info("학교", region_code) # 이름이 없어서 정확한 조회가 어려움
                # 임시로 코드 기반 정보 생성
                school_info = {
                    'code': school_code,
                    'name': f"학교({school_code})", # 이름은 알 수 없으므로 코드로 표시
                    'region_code': region_code,
                    'region_name': region_name
                }
                school_code_to_info_cache[school_code] = school_info
                found = True
                break
        if not found:
             return redirect(url_for('index', error_message=f"학교 코드({school_code})에 대한 정보를 찾을 수 없습니다. 다시 검색해주세요."))

    # 3. 급식 정보 가져오기
    month_meals_data = get_month_meals(school_code, school_info['region_code'])
    week_dates_list = get_week_dates()
    week_meals_data = {date_str: month_meals_data.get(date_str, {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"}) for date_str in week_dates_list}
    month_dates_list = get_month_dates()
    full_month_meals_data = {date_str: month_meals_data.get(date_str, {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"}) for date_str in month_dates_list}
    
    # 4. 동적 타이틀 생성
    title = f"{school_info['name']} 급식 정보 - 급식알리미"

    # 5. 템플릿 렌더링 및 응답 생성
    resp = make_response(render_template(
        'school_meal.html',
        title=title,
        regions=regions,
        school_name=school_info['name'],
        school_code=school_code,
        week_meals=week_meals_data,
        month_meals=full_month_meals_data,
        region=school_info['region_name']
    ))

    # 6. 최신 정보로 쿠키 업데이트
    resp.set_cookie('school_code', school_info['code'], max_age=60*60*24*30, samesite='Lax')
    resp.set_cookie('school_name', quote(school_info['name']), max_age=60*60*24*30, samesite='Lax')
    resp.set_cookie('region_code', school_info['region_code'], max_age=60*60*24*30, samesite='Lax')
    resp.set_cookie('region_name', school_info['region_name'], max_age=60*60*24*30, samesite='Lax')

    return resp

@app.route('/api/meals/<school_code>/<date>')
def get_school_meal_api(school_code, date):
    school_info = school_code_to_info_cache.get(school_code)
    if not school_info:
        return jsonify({"error": "School information not cached. Please search for the school first."}), 404
    
    try:
        month_meals = get_month_meals(school_code, school_info['region_code'])
        meal_data = month_meals.get(date, {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"})
        return jsonify(meal_data)
    except Exception as e:
        app.logger.error(f"API get_school_meal 오류: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/current_time')
def current_time():
    return jsonify({'current_time': datetime.now(KST).isoformat()})

# --- 정적 파일 및 기타 라우트 ---
@app.route('/robots.txt')
def robots_txt(): return send_from_directory(app.static_folder, 'robots.txt')

@app.route('/favicon.svg')
def favicon(): return send_from_directory(app.static_folder, 'favicon.svg')

@app.route('/manifest.json')
def manifest(): return send_from_directory('static', 'manifest.json')

# --- 응답 로깅 (개선됨) ---
@app.after_request
def after_request_func(response):
    # HEAD 요청은 로그 기록에서 제외
    if request.method == 'HEAD':
        return response
    
    # 403 오류는 security.log에만 기록되므로 여기서는 제외
    if response.status_code == 403:
        return response

    # 통합 앱 로그 기록
    log_entry = (
        f"IP: {get_client_ip()} | Status: {response.status_code} | Method: {request.method} | "
        f"Path: {request.path} | UA: {clean_user_agent(request.headers.get('User-Agent', ''))}"
    )
    app.logger.info(log_entry)
    
    return response

# --- 앱 실행 ---
if __name__ == "__main__":
    app.logger.info(f"앱 로그 파일 경로: {APP_LOG_FILE}")
    app.logger.info(f"보안 로그 파일 경로: {SECURITY_LOG_FILE}")
    app.run(debug=False, host='0.0.0.0', port=5000)
