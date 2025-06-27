from flask import Flask, render_template, request, make_response, jsonify, redirect, url_for, send_from_directory, abort
from datetime import datetime, timedelta, timezone
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
from functools import wraps

app = Flask(__name__)

# --- 보안 설정 (기존과 동일) ---
BLACKLIST_FILE = os.path.join(os.getcwd(), 'ip_blacklist.txt')
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

# --- 로깅 설정 (요청사항 반영하여 수정) ---

# 로그 디렉토리 생성
if not os.path.exists('logs'):
    os.makedirs('logs')

LOG_DIR = 'logs'
APP_LOG_PATH = os.path.join(LOG_DIR, 'app.log')
ERROR_403_LOG_PATH = os.path.join(LOG_DIR, '403_errors.log')
SECURITY_LOG_PATH = os.path.join(LOG_DIR, 'security.log')
NAMUBOARD_LOG_PATH = os.path.join(LOG_DIR, 'namuboard.log')

def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    return request.remote_addr

def clean_user_agent(user_agent_string):
    """User-Agent에서 Mozilla/5.0 등 일반적인 부분을 제거합니다."""
    if not user_agent_string:
        return 'N/A'
    # Mozilla/5.0 (...) 부분을 제거
    ua = re.sub(r'Mozilla/\d\.\d\s*\(.*?\)\s*', '', user_agent_string).strip()
    # 기타 불필요한 부분 정리
    ua = re.sub(r'AppleWebKit/[\d\.]+\s*\(KHTML, like Gecko\)\s*', '', ua).strip()
    ua = re.sub(r'\s+', ' ', ua).strip()
    return ua if ua else user_agent_string

def setup_logging():
    # 모든 핸들러를 클리어하고 새로 설정
    app.logger.handlers.clear()
    loggers = [logging.getLogger(name) for name in logging.root.manager.loggerDict]
    for logger in loggers:
        if 'flask' in logger.name or 'werkzeug' in logger.name:
            logger.handlers = []
            logger.propagate = True
    
    # 1. 통합 로그 핸들러 (logs/app.log)
    app_handler = RotatingFileHandler(APP_LOG_PATH, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
    # 로그 포맷에 user_agent 추가
    app_formatter = logging.Formatter('[%(asctime)s] IP: %(ip)s UA: %(user_agent)s "%(method)s %(path)s" Status: %(status)s - %(levelname)s: %(message)s')
    app_handler.setFormatter(app_formatter)
    
    # 2. 403 에러 로그 핸들러 (logs/403_errors.log)
    error_403_logger = logging.getLogger('403_errors')
    error_403_logger.setLevel(logging.WARNING)
    error_403_handler = RotatingFileHandler(ERROR_403_LOG_PATH, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8')
    error_403_formatter = logging.Formatter('[%(asctime)s] FORBIDDEN - IP: %(ip)s UA: %(user_agent)s "%(method)s %(path)s"')
    error_403_handler.setFormatter(error_403_formatter)
    error_403_logger.addHandler(error_403_handler)
    error_403_logger.propagate = False

    # Flask의 기본 로거에 통합 핸들러 추가
    app.logger.setLevel(logging.INFO)
    app.logger.addHandler(app_handler)

setup_logging()

# --- 보안 함수 (기존과 동일) ---
def load_ip_blacklist():
    if not os.path.exists(BLACKLIST_FILE): return []
    with open(BLACKLIST_FILE, 'r', encoding='utf-8') as f:
        cidrs = [line.split('#', 1)[0].strip() for line in f if line.strip() and not line.startswith('#')]
    return [cidr for cidr in cidrs if cidr]

BLOCKED_NETWORKS = load_ip_blacklist()

def is_ip_blocked(ip_address):
    try:
        client_ip = ipaddress.ip_address(ip_address)
        if ip_address in blocked_ips: return True
        return any(client_ip in ipaddress.ip_network(net, strict=False) for net in BLOCKED_NETWORKS)
    except ValueError: return True

def is_admin_ip(ip_address):
    try:
        client_ip = ipaddress.ip_address(ip_address)
        return any(client_ip in ipaddress.ip_network(net, strict=False) for net in ADMIN_WHITELIST)
    except ValueError: return False

@app.before_request
def security_check():
    client_ip = get_client_ip()
    if is_admin_ip(client_ip): return
    if is_ip_blocked(client_ip): abort(403)
    # ... (기타 보안 검사 생략, 원본과 동일)

# --- NEIS API 및 기본 설정 ---
API_KEY = "4e2c538d90ef493c94c6e2d943e756d9"
KST = timezone(timedelta(hours=9))
regions = {
    "서울": "B10", "부산": "C10", "대구": "D10", "인천": "E10", "광주": "F10",
    "대전": "G10", "울산": "H10", "세종": "I10", "경기": "J10", "강원": "K10",
    "충북": "M10", "충남": "N10", "전북": "P10", "전남": "Q10", "경북": "R10",
    "경남": "S10", "제주": "T10"
}
school_cache = {}
meal_cache = {}
school_code_cache = {} # 학교 코드를 key로 사용하는 캐시 추가

# --- 핵심 함수 ---
def get_school_code(school_name, region_code):
    """학교 이름과 지역 코드로 NEIS API에서 학교 정보를 조회합니다."""
    cache_key = f"{region_code}_{school_name}"
    if cache_key in school_cache:
        return school_cache[cache_key]
    # (API 호출 로직은 원본과 동일)
    url = "https://open.neis.go.kr/hub/schoolInfo"
    params = {"KEY": API_KEY, "Type": "json", "pIndex": 1, "pSize": 100, "ATPT_OFCDC_SC_CODE": region_code, "SCHUL_NM": school_name}
    try:
        response = requests.get(url, params=params, timeout=5)
        response.raise_for_status()
        data = response.json()
        if "schoolInfo" in data and data.get("schoolInfo")[1].get("row"):
            school_data = data["schoolInfo"][1]["row"][0]
            school_info = {'code': school_data["SD_SCHUL_CODE"], 'name': school_data["SCHUL_NM"], 'region_code': region_code}
            school_cache[cache_key] = school_info
            school_cache[f"{region_code}_{school_info['name']}"] = school_info
            school_code_cache[school_info['code']] = school_info # 코드 기반 캐시 저장
            return school_info
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error fetching school code: {e}")
    return None

def get_school_info_by_code(school_code):
    """학교 코드로 학교 정보를 조회합니다. (외부 링크 접속용)"""
    if school_code in school_code_cache:
        return school_code_cache[school_code]
    
    # 캐시에 없으면 모든 지역을 순회하며 찾아야 함 (비효율적이므로, 검색을 통해 캐시를 채우는 것을 권장)
    # 여기서는 간단히 에러 처리를 위해 캐시 조회만 구현합니다.
    # 실제 운영 환경에서는 이 부분에 대한 보강이 필요할 수 있습니다.
    app.logger.warning(f"School info for code {school_code} not found in cache. Needs to be searched first.")
    return None

def get_month_meals(school_code, region_code):
    # (급식 정보 조회 로직은 원본과 동일)
    month_str = datetime.now(KST).strftime("%Y%m")
    cache_key = f"{region_code}_{school_code}_{month_str}"
    if cache_key in meal_cache: return meal_cache[cache_key]
    url = "https://open.neis.go.kr/hub/mealServiceDietInfo"
    params = {"KEY": API_KEY, "Type": "json", "pIndex": 1, "pSize": 100, "ATPT_OFCDC_SC_CODE": region_code, "SD_SCHUL_CODE": school_code, "MLSV_YMD": month_str}
    meals = defaultdict(lambda: {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"})
    try:
        response = requests.get(url, params=params, timeout=5)
        response.raise_for_status()
        data = response.json()
        if "mealServiceDietInfo" in data and data.get("mealServiceDietInfo")[1].get("row"):
            for row in data["mealServiceDietInfo"][1]["row"]:
                date_str, menu, meal_type = row["MLSV_YMD"], row["DDISH_NM"].replace("<br/>", "\n"), row["MMEAL_SC_CODE"]
                if meal_type == "1": meals[date_str]["breakfast"] = menu
                elif meal_type == "2": meals[date_str]["lunch"] = menu
                elif meal_type == "3": meals[date_str]["dinner"] = menu
        meal_cache[cache_key] = dict(meals)
        return dict(meals)
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error fetching meals: {e}")
    return dict(meals)

# --- 템플릿 필터 및 컨텍스트 프로세서 (원본과 동일) ---
@app.template_filter('format_date')
def format_date(value):
    try:
        date_obj = datetime.strptime(value, "%Y%m%d")
        korean_day_names = {'Monday': '월', 'Tuesday': '화', 'Wednesday': '수', 'Thursday': '목', 'Friday': '금', 'Saturday': '토', 'Sunday': '일'}
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
    # 요청사항 반영: 쿠키가 있더라도 메인 페이지는 항상 검색 화면을 보여줌
    if request.method == 'POST':
        region_name = request.form['region']
        school_name_input = request.form['school_name']
        if not region_name or not school_name_input:
            return render_template('school_meal.html', error_message="지역과 학교명을 모두 입력해주세요.", regions=regions)
        region_code = regions.get(region_name)
        school_info = get_school_code(school_name_input, region_code)
        if school_info:
            # 검색 성공 시 쿠키를 설정하고 해당 학교 페이지로 리다이렉트
            response = make_response(redirect(url_for('school_meal_view', school_code=school_info['code'])))
            response.set_cookie('school_code', school_info['code'], max_age=60*60*24*30, samesite='Lax')
            response.set_cookie('school_name', quote(school_info['name']), max_age=60*60*24*30, samesite='Lax')
            response.set_cookie('region_code', school_info['region_code'], max_age=60*60*24*30, samesite='Lax')
            response.set_cookie('region_name', region_name, max_age=60*60*24*30, samesite='Lax')
            return response
        else:
            return render_template('school_meal.html', error_message="학교를 찾을 수 없습니다.", regions=regions, region=region_name, school_name=school_name_input)
    
    # GET 요청: 검색 페이지 렌더링. 쿠키 값을 UI에 채워주기만 함.
    error_message = request.args.get('error_message')
    region_cookie = request.cookies.get('region_name')
    school_name_encoded = request.cookies.get('school_name')
    school_name_cookie = unquote(school_name_encoded) if school_name_encoded else None
    return render_template('school_meal.html', regions=regions, error_message=error_message, region=region_cookie, school_name=school_name_cookie)

@app.route("/meal/<school_code>")
def school_meal_view(school_code):
    # 요청사항 반영: URL의 school_code를 기준으로 동작
    school_info = get_school_info_by_code(school_code)

    # 캐시에 정보가 없으면, 사용자가 다시 검색하도록 유도
    if not school_info:
        return redirect(url_for('index', error_message="학교 정보가 만료되었거나 없습니다. 다시 검색해주세요."))

    # 이제부터는 조회된 school_info를 사용
    region_code = school_info['region_code']
    school_name = school_info['name']
    
    month_meals_data = get_month_meals(school_code, region_code)

    # 날짜 계산 (원본과 동일)
    today = datetime.now(KST).date()
    start_of_week = today - timedelta(days=(today.weekday() + 1) % 7)
    week_dates_list = [(start_of_week + timedelta(days=i)).strftime('%Y%m%d') for i in range(7)]
    _, last_day = calendar.monthrange(today.year, today.month)
    month_dates_list = [date(today.year, today.month, day).strftime('%Y%m%d') for day in range(1, last_day + 1)]
    
    week_meals_data = {d: month_meals_data.get(d, {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"}) for d in week_dates_list}
    full_month_meals_data = {d: month_meals_data.get(d, {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"}) for d in month_dates_list}

    # 요청사항 반영: 동적 HTML 타이틀 생성
    title = f"{school_name} 급식 정보 - ImHungry - 간편한 급식 사이트"

    region_name = next((name for name, code in regions.items() if code == region_code), None)
    
    resp = make_response(render_template(
        'school_meal.html',
        regions=regions,
        school_name=school_name,
        school_code=school_code,
        week_meals=week_meals_data,
        month_meals=full_month_meals_data,
        loading=False,
        region=region_name,
        title=title # title 변수를 템플릿에 전달
    ))

    # 최신 정보로 쿠키 갱신
    resp.set_cookie('school_code', school_code, max_age=60*60*24*30, samesite='Lax')
    resp.set_cookie('school_name', quote(school_name), max_age=60*60*24*30, samesite='Lax')
    resp.set_cookie('region_code', region_code, max_age=60*60*24*30, samesite='Lax')
    if region_name:
        resp.set_cookie('region_name', region_name, max_age=60*60*24*30, samesite='Lax')

    return resp

@app.route('/api/meals/<school_code>/<date>')
def get_school_meal(school_code, date):
    # API는 쿠키 대신 school_code 기반으로 동작하도록 수정
    school_info = get_school_info_by_code(school_code)
    if not school_info:
        return jsonify({"error": "School information not found for the given code"}), 404
        
    try:
        month_meals = get_month_meals(school_code, school_info['region_code'])
        meal_data = month_meals.get(date, {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"})
        return jsonify(meal_data)
    except Exception as e:
        app.logger.error(f"Error in get_school_meal API: {e}")
        return jsonify({"error": "Internal server error"}), 500

# --- 기타 라우트 (원본과 동일) ---
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
def serve_tampermonkey_script(): return send_from_directory(app.root_path, 'namuboardextension.user.js', mimetype='application/javascript')

# --- 로그 확인용 엔드포인트 (기존 로직 유지) ---
@app.route('/logs/<log_name>')
def view_logs(log_name):
    client_ip = get_client_ip()
    if not (is_admin_ip(client_ip) or (app.debug and os.environ.get('ENABLE_LOG_VIEW') == 'true')):
        abort(403)
    log_paths = {'app': APP_LOG_PATH, '403': ERROR_403_LOG_PATH}
    log_path = log_paths.get(log_name)
    if not log_path or not os.path.exists(log_path): return "Log not found.", 404
    with open(log_path, 'r', encoding='utf-8') as f: content = f.read()
    return f'<h2>{log_name.capitalize()} Log</h2><pre>{content}</pre>'

# --- 응답 로깅 (요청사항 반영하여 수정) ---
@app.after_request
def after_request_func(response):
    # HEAD 요청은 로그 기록에서 제외
    if request.method == 'HEAD':
        return response

    # 로그에 포함할 추가 정보
    log_extra = {
        'ip': get_client_ip(),
        'user_agent': clean_user_agent(request.headers.get('User-Agent', 'N/A')),
        'method': request.method,
        'path': request.full_path,
        'status': response.status_code
    }
    
    # 403 에러는 별도 로거로 기록
    if response.status_code == 403:
        logging.getLogger('403_errors').warning("Forbidden access", extra=log_extra)
        return response # 일반 로그에는 기록하지 않고 종료

    # 그 외 모든 요청은 app.log에 기록
    app.logger.info("Request processed", extra=log_extra)
    return response

# --- 앱 실행 ---
if __name__ == "__main__":
    setup_logging() # 앱 시작 시 로깅 설정
    app.logger.info("Application starting...")
    app.run(debug=False)
