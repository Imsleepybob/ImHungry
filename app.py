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

# --- 로깅 설정 (개선됨) ---

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
    """로그 용량을 줄이기 위해 User-Agent에서 불필요한 부분을 제거합니다."""
    if not user_agent_string:
        return 'N/A'
    ua = re.sub(r'Mozilla/\d\.\d\s\(.*?\)\s*', '', user_agent_string)
    ua = re.sub(r'AppleWebKit/[\d\.]+\s\(KHTML, like Gecko\)\s*', '', ua)
    ua = re.sub(r'\s+', ' ', ua).strip()
    # 클리닝 후 비어있으면 원본 반환 (짧은 UA 대비)
    return ua if ua else user_agent_string

class UnifiedLogFormatter(logging.Formatter):
    """요청 정보를 로그 메시지에 포함시키는 커스텀 포맷터"""
    def format(self, record):
        record.remote_addr = get_client_ip()
        user_agent_raw = request.headers.get('User-Agent', 'N/A')
        record.user_agent = clean_user_agent(user_agent_raw)
        record.method = request.method
        record.path = request.path
        record.status = getattr(record, 'status', 'N/A')
        record.referrer = request.headers.get('Referer', 'N/A')
        return super().format(record)

def setup_logging():
    # 기본 로거(app.logger) 설정 - 통합 로그용
    app.logger.handlers.clear()
    app.logger.setLevel(logging.INFO)

    # 1. 통합 앱 로그 핸들러 (logs/app.log)
    app_handler = RotatingFileHandler(APP_LOG_PATH, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
    app_formatter = UnifiedLogFormatter('[%(asctime)s] - IP: %(remote_addr)s - UA: %(user_agent)s - "%(method)s %(path)s" - Status: %(status)s - Referrer: "%(referrer)s" - %(levelname)s: %(message)s')
    app_handler.setFormatter(app_formatter)
    app.logger.addHandler(app_handler)

    # 2. 403 에러 로그 핸들러 (logs/403_errors.log)
    error_403_logger = logging.getLogger('error_403')
    if not error_403_logger.handlers:
        error_403_logger.setLevel(logging.WARNING)
        error_403_handler = RotatingFileHandler(ERROR_403_LOG_PATH, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8')
        error_403_formatter = UnifiedLogFormatter('[%(asctime)s] - FORBIDDEN - IP: %(remote_addr)s - UA: "%(user_agent)s" - Method: %(method)s - Path: %(path)s - Referrer: "%(referrer)s"')
        error_403_handler.setFormatter(error_403_formatter)
        error_403_logger.addHandler(error_403_handler)
        error_403_logger.propagate = False
    
    # 3. 보안 사고 로그 (기존과 동일, 경로만 수정)
    security_logger = logging.getLogger('security')
    if not security_logger.handlers:
        security_logger.setLevel(logging.WARNING)
        security_handler = RotatingFileHandler(SECURITY_LOG_PATH, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
        security_handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s'))
        security_logger.addHandler(security_handler)
        security_logger.propagate = False

    # 4. NamuBoard Extension 로그 (기존과 동일, 경로만 수정)
    namuboard_logger = logging.getLogger('namuboard')
    if not namuboard_logger.handlers:
        namuboard_logger.setLevel(logging.INFO)
        namuboard_handler = RotatingFileHandler(NAMUBOARD_LOG_PATH, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8')
        namuboard_formatter = UnifiedLogFormatter('[%(asctime)s] - IP: %(remote_addr)s - UA: %(user_agent)s - Referrer: "%(referrer)s"')
        namuboard_handler.setFormatter(namuboard_formatter)
        namuboard_logger.addHandler(namuboard_handler)
        namuboard_logger.propagate = False

setup_logging()

# --- 보안 함수 (기존과 거의 동일) ---
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
    if is_ip_blocked(client_ip):
        logging.getLogger('security').warning(f"SECURITY INCIDENT - IP: {client_ip}, Type: BLOCKED_IP")
        abort(403)
    # ... (다른 보안 검사들은 생략, 기존 코드와 동일하게 유지)

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
    cache_key = f"{region_code}_{school_name}"
    if cache_key in school_cache:
        return school_cache[cache_key]

    url = "https://open.neis.go.kr/hub/schoolInfo"
    params = {"KEY": API_KEY, "Type": "json", "pIndex": 1, "pSize": 100, "ATPT_OFCDC_SC_CODE": region_code, "SCHUL_NM": school_name}
    try:
        response = requests.get(url, params=params, timeout=5)
        response.raise_for_status()
        data = response.json()

        if "schoolInfo" in data and data.get("schoolInfo")[1].get("row"):
            school_data = data["schoolInfo"][1]["row"][0]
            school_info = {
                'code': school_data["SD_SCHUL_CODE"],
                'name': school_data["SCHUL_NM"],
                'region_code': region_code
            }
            # 캐시 저장 (2종류)
            school_cache[cache_key] = school_info
            school_cache[f"{region_code}_{school_info['name']}"] = school_info
            school_code_cache[school_info['code']] = school_info
            return school_info
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error fetching school code (Request) for {school_name}: {e}")
    return None

def get_month_meals(school_code, region_code):
    month_str = datetime.now(KST).strftime("%Y%m")
    cache_key = f"{region_code}_{school_code}_{month_str}"
    if cache_key in meal_cache:
        return meal_cache[cache_key]

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
        app.logger.error(f"Error fetching meals (Request) for {school_code}: {e}")
    return dict(meals)

# --- 템플릿 필터 및 컨텍스트 프로세서 ---
@app.template_filter('format_date')
def format_date_filter(value):
    try:
        date_obj = datetime.strptime(value, "%Y%m%d")
        day_name = '월화수목금토일'[date_obj.weekday()]
        return f"{date_obj.strftime('%m월 %d일')} ({day_name})"
    except:
        return value

# --- 라우트 (Routes) ---
@app.route("/", methods=["GET", "POST"])
def index():
    # POST 요청 (학교 검색)
    if request.method == 'POST':
        region_name = request.form['region']
        school_name_input = request.form['school_name']
        region_code = regions.get(region_name)

        if not region_code or not school_name_input:
            return render_template('school_meal.html', error_message="지역과 학교명을 모두 입력해주세요.", regions=regions), 400

        school_info = get_school_code(school_name_input, region_code)
        if school_info:
            return redirect(url_for('school_meal_view', school_code=school_info['code']))
        else:
            return render_template('school_meal.html', error_message="학교를 찾을 수 없습니다.", regions=regions, region=region_name, school_name=school_name_input)

    # GET 요청 (메인 페이지)
    error_message = request.args.get('error_message')
    region_cookie = request.cookies.get('region_name')
    school_name_encoded = request.cookies.get('school_name')
    school_name_cookie = unquote(school_name_encoded) if school_name_encoded else None
    
    return render_template('school_meal.html', regions=regions, error_message=error_message, region=region_cookie, school_name=school_name_cookie)

@app.route("/meal/<school_code>")
def school_meal_view(school_code):
    # URL의 school_code를 기준으로 캐시에서 학교 정보 조회
    school_info = school_code_cache.get(school_code)

    if not school_info:
        # 캐시에 없으면 사용자가 다시 검색하도록 유도
        return redirect(url_for('index', error_message="학교 정보를 찾을 수 없습니다. 다시 검색해주세요."))

    # 급식 정보 가져오기
    month_meals_data = get_month_meals(school_code, school_info['region_code'])
    
    today = datetime.now(KST).date()
    start_of_week = today - timedelta(days=(today.weekday() + 1) % 7) # 일요일 시작
    week_dates_list = [(start_of_week + timedelta(days=i)).strftime('%Y%m%d') for i in range(7)]
    
    _, last_day = calendar.monthrange(today.year, today.month)
    month_dates_list = [date(today.year, today.month, day).strftime('%Y%m%d') for day in range(1, last_day + 1)]
    
    week_meals = {d: month_meals_data.get(d, {}) for d in week_dates_list}
    month_meals = {d: month_meals_data.get(d, {}) for d in month_dates_list}

    # 동적 타이틀 생성
    title = f"{school_info['name']} 급식 정보 - 급식알리미"
    
    resp = make_response(render_template(
        'school_meal.html',
        regions=regions,
        school_name=school_info['name'],
        school_code=school_code,
        week_meals=week_meals,
        month_meals=month_meals,
        title=title
    ))

    # 현재 페이지에 맞는 정보로 쿠키 설정/갱신
    region_name = next((name for name, code in regions.items() if code == school_info['region_code']), None)
    resp.set_cookie('school_code', school_info['code'], max_age=30*24*60*60, samesite='Lax')
    resp.set_cookie('school_name', quote(school_info['name']), max_age=30*24*60*60, samesite='Lax')
    resp.set_cookie('region_code', school_info['region_code'], max_age=30*24*60*60, samesite='Lax')
    if region_name:
        resp.set_cookie('region_name', region_name, max_age=30*24*60*60, samesite='Lax')

    return resp

@app.route('/api/meals/<school_code>/<date>')
def get_school_meal_api(school_code, date):
    """API: 특정 학교, 특정 날짜의 급식 정보를 반환합니다."""
    school_info = school_code_cache.get(school_code)
    if not school_info:
        return jsonify({"error": "Unknown school code"}), 404

    try:
        month_meals = get_month_meals(school_code, school_info['region_code'])
        meal_data = month_meals.get(date, {})
        return jsonify(meal_data)
    except Exception as e:
        app.logger.error(f"Error in get_school_meal API: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/current_time')
def current_time_api():
    return jsonify({'current_time': datetime.now(KST).isoformat()})

# --- 정적 파일 및 기타 라우트 ---
@app.route('/robots.txt')
def robots_txt(): return send_from_directory(app.static_folder, 'robots.txt')
@app.route('/favicon.svg')
def favicon(): return send_from_directory(app.static_folder, 'favicon.svg')
@app.route('/favicon.ico')
def favicon_ico(): return send_from_directory(app.static_folder, 'favicon.svg')
@app.route('/manifest.json')
def manifest(): return send_from_directory('static', 'manifest.json')
@app.route('/namuboardextension.user.js')
def serve_tampermonkey_script():
    logging.getLogger('namuboard').info('NamuBoard Extension Access')
    return send_from_directory(app.root_path, 'namuboardextension.user.js', mimetype='application/javascript')

# --- 로그 확인용 엔드포인트 (관리자용) ---
def check_admin_or_debug():
    client_ip = get_client_ip()
    if not (is_admin_ip(client_ip) or (app.debug and os.environ.get('ENABLE_LOG_VIEW') == 'true')):
        abort(403)

@app.route('/logs/<log_name>')
def view_logs(log_name):
    check_admin_or_debug()
    log_paths = {
        'app': APP_LOG_PATH,
        'security': SECURITY_LOG_PATH,
        'namuboard': NAMUBOARD_LOG_PATH,
        '403': ERROR_403_LOG_PATH
    }
    log_path = log_paths.get(log_name)
    if not log_path or not os.path.exists(log_path):
        return "Log not found.", 404
    with open(log_path, 'r', encoding='utf-8') as f:
        content = f.read()
    return f'<h2>{log_name.capitalize()} Log</h2><pre>{content}</pre>'

# --- 응답 로깅 ---
@app.after_request
def log_request(response):
    # HEAD 요청은 기록하지 않음
    if request.method == 'HEAD':
        return response

    # 403 응답은 별도 로그 파일에 기록하고, 일반 로그에서는 제외
    if response.status_code == 403:
        logging.getLogger('error_403').warning("Forbidden access triggered.")
        # 403 응답은 일반 로그에 기록되지 않음
        return response

    # 그 외 성공/오류 요청은 app.log에 기록
    log_level = app.logger.warning if response.status_code >= 400 else app.logger.info
    log_level("Request processed", extra={'status': response.status_code})
    
    return response

# --- 앱 실행 ---
if __name__ == "__main__":
    app.logger.info("Application starting...")
    app.logger.info(f"Log directory: {os.path.abspath(LOG_DIR)}")
    app.run(debug=False)
