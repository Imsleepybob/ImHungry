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
from functools import wraps

app = Flask(__name__)

# --- 보안 설정 (원본 전체 복구) ---
BLACKLIST_FILE = os.path.join(os.getcwd(), 'ip_blacklist.txt')
SUSPICIOUS_PATTERNS_FILE = os.path.join(os.getcwd(), 'suspicious_patterns.json')
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
    if not os.path.exists(BLACKLIST_FILE): return []
    with open(BLACKLIST_FILE, 'r', encoding='utf-8') as f:
        return [line.split('#', 1)[0].strip() for line in f if line.strip() and not line.startswith('#')]

BLOCKED_NETWORKS = load_ip_blacklist()

def save_to_blacklist(ip_or_cidr, reason="Automatic detection"):
    try:
        with open(BLACKLIST_FILE, 'a', encoding='utf-8') as f:
            f.write(f"{ip_or_cidr}  # {reason} - {datetime.now()}\n")
    except Exception as e:
        app.logger.error(f"Error saving to blacklist: {e}")

# --- 로깅 설정 (요청사항 반영) ---
LOG_DIR = 'logs'
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

APP_LOG_PATH = os.path.join(LOG_DIR, 'app.log')
ERROR_403_LOG_PATH = os.path.join(LOG_DIR, '403_errors.log')
SECURITY_LOG_PATH = os.path.join(LOG_DIR, 'security.log')
NAMUBOARD_LOG_PATH = os.path.join(LOG_DIR, 'namuboard.log') # 원본 유지

def clean_user_agent(ua_string):
    """로그용 User-Agent 정리 함수"""
    if not ua_string: return 'N/A'
    ua = re.sub(r'Mozilla/\d\.\d\s*\(.*?\)\s*', '', ua_string, 1).strip()
    ua = re.sub(r'AppleWebKit/[\d\.]+\s*\(KHTML, like Gecko\)\s*', '', ua).strip()
    return ua if ua else ua_string

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
    
    # 통합 앱 로거 (werkzeug 로그 포함)
    app_logger = logging.getLogger()
    app_logger.setLevel(logging.INFO)
    # 기존 핸들러 제거
    for h in app_logger.handlers[:]: app_logger.removeHandler(h)
        
    app_handler = RotatingFileHandler(APP_LOG_PATH, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
    app_formatter = logging.Formatter('[%(asctime)s] IP: %(ip)s - UA: %(user_agent)s - "%(method)s %(path)s" - Status: %(status)s - %(levelname)s: %(message)s')
    app_handler.setFormatter(app_formatter)
    app_logger.addHandler(app_handler)

setup_loggers()

# --- 보안 관련 함수 (원본 전체 복구) ---
def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
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
    return score >= 10, score, reasons

def log_security_incident(ip, incident_type, details, score=0):
    logging.getLogger('security').warning(f"SECURITY INCIDENT - IP: {ip}, Type: {incident_type}, Score: {score}, Details: {details}")

def auto_block_ip(ip, reason, duration=3600):
    blocked_ips.add(ip)
    log_security_incident(ip, "AUTO_BLOCK", f"{reason} - Duration: {duration}s")
    failed_attempts[ip] += 1
    if failed_attempts[ip] >= SECURITY_CONFIG['failed_attempt_threshold']:
        save_to_blacklist(f"{ip}/32", f"Auto-blocked: {reason}")

@app.before_request
def security_check():
    ip = get_client_ip()
    if is_admin_ip(ip): return
    if is_ip_blocked(ip): abort(403)
    if is_rate_limited(ip):
        log_security_incident(ip, "RATE_LIMIT", "Too many requests")
        auto_block_ip(ip, "Rate limit exceeded", 300)
        abort(429)
    is_suspicious, score, reasons = is_suspicious_request()
    if is_suspicious:
        log_security_incident(ip, "SUSPICIOUS_PATTERN", f"Reasons: {reasons}", score)
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
school_code_cache = {} # 요청사항 반영

# --- 핵심 함수 ---
def get_school_code(school_name, region_code):
    cache_key = f"{region_code}_{school_name}"
    if cache_key in school_cache: return school_cache[cache_key]
    url = "https://open.neis.go.kr/hub/schoolInfo"
    params = {"KEY": API_KEY, "Type": "json", "pIndex": 1, "pSize": 100, "ATPT_OFCDC_SC_CODE": region_code, "SCHUL_NM": school_name}
    try:
        res = requests.get(url, params=params, timeout=5)
        res.raise_for_status()
        data = res.json()
        if "schoolInfo" in data and data.get("schoolInfo")[1].get("row"):
            s_data = data["schoolInfo"][1]["row"][0]
            s_info = {'code': s_data["SD_SCHUL_CODE"], 'name': s_data["SCHUL_NM"], 'region_code': region_code}
            school_cache[cache_key] = s_info
            school_cache[f"{region_code}_{s_info['name']}"] = s_info
            school_code_cache[s_info['code']] = s_info
            return s_info
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error fetching school code: {e}")
    return None

def get_school_info_by_code(school_code):
    return school_code_cache.get(school_code)

def get_month_meals(school_code, region_code):
    month_str = datetime.now(KST).strftime("%Y%m")
    cache_key = f"{region_code}_{school_code}_{month_str}"
    if cache_key in meal_cache: return meal_cache[cache_key]
    url = "https://open.neis.go.kr/hub/mealServiceDietInfo"
    params = {"KEY": API_KEY, "Type": "json", "pIndex": 1, "pSize": 100, "ATPT_OFCDC_SC_CODE": region_code, "SD_SCHUL_CODE": school_code, "MLSV_YMD": month_str}
    meals = defaultdict(lambda: {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"})
    try:
        res = requests.get(url, params=params, timeout=5)
        res.raise_for_status()
        data = res.json()
        if "mealServiceDietInfo" in data and data.get("mealServiceDietInfo")[1].get("row"):
            for row in data["mealServiceDietInfo"][1]["row"]:
                d, m, t = row["MLSV_YMD"], row["DDISH_NM"].replace("<br/>", "\n"), row["MMEAL_SC_CODE"]
                if t == "1": meals[d]["breakfast"] = m
                elif t == "2": meals[d]["lunch"] = m
                elif t == "3": meals[d]["dinner"] = m
        meal_cache[cache_key] = dict(meals)
        return dict(meals)
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error fetching meals: {e}")
    return dict(meals)

@app.template_filter('format_date')
def format_date_filter(value):
    try:
        d = datetime.strptime(value, "%Y%m%d")
        return f"{d.strftime('%Y년 %m월 %d일')} ({'월화수목금토일'[d.weekday()]})"
    except: return value

@app.context_processor
def inject_today_date(): return dict(today_date=datetime.now(KST).strftime("%Y%m%d"))

# --- 라우트 (요청사항 반영) ---
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == 'POST':
        region, school = request.form['region'], request.form['school_name']
        if not region or not school:
            return render_template('school_meal.html', error_message="지역과 학교명을 모두 입력해주세요.", regions=regions)
        region_code = regions.get(region)
        school_info = get_school_code(school, region_code)
        if school_info:
            res = make_response(redirect(url_for('school_meal_view', school_code=school_info['code'])))
            res.set_cookie('school_name', quote(school_info['name']), max_age=30*24*3600, samesite='Lax')
            res.set_cookie('region_name', region, max_age=30*24*3600, samesite='Lax')
            return res
        else:
            return render_template('school_meal.html', error_message="학교를 찾을 수 없습니다.", regions=regions, region=region, school_name=school)
    
    error = request.args.get('error_message')
    s_name = unquote(request.cookies.get('school_name', ''))
    r_name = request.cookies.get('region_name')
    return render_template('school_meal.html', regions=regions, error_message=error, region=r_name, school_name=s_name)

@app.route("/meal/<school_code>")
def school_meal_view(school_code):
    school_info = get_school_info_by_code(school_code)
    if not school_info:
        return redirect(url_for('index', error_message="학교 정보가 만료되었거나 없습니다. 다시 검색해주세요."))
    
    meals_data = get_month_meals(school_code, school_info['region_code'])
    today = datetime.now(KST).date()
    start_of_week = today - timedelta(days=(today.weekday() + 1) % 7)
    week_dates = [(start_of_week + timedelta(i)).strftime('%Y%m%d') for i in range(7)]
    _, last_day = calendar.monthrange(today.year, today.month)
    month_dates = [date(today.year, today.month, d).strftime('%Y%m%d') for d in range(1, last_day + 1)]

    week_meals = {d: meals_data.get(d, {}) for d in week_dates}
    month_meals = {d: meals_data.get(d, {}) for d in month_dates}

    title = f"{school_info['name']} 급식 정보 - ImHungry - 간편한 급식 사이트"
    region_name = next((name for name, code in regions.items() if code == school_info['region_code']), None)

    return render_template('school_meal.html', regions=regions, school_name=school_info['name'],
                           school_code=school_code, week_meals=week_meals, month_meals=month_meals,
                           loading=False, region=region_name, title=title)

@app.route('/api/meals/<school_code>/<date>')
def api_get_meal(school_code, date):
    school_info = get_school_info_by_code(school_code)
    if not school_info: return jsonify({"error": "Unknown school"}), 404
    meals = get_month_meals(school_code, school_info['region_code'])
    return jsonify(meals.get(date, {}))

# --- 기타 라우트 및 로그 뷰어 (원본 복구) ---
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

@app.route('/logs/<log_type>')
def view_logs(log_type):
    if not is_admin_ip(get_client_ip()): abort(403)
    log_map = {'app': APP_LOG_PATH, '403': ERROR_403_LOG_PATH, 'security': SECURITY_LOG_PATH}
    log_file = log_map.get(log_type)
    if not log_file or not os.path.exists(log_file): return "Log not found.", 404
    with open(log_file, 'r', encoding='utf-8') as f: content = f.read()
    return f'<h2>{log_type.upper()} Log</h2><pre>{content}</pre>'

# --- 응답 로깅 (요청사항 반영) ---
@app.after_request
def after_request_logging(response):
    if request.method == 'HEAD':
        return response

    log_extra = {
        'ip': get_client_ip(),
        'user_agent': clean_user_agent(request.headers.get('User-Agent')),
        'method': request.method,
        'path': request.full_path,
        'status': response.status_code
    }
    
    if response.status_code == 403:
        logging.getLogger('403_logger').warning("Forbidden", extra=log_extra)
    else:
        # werkzeug 로그를 캡처하기 위해 info 레벨로 일반 로그 기록
        logging.getLogger().info("Request handled", extra=log_extra)
        
    return response

# --- 앱 실행 (원본 복구) ---
if __name__ == "__main__":
    if not os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, 'w', encoding='utf-8') as f:
            f.write("# IP Blacklist\n")
    
    logging.info(f"Log files located in: {os.path.abspath(LOG_DIR)}")
    app.run(debug=False)

