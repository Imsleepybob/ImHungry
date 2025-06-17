from flask import Flask, render_template, request, send_file, make_response, jsonify, redirect, url_for, send_from_directory
from datetime import datetime, timedelta, date, timezone
from collections import defaultdict
import calendar
import requests
import logging
from logging.handlers import RotatingFileHandler
import ipaddress
from urllib.parse import quote, unquote

app = Flask(__name__)

# --- IP 차단 설정 ---
BLOCKED_NETWORKS = [
    '2a06:98c0:3600::/48',
    # 추가적인 차단할 네트워크 대역 입력 가능
]

def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    elif request.access_route:
        return request.access_route[0]
    else:
        return request.remote_addr

def is_ip_blocked(ip_address):
    try:
        client_ip = ipaddress.ip_address(ip_address)
        for blocked_network in BLOCKED_NETWORKS:
            network = ipaddress.ip_network(blocked_network, strict=False)
            if client_ip in network:
                return True
        return False
    except ValueError:
        app.logger.error(f"Invalid IP address detected: {ip_address}")
        return False

@app.before_request
def block_method():
    client_ip = get_client_ip()
    # app.logger.info(f"Client IP detected: {client_ip}") # 너무 많은 로그를 생성할 수 있으므로 필요시 주석 해제
    if is_ip_blocked(client_ip):
        app.logger.warning(f"Blocked access attempt from IP: {client_ip}")
        return 'Access Denied', 403

# --- 로깅 설정 ---
def setup_logging():
    # 기본 로거 설정
    logging.basicConfig(level=logging.INFO)
    # 파일 핸들러 설정 (앱 로그)
    handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=3, encoding='utf-8')
    handler.setFormatter(logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
    ))
    # IP 차단 로그 핸들러
    ip_handler = logging.FileHandler('ip_block.log', encoding='utf-8')
    ip_handler.setLevel(logging.WARNING)
    ip_handler.setFormatter(logging.Formatter(
         '[%(asctime)s] %(levelname)s: %(message)s'
    ))

    # 앱 로거 가져오기 및 핸들러 추가
    logger = logging.getLogger(__name__)
    logger.addHandler(handler)
    logger.addHandler(ip_handler)
    app.logger.addHandler(handler) # Flask 기본 로거에도 추가
    app.logger.addHandler(ip_handler)

setup_logging()

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

# --- 핵심 함수 ---
def get_school_code(school_name, region_code):
    """학교 이름과 지역 코드로 NEIS API에서 학교 코드와 전체 이름을 조회합니다."""
    cache_key = f"{region_code}_{school_name}"
    if cache_key in school_cache:
        return school_cache[cache_key]

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
            school_cache[cache_key] = {
                'code': school_code_val,
                'name': full_school_name,
                'region_code': region_code
            }
            # 입력 이름과 다른 경우에도 캐시 (예: 양정고 -> 양정고등학교)
            school_cache[f"{region_code}_{full_school_name}"] = school_cache[cache_key]
            return school_cache[cache_key]
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error fetching school code (Request) for {school_name}: {e}")
    except Exception as e:
        app.logger.error(f"Error fetching school code (General) for {school_name}: {e}")
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

# --- 라우트 (Routes) ---
@app.route("/", methods=["GET", "POST"])
def index():
    error_message = request.args.get('error_message')
    region_cookie = request.cookies.get('region_name')
    school_name_encoded = request.cookies.get('school_name')
    school_name_cookie = unquote(school_name_encoded) if school_name_encoded else None

    if request.method == 'GET':
        school_code = request.cookies.get('school_code')
        if school_code and school_name_cookie:
            app.logger.info(f"Redirecting to saved school: {school_name_cookie} ({school_code})")
            return redirect(url_for('school_meal_view', school_code=school_code))

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
            response.set_cookie('school_code', school_info['code'], max_age=60*60*24*30)
            response.set_cookie('school_name', quote(school_info['name']), max_age=60*60*24*30)
            response.set_cookie('region_code', school_info['region_code'], max_age=60*60*24*30)
            response.set_cookie('region_name', region_name, max_age=60*60*24*30)
            return response
        else:
            return render_template('school_meal.html', error_message="학교를 찾을 수 없습니다.", regions=regions, region=region_name, school_name=school_name_input)

    return render_template('school_meal.html', regions=regions, error_message=error_message, region=region_cookie, school_name=school_name_cookie)

@app.route("/meal/<school_code>")
def school_meal_view(school_code):
    school_name_encoded = request.cookies.get('school_name')
    region_code = request.cookies.get('region_code')

    if not school_name_encoded or not region_code:
        return redirect(url_for('index', error_message="학교 정보가 만료되었거나 없습니다. 다시 검색해주세요."))

    school_name = unquote(school_name_encoded)
    school_info = None

    # 캐시에서 먼저 찾아보기
    for info in school_cache.values():
        if info.get('code') == school_code:
            school_info = info
            break

    # 캐시에 없으면 API 호출 시도
    if not school_info:
        school_info = get_school_code(school_name, region_code)

    # API 호출도 실패하면 쿠키 정보로 최소 구성
    if not school_info:
        school_info = {'code': school_code, 'name': school_name, 'region_code': region_code}
        app.logger.warning(f"Using fallback school info for {school_code}")

    month_meals_data = get_month_meals(school_code, school_info['region_code'])
    week_dates_list = get_week_dates()
    week_meals_data = {date_str: month_meals_data.get(date_str, {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"}) for date_str in week_dates_list}
    month_dates_list = get_month_dates()
    full_month_meals_data = {date_str: month_meals_data.get(date_str, {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"}) for date_str in month_dates_list}

    resp = make_response(render_template(
        'school_meal.html',
        regions=regions,
        school_name=school_info['name'],
        school_code=school_code,
        week_meals=week_meals_data,
        month_meals=full_month_meals_data,
        loading=False,
        region=next((name for name, code in regions.items() if code == school_info['region_code']), None)
    ))

    # 쿠키 갱신 (인코딩)
    resp.set_cookie('school_code', school_info['code'], max_age=60*60*24*30)
    resp.set_cookie('school_name', quote(school_info['name']), max_age=60*60*24*30)
    resp.set_cookie('region_code', school_info['region_code'], max_age=60*60*24*30)
    region_name_cookie = request.cookies.get('region_name')
    if region_name_cookie:
        resp.set_cookie('region_name', region_name_cookie, max_age=60*60*24*30)

    return resp

@app.route('/api/meals/<school_code>/<date>')
def get_school_meal(school_code, date):
    """API: 특정 학교, 특정 날짜의 급식 정보를 반환합니다."""
    region_code = request.cookies.get('region_code') # 알림용 API이므로 쿠키에 의존
    if not region_code:
        return jsonify({"error": "Region code missing in cookies"}), 400

    try:
        month_meals = get_month_meals(school_code, region_code)
        meal_data = month_meals.get(date, {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"})
        return jsonify(meal_data)
    except Exception as e:
        app.logger.error(f"Error in get_school_meal API: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/current_time')
def current_time():
    """KST 기준 현재 시간을 반환합니다."""
    return jsonify({'current_time': datetime.now(KST).isoformat()})

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

# --- 응답 로깅 ---
@app.after_request
def after_request_func(response):
    log_entry = (
        f"IP: {get_client_ip()}, "
        f"Method: {request.method}, "
        f"URL: {request.url}, "
        f"Status: {response.status_code}"
        # f"User-Agent: {request.user_agent.string}" # 너무 길면 주석 처리
    )
    app.logger.info(log_entry)
    return response

STATIC_DIR = os.path.join(app.root_path, 'static')

@app.route('/namuboardsharebutton-user.js')
def serve_tampermonkey_script():
    try:
        return send_from_directory(STATIC_DIR, 'namuboardsharebutton-user.js', mimetype='application/javascript')
    except FileNotFoundError:
        return "스크립트 파일을 찾을 수 없습니다.", 404
    except Exception as e:
        print(f"Error serving script: {e}")
        return "스크립트를 제공하는 중 오류가 발생했습니다.", 500

# --- 앱 실행 ---
if __name__ == "__main__":
    app.run(debug=True) # 개발 시에는 True, 배포 시에는 False 및 WSGI 서버 사용
