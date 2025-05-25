from flask import Flask, render_template, request, send_file, make_response, jsonify, redirect, url_for, send_from_directory
from datetime import datetime, timedelta, date, timezone # timezone 추가
from collections import defaultdict
import calendar
import requests
import logging
from logging.handlers import RotatingFileHandler
import ipaddress

app = Flask(__name__)

# CIDR 형식의 IP 대역 정의
BLOCKED_NETWORKS = [
    '2a06:98c0:3600::/48',
    # 추가적인 차단할 네트워크 대역 입력 가능
]

def get_client_ip():
    """
    클라이언트의 실제 IP 주소를 반환합니다.
    X-Forwarded-For 헤더를 우선으로 사용합니다.
    """
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    elif request.access_route:
        return request.access_route[0]
    else:
        return request.remote_addr


def is_ip_blocked(ip_address):
    """
    요청 IP가 차단된 네트워크 대역에 속하는지 확인합니다.
    """
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
    app.logger.info(f"Client IP detected: {client_ip}")
    if is_ip_blocked(client_ip):
        app.logger.warning(f"Blocked access attempt from IP: {client_ip}")
        return 'Access Denied', 403

def setup_logging():
    handler = logging.FileHandler('ip_block.log')
    handler.setLevel(logging.WARNING)
    app.logger.addHandler(handler)

setup_logging()

logging.basicConfig(level=logging.INFO)
handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=3)
handler.setFormatter(logging.Formatter(
    '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
))
logger = logging.getLogger(__name__)
logger.addHandler(handler)

API_KEY = "4e2c538d90ef493c94c6e2d943e756d9"

regions = {
    "서울": "B10", "부산": "C10", "대구": "D10", "인천": "E10", "광주": "F10",
    "대전": "G10", "울산": "H10", "세종": "I10", "경기": "J10", "강원": "K10",
    "충북": "M10", "충남": "N10", "전북": "P10", "전남": "Q10", "경북": "R10",
    "경남": "S10", "제주": "T10"
}

school_cache = {}
meal_cache = {}

# KST 시간대 정의 (UTC+9)
KST = timezone(timedelta(hours=9))

def get_school_code(school_name, region_code):
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
        response.raise_for_status() # HTTP 오류 발생 시 예외 발생
        data = response.json()

        if "schoolInfo" in data and data["schoolInfo"][1]["row"]:
            school_data = data["schoolInfo"][1]["row"][0]
            school_code = school_data["SD_SCHUL_CODE"]
            school_cache[cache_key] = {
                'code': school_code,
                'name': school_data["SCHUL_NM"],
                'region_code': region_code
            }
            return school_cache[cache_key]
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching school code (Request): {e}")
    except Exception as e:
        logger.error(f"Error fetching school code (General): {e}")
    return None

def get_month_dates():
    today = datetime.now(KST).date() # KST 기준
    _, last_day = calendar.monthrange(today.year, today.month)
    return [(date(today.year, today.month, day)).strftime('%Y%m%d') for day in range(1, last_day + 1)]

def get_week_dates():
    today = datetime.now(KST).date() # KST 기준
    # 일요일(6)이 주의 시작이 되도록 계산 (today.weekday() 월요일=0, ..., 일요일=6)
    start_of_week = today - timedelta(days=(today.weekday() + 1) % 7)
    dates = [(start_of_week + timedelta(days=i)).strftime('%Y%m%d') for i in range(7)]
    return dates

def get_month_meals(school_code, region_code):
    today = datetime.now(KST) # KST 기준
    month_str = today.strftime("%Y%m")
    cache_key = f"{region_code}_{school_code}_{month_str}"

    if cache_key in meal_cache:
        return meal_cache[cache_key]

    url = "https://open.neis.go.kr/hub/mealServiceDietInfo"
    params = {
        "KEY": API_KEY, "Type": "json", "pIndex": 1, "pSize": 100,
        "ATPT_OFCDC_SC_CODE": region_code, "SD_SCHUL_CODE": school_code,
        "MLSV_YMD": month_str # 해당 월 전체 조회
    }

    try:
        response = requests.get(url, params=params, timeout=5)
        response.raise_for_status()
        data = response.json()

        meals = defaultdict(lambda: {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"})

        if "mealServiceDietInfo" in data:
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
        logger.error(f"Error fetching meals (Request): {e}")
    except Exception as e:
        logger.error(f"Error fetching meals (General): {e}")
    return defaultdict(lambda: {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"})

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
    today_date = datetime.now(KST).strftime("%Y%m%d") # KST 기준
    return dict(today_date=today_date)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == 'GET':
        school_code = request.cookies.get('school_code')
        school_name = request.cookies.get('school_name')
        region_code_saved = request.cookies.get('region_code') # 지역 코드도 확인

        if school_code and school_name and region_code_saved:
            # 캐시에 정보가 없으면 API를 통해 다시 가져오도록 유도하거나,
            # 리다이렉트 시 필요한 정보를 넘겨줄 수 있도록 처리
            if not any(info.get('code') == school_code for info in school_cache.values()):
                 # 캐시에 없으면 검색 페이지로 (또는 API 호출)
                 logger.info(f"School info for {school_code} not in cache, showing index.")
                 return render_template('school_meal.html', regions=regions)

            logger.info(f"Redirecting to saved school: {school_name} ({school_code})")
            return redirect(url_for('school_meal_view', school_code=school_code))

    elif request.method == 'POST':
        region_name = request.form['region'] # 폼에서는 지역 이름(예: "서울")을 받음
        school_name = request.form['school_name']
        logger.info(f"Search request - Region: {region_name}, School: {school_name}")

        if not region_name or not school_name:
            return render_template('school_meal.html', error_message="지역과 학교명을 모두 입력해주세요.", regions=regions)

        region_code = regions.get(region_name) # 이름으로 코드 조회
        if not region_code:
            return render_template('school_meal.html', error_message="유효하지 않은 지역입니다.", regions=regions)

        school_info = get_school_code(school_name, region_code)
        if school_info:
            response = make_response(redirect(url_for('school_meal_view', school_code=school_info['code'])))
            response.set_cookie('school_code', school_info['code'], max_age=60*60*24*30)
            response.set_cookie('school_name', school_info['name'], max_age=60*60*24*30)
            response.set_cookie('region_code', school_info['region_code'], max_age=60*60*24*30) # 지역 코드도 저장
            return response
        else:
            return render_template('school_meal.html', error_message="학교를 찾을 수 없습니다.", regions=regions, region=region_name, school_name=school_name) # 검색어 유지

    return render_template('school_meal.html', regions=regions)


@app.route("/meal/<school_code>")
def school_meal_view(school_code):
    school_info = None
    for info in school_cache.values():
        if info.get('code') == school_code:
            school_info = info
            break

    # 캐시에 없으면 쿠키를 사용하고, 그래도 없으면 에러 처리 또는 기본값
    if not school_info:
        school_name = request.cookies.get('school_name')
        region_code = request.cookies.get('region_code')
        if school_name and region_code:
             # 캐시에 없으면 API를 통해 다시 가져오거나, 최소 정보로 구성
             school_info = get_school_code(school_name, region_code)
             if not school_info : # 그래도 못찾으면 에러
                 logger.warning(f"Could not find school info for {school_code} even with cookies.")
                 return redirect(url_for('index', error_message="학교 정보를 다시 검색해주세요."))
        else:
            logger.warning(f"No cache or cookie found for {school_code}.")
            return redirect(url_for('index', error_message="학교 정보를 다시 검색해주세요."))


    month_meals = get_month_meals(school_code, school_info['region_code'])
    week_dates = get_week_dates()
    week_meals = {date: month_meals.get(date, {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"}) for date in week_dates}

    # 월간 급식표를 위해 전체 월 데이터를 전달
    all_month_dates = get_month_dates()
    full_month_meals = {date: month_meals.get(date, {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"}) for date in all_month_dates}

    resp = make_response(render_template(
        'school_meal.html',
        regions=regions,
        school_name=school_info['name'],
        school_code=school_code,
        week_meals=week_meals,
        month_meals=full_month_meals, # 월간 데이터 전달
        loading=False,
        region=next((name for name, code in regions.items() if code == school_info['region_code']), None) # 지역 이름 전달
    ))

    resp.set_cookie('school_code', school_code, max_age=60*60*24*30)
    resp.set_cookie('school_name', school_info['name'], max_age=60*60*24*30)
    resp.set_cookie('region_code', school_info['region_code'], max_age=60*60*24*30)
    return resp

@app.route('/api/meals/<school_code>/<date>')
def get_school_meal(school_code, date):
    try:
        school_info = None
        for info in school_cache.values():
            if info.get('code') == school_code:
                school_info = info
                break

        # 캐시에 없으면 쿠키에서 지역 코드 가져오기 (API 호출에 필요)
        if not school_info:
             region_code = request.cookies.get('region_code')
             if region_code:
                 school_info = {'code': school_code, 'region_code': region_code} # 임시 정보
             else:
                 logger.error(f"Region code not found for {school_code} in API call.")
                 return jsonify({"error": "Region code missing"}), 400


        # API 호출 시에는 특정 날짜가 아닌 월 단위로 데이터를 가져와 캐시/사용
        month = date[:6] # YYYYMM
        month_meals = get_month_meals(school_code, school_info['region_code'])
        meal_data = month_meals.get(date, {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"})

        logger.info(f"API Meal request - School: {school_code}, Date: {date}")

        return jsonify({
            "breakfast": meal_data["breakfast"],
            "lunch": meal_data["lunch"],
            "dinner": meal_data["dinner"],
        })
    except Exception as e:
        logger.error(f"Error in get_school_meal route: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route('/current_time')
def current_time():
    now = datetime.now(KST) # KST 기준
    return jsonify({'current_time': now.isoformat()})

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
    return send_from_directory(app.static_folder, 'manifest.json')

def log_request(response):
    log_entry = (
        f"IP: {get_client_ip()}, "
        f"Method: {request.method}, "
        f"URL: {request.url}, "
        f"User-Agent: {request.user_agent.string}, "
        f"Status: {response.status_code}"
    )
    logger.info(log_entry)
    return response

@app.after_request
def after_request_func(response):
    return log_request(response)

@app.route("/It's Christmas Time Again.mp3")
def namufile1():
    return send_file("It's Christmas Time Again.mp3", mimetype="audio/mpeg")

if __name__ == "__main__":
    app.run(debug=True)
