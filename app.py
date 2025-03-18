from flask import Flask, render_template, request, send_file, make_response, jsonify, redirect, url_for, send_from_directory
from datetime import datetime, timedelta, date
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
        # X-Forwarded-For 헤더에 포함된 첫 번째 IP를 사용
        return request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    elif request.access_route:
        # access_route에 있는 첫 번째 IP
        return request.access_route[0]
    else:
        # 기본 remote_addr
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
        # IP 주소가 유효하지 않음
        app.logger.error(f"Invalid IP address detected: {ip_address}")
        return False

@app.before_request
def block_method():
    client_ip = get_client_ip()
    app.logger.info(f"Client IP detected: {client_ip}")
    if is_ip_blocked(client_ip):
        app.logger.warning(f"Blocked access attempt from IP: {client_ip}")
        return 'Access Denied', 403

# 추가 로깅 설정 (선택사항)
def setup_logging():
    handler = logging.FileHandler('ip_block.log')
    handler.setLevel(logging.WARNING)
    app.logger.addHandler(handler)

# 로깅 초기화
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
    "서울": "B10",
    "부산": "C10",
    "대구": "D10",
    "인천": "E10",
    "광주": "F10",
    "대전": "G10",
    "울산": "H10",
    "세종": "I10",
    "경기": "J10",
    "강원": "K10",
    "충북": "M10",
    "충남": "N10",
    "전북": "P10",
    "전남": "Q10",
    "경북": "R10",
    "경남": "S10",
    "제주": "T10"
}

school_cache = {}
meal_cache = {}

def get_school_code(school_name, region_code):
    cache_key = f"{region_code}_{school_name}"
    if cache_key in school_cache:
        return school_cache[cache_key]

    url = "https://open.neis.go.kr/hub/schoolInfo"
    params = {
        "KEY": API_KEY,
        "Type": "json",
        "pIndex": 1,
        "pSize": 100,
        "ATPT_OFCDC_SC_CODE": region_code,
        "SCHUL_NM": school_name
    }
    try:
        response = requests.get(url, params=params, timeout=5)
        data = response.json()

        if "schoolInfo" in data:
            school_data = data["schoolInfo"][1]["row"][0]
            school_code = school_data["SD_SCHUL_CODE"]
            school_cache[cache_key] = {
                'code': school_code,
                'name': school_data["SCHUL_NM"],
                'region_code': region_code
            }
            return school_cache[cache_key]
    except Exception as e:
        logger.error(f"Error fetching school code: {e}")
        return None
    return None

def get_month_dates():
    today = datetime.now().date()
    _, last_day = calendar.monthrange(today.year, today.month)
    return [(date(today.year, today.month, day)).strftime('%Y%m%d') for day in range(1, last_day + 1)]

def get_week_dates():
    today = datetime.now().date()
    start_of_week = today - timedelta(days=today.weekday() + 1)
    dates = [(start_of_week + timedelta(days=i)).strftime('%Y%m%d') for i in range(7)]
    return dates

def get_month_meals(school_code, region_code):
    today = datetime.now()
    cache_key = f"{region_code}_{school_code}_{today.strftime('%Y%m')}"

    if cache_key in meal_cache:
        return meal_cache[cache_key]

    url = "https://open.neis.go.kr/hub/mealServiceDietInfo"
    params = {
        "KEY": API_KEY,
        "Type": "json",
        "pIndex": 1,
        "pSize": 100,
        "ATPT_OFCDC_SC_CODE": region_code,
        "SD_SCHUL_CODE": school_code,
        "MLSV_YMD": today.strftime("%Y%m")
    }

    try:
        response = requests.get(url, params=params, timeout=5)
        data = response.json()

        # 급식 유형별로 구분하여 저장 (1: 조식, 2: 중식, 3: 석식)
        meals = defaultdict(lambda: {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"})

    if "mealServiceDietInfo" in data:
        for row in data["mealServiceDietInfo"][1]["row"]:
            date = row["MLSV_YMD"]
            # Clean up the menu text by replacing "<br/>" with newlines and removing "y" suffixes
            menu = row["DDISH_NM"].replace("<br/>", "\n").replace("y ", "").replace("y\n", "\n")
            meal_type = row["MMEAL_SC_CODE"]
                
                if meal_type == "1":  # 조식
                    meals[date]["breakfast"] = menu
                elif meal_type == "2":  # 중식
                    meals[date]["lunch"] = menu
                elif meal_type == "3":  # 석식
                    meals[date]["dinner"] = menu

        meal_cache[cache_key] = dict(meals)
        return dict(meals)
    except Exception as e:
        logger.error(f"Error fetching meals: {e}")
        return defaultdict(lambda: {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"})

@app.template_filter('format_date')
def format_date(value):
    date_obj = datetime.strptime(value, "%Y%m%d")
    formatted_date = date_obj.strftime("%Y년 %m월 %d일")
    day_of_week = calendar.day_name[date_obj.weekday()]
    korean_day_names = {'Sunday': '일', 'Monday': '월', 'Tuesday': '화', 'Wednesday': '수',
                       'Thursday': '목', 'Friday': '금', 'Saturday': '토'}
    formatted_date_with_day = f"{formatted_date} ({korean_day_names[day_of_week]})"
    return formatted_date_with_day

@app.context_processor
def inject_today_date():
    today_date = datetime.now().strftime("%Y%m%d")
    return dict(today_date=today_date)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == 'GET':
        # GET 요청일 때 쿠키 확인
        school_code = request.cookies.get('school_code')
        school_name = request.cookies.get('school_name')

        # 쿠키에 학교 정보가 있으면 해당 학교의 급식 페이지로 리다이렉트
        if school_code and school_name:
            logger.info(f"Redirecting to saved school: {school_name} ({school_code})")
            return redirect(url_for('school_meal_view', school_code=school_code))

    elif request.method == 'POST':
        region = request.form['region']
        school_name = request.form['school_name']
        logger.info(f"Search request - Region: {region}, School: {school_name}")

        if not region or not school_name:
            return render_template('school_meal.html', error_message="지역과 학교명을 모두 입력해주세요.", regions=regions)

        school_info = get_school_code(school_name, regions[region])
        if school_info:
            response = redirect(url_for('school_meal_view', school_code=school_info['code']))
            # 쿠키에 학교 정보 저장 (30일 유효)
            response.set_cookie('school_code', school_info['code'], max_age=60*60*24*30)
            response.set_cookie('school_name', school_info['name'], max_age=60*60*24*30)
            return response
        else:
            return render_template('school_meal.html', error_message="학교를 찾을 수 없습니다.", regions=regions)

    return render_template('school_meal.html', regions=regions)

@app.route("/meal/<school_code>")
def school_meal_view(school_code):
    # 캐시에서 학교 정보 찾기
    school_info = None
    for cache_info in school_cache.values():
        if cache_info.get('code') == school_code:
            school_info = cache_info
            break

    if not school_info:
        # 쿠키에서 학교 이름을 가져와서 사용
        school_name = request.cookies.get('school_name', '알 수 없는 학교')
        school_info = {
            'code': school_code,
            'name': school_name,
            'region_code': next(iter(regions.values()))  # 기본 지역 코드
        }

    month_meals = get_month_meals(school_code, school_info['region_code'])
    week_dates = get_week_dates()
    week_meals = {date: month_meals.get(date, {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"}) for date in week_dates}

    resp = make_response(render_template(
        'school_meal.html',
        regions=regions,
        school_name=school_info['name'],
        school_code=school_code,
        week_meals=week_meals,
        month_meals=month_meals,
        loading=False
    ))

    # 응답에도 쿠키 설정 (새로고침해도 유지되도록)
    resp.set_cookie('school_code', school_code, max_age=60*60*24*30)
    resp.set_cookie('school_name', school_info['name'], max_age=60*60*24*30)
    return resp

@app.route('/api/meals/<school_code>/<date>')
def get_school_meal(school_code, date):
    try:
        school_info = None
        for cache_info in school_cache.values():
            if cache_info.get('code') == school_code:
                school_info = cache_info
                break

        if school_info:
            month_meals = get_month_meals(school_code, school_info['region_code'])
            meal_data = month_meals.get(date, {"breakfast": "급식 정보 없음", "lunch": "급식 정보 없음", "dinner": "급식 정보 없음"})
            logger.info(f"Meal request - School: {school_info['name']}, Date: {date}")
            
            # 급식 정보가 있는지 확인
            has_meal = (
                meal_data["breakfast"] != "급식 정보 없음" or
                meal_data["lunch"] != "급식 정보 없음" or
                meal_data["dinner"] != "급식 정보 없음"
            )
            
            return jsonify({
                "breakfast": meal_data["breakfast"],
                "lunch": meal_data["lunch"],
                "dinner": meal_data["dinner"],
                "has_meal": has_meal
            })
        return jsonify({
            "breakfast": "급식 정보 없음",
            "lunch": "급식 정보 없음", 
            "dinner": "급식 정보 없음",
            "has_meal": False
        })
    except Exception as e:
        logger.error(f"Error in get_meal route: {e}")
        return jsonify({
            "breakfast": "오류가 발생했습니다.", 
            "lunch": "오류가 발생했습니다.", 
            "dinner": "오류가 발생했습니다.", 
            "has_meal": False
        })

@app.route('/current_time')
def current_time():
    now = datetime.now()
    return jsonify({'current_time': now.isoformat()})

@app.route('/robots.txt')
def robots_txt():
    return send_from_directory('static', 'robots.txt')

@app.route('/favicon.svg')
def favicon():
    return send_from_directory('static', 'favicon.svg')

@app.route('/favicon.ico')
def faviconico():
    return send_from_directory('static', 'favicon.svg')

@app.route('/manifest.json')
def manifest():
    return send_from_directory('static', 'manifest.json')

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

# 기존 after_request 데코레이터 유지
@app.after_request
def after_request(response):
    log_request(response)
    return response

if __name__ == "__main__":
    app.run(debug=True)
