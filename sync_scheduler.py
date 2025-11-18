import requests
import logging
import time
from datetime import datetime, timedelta, timezone
from collections import defaultdict
import re

from database import (
    insert_school, insert_meal, log_sync_start, log_sync_complete,
    get_school_by_code
)

logger = logging.getLogger(__name__)

API_KEY = "4e2c538d90ef493c94c6e2d943e756d9"
KST = timezone(timedelta(hours=9))

regions = {
    "서울": "B10", "부산": "C10", "대구": "D10", "인천": "E10", "광주": "F10",
    "대전": "G10", "울산": "H10", "세종": "I10", "경기": "J10", "강원": "K10",
    "충북": "M10", "충남": "N10", "전북": "P10", "전남": "Q10", "경북": "R10",
    "경남": "S10", "제주": "T10"
}

school_levels = {
    "초등학교": ["초등학교"],
    "중학교": ["중학교", "중등학교"],
    "고등학교": ["고등학교", "고등", "고교"],
    "특수학교": ["특수학교"],
    "각종학교": ["각종학교"]
}

def extract_district_from_address(address):
    """주소에서 시/구 추출"""
    if not address:
        return None
    
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

def get_school_level_from_name(school_name):
    """학교명에서 학교급 추출"""
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

def sync_schools_for_region(region_name, region_code):
    """특정 지역의 모든 학교 정보 동기화"""
    logger.info(f"Starting school sync for region: {region_name} ({region_code})")
    
    url = "https://open.neis.go.kr/hub/schoolInfo"
    synced_count = 0
    error_count = 0
    
    page = 1
    while page <= 10:
        params = {
            "KEY": API_KEY,
            "Type": "json",
            "pIndex": page,
            "pSize": 300,
            "ATPT_OFCDC_SC_CODE": region_code
        }
        
        try:
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if "schoolInfo" not in data or len(data["schoolInfo"]) < 2:
                break
            
            rows = data["schoolInfo"][1].get("row", [])
            if not rows:
                break
            
            for school_data in rows:
                try:
                    school_info = {
                        'code': school_data["SD_SCHUL_CODE"],
                        'name': school_data["SCHUL_NM"],
                        'region_code': region_code,
                        'region_name': region_name,
                        'address': school_data.get("ORG_RDNMA", ""),
                        'district': extract_district_from_address(school_data.get("ORG_RDNMA", "")),
                        'school_level': get_school_level_from_name(school_data["SCHUL_NM"])
                    }
                    
                    if insert_school(school_info):
                        synced_count += 1
                    else:
                        error_count += 1
                        
                except KeyError as e:
                    logger.error(f"Missing key in school data: {e}")
                    error_count += 1
                    continue
            
            if len(rows) < 300:
                break
                
            page += 1
            time.sleep(0.5)
            
        except requests.exceptions.Timeout:
            logger.error(f"Timeout while fetching schools for {region_name}, page {page}")
            error_count += 1
            time.sleep(2)
            continue
        except Exception as e:
            logger.error(f"Error syncing schools for {region_name}, page {page}: {e}")
            error_count += 1
            break
    
    logger.info(f"Completed school sync for {region_name}: {synced_count} synced, {error_count} errors")
    return synced_count, error_count

def sync_all_schools():
    """모든 지역의 학교 정보 동기화"""
    sync_id = log_sync_start('schools', 'all')
    total_synced = 0
    total_errors = 0
    
    logger.info("Starting full school sync for all regions")
    
    for region_name, region_code in regions.items():
        synced, errors = sync_schools_for_region(region_name, region_code)
        total_synced += synced
        total_errors += errors
        time.sleep(1)
    
    status = 'completed' if total_errors == 0 else 'completed_with_errors'
    message = f"Synced {total_synced} schools with {total_errors} errors"
    log_sync_complete(sync_id, status, message, total_synced, total_errors)
    
    logger.info(f"Full school sync completed: {message}")
    return total_synced, total_errors

def sync_meals_for_school(school_code, region_code, year_month):
    """특정 학교의 급식 정보 동기화"""
    url = "https://open.neis.go.kr/hub/mealServiceDietInfo"
    params = {
        "KEY": API_KEY,
        "Type": "json",
        "pIndex": 1,
        "pSize": 100,
        "ATPT_OFCDC_SC_CODE": region_code,
        "SD_SCHUL_CODE": school_code,
        "MLSV_YMD": year_month
    }
    
    synced_count = 0
    
    try:
        response = requests.get(url, params=params, timeout=8)
        response.raise_for_status()
        data = response.json()
        
        if "mealServiceDietInfo" in data and data.get("mealServiceDietInfo")[1].get("row"):
            for row in data["mealServiceDietInfo"][1]["row"]:
                meal_info = {
                    'school_code': school_code,
                    'meal_date': row["MLSV_YMD"],
                    'meal_type': row["MMEAL_SC_CODE"],
                    'menu': row["DDISH_NM"].replace("<br/>", "\n").replace("y ", "").replace("y\n", "\n")
                }
                
                if insert_meal(meal_info):
                    synced_count += 1
        
        return synced_count, 0
        
    except requests.exceptions.Timeout:
        logger.error(f"Timeout while fetching meals for school {school_code}")
        return 0, 1
    except Exception as e:
        logger.error(f"Error syncing meals for school {school_code}: {e}")
        return 0, 1

def sync_meals_for_current_month():
    """이번 달 모든 학교의 급식 정보 동기화"""
    from database import get_db_connection
    
    today = datetime.now(KST)
    year_month = today.strftime("%Y%m")
    
    sync_id = log_sync_start('meals', year_month)
    total_synced = 0
    total_errors = 0
    
    logger.info(f"Starting meal sync for {year_month}")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT school_code, region_code FROM schools')
    schools = cursor.fetchall()
    conn.close()
    
    total_schools = len(schools)
    logger.info(f"Found {total_schools} schools to sync")
    
    for idx, school in enumerate(schools, 1):
        school_code = school['school_code']
        region_code = school['region_code']
        
        synced, errors = sync_meals_for_school(school_code, region_code, year_month)
        total_synced += synced
        total_errors += errors
        
        if idx % 100 == 0:
            logger.info(f"Progress: {idx}/{total_schools} schools processed")
            time.sleep(2)
        else:
            time.sleep(0.3)
    
    status = 'completed' if total_errors == 0 else 'completed_with_errors'
    message = f"Synced {total_synced} meals from {total_schools} schools with {total_errors} errors"
    log_sync_complete(sync_id, status, message, total_synced, total_errors)
    
    logger.info(f"Meal sync completed: {message}")
    return total_synced, total_errors

def sync_meals_for_next_month():
    """다음 달 급식 정보 동기화 (월말에 실행)"""
    from database import get_db_connection
    
    next_month = datetime.now(KST) + timedelta(days=32)
    year_month = next_month.strftime("%Y%m")
    
    sync_id = log_sync_start('meals', year_month)
    total_synced = 0
    total_errors = 0
    
    logger.info(f"Starting meal sync for next month: {year_month}")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT school_code, region_code FROM schools')
    schools = cursor.fetchall()
    conn.close()
    
    for idx, school in enumerate(schools, 1):
        school_code = school['school_code']
        region_code = school['region_code']
        
        synced, errors = sync_meals_for_school(school_code, region_code, year_month)
        total_synced += synced
        total_errors += errors
        
        if idx % 100 == 0:
            logger.info(f"Progress: {idx}/{len(schools)} schools processed")
            time.sleep(2)
        else:
            time.sleep(0.3)
    
    status = 'completed' if total_errors == 0 else 'completed_with_errors'
    message = f"Synced {total_synced} meals for next month with {total_errors} errors"
    log_sync_complete(sync_id, status, message, total_synced, total_errors)
    
    logger.info(f"Next month meal sync completed: {message}")
    return total_synced, total_errors

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(levelname)s: %(message)s'
    )
    
    print("=== School Meal Data Sync ===")
    print("1. Sync all schools")
    print("2. Sync current month meals")
    print("3. Sync next month meals")
    
    choice = input("Select option (1-3): ")
    
    if choice == "1":
        sync_all_schools()
    elif choice == "2":
        sync_meals_for_current_month()
    elif choice == "3":
        sync_meals_for_next_month()
    else:
        print("Invalid choice")
