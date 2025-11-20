import requests
import logging
import time
from datetime import datetime, timedelta, timezone
import re

from database import (
    insert_school, log_sync_start, log_sync_complete
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

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(levelname)s: %(message)s'
    )
    
    print("=== School Data Sync ===")
    print("1. Sync all schools")
    
    choice = input("Select option (1): ")
    
    if choice == "1":
        sync_all_schools()
    else:
        print("Invalid choice")
