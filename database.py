import sqlite3
import os
from datetime import datetime
import logging

DB_PATH = os.path.join(os.getcwd(), 'school_meals.db')

logger = logging.getLogger(__name__)

def get_db_connection():
    """DB 연결 생성"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    """데이터베이스 초기화 - 테이블 생성"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 학교 정보 테이블
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS schools (
            school_code TEXT PRIMARY KEY,
            school_name TEXT NOT NULL,
            region_code TEXT NOT NULL,
            region_name TEXT,
            address TEXT,
            district TEXT,
            school_level TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 급식 정보 테이블
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS meals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_code TEXT NOT NULL,
            meal_date TEXT NOT NULL,
            meal_type TEXT NOT NULL,
            menu TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(school_code, meal_date, meal_type),
            FOREIGN KEY (school_code) REFERENCES schools(school_code)
        )
    ''')
    
    # 동기화 로그 테이블
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sync_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sync_type TEXT NOT NULL,
            region_code TEXT,
            status TEXT NOT NULL,
            message TEXT,
            synced_count INTEGER DEFAULT 0,
            error_count INTEGER DEFAULT 0,
            started_at TIMESTAMP,
            completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 인덱스 생성
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_schools_name ON schools(school_name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_schools_region ON schools(region_code)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_meals_date ON meals(meal_date)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_meals_school ON meals(school_code)')
    
    conn.commit()
    conn.close()
    logger.info("Database initialized successfully")

def insert_school(school_data):
    """학교 정보 저장"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT OR REPLACE INTO schools 
            (school_code, school_name, region_code, region_name, address, district, school_level, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            school_data['code'],
            school_data['name'],
            school_data['region_code'],
            school_data.get('region_name'),
            school_data.get('address'),
            school_data.get('district'),
            school_data.get('school_level'),
            datetime.now()
        ))
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error inserting school: {e}")
        return False
    finally:
        conn.close()

def insert_meal(meal_data):
    """급식 정보 저장"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT OR REPLACE INTO meals 
            (school_code, meal_date, meal_type, menu, updated_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            meal_data['school_code'],
            meal_data['meal_date'],
            meal_data['meal_type'],
            meal_data['menu'],
            datetime.now()
        ))
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error inserting meal: {e}")
        return False
    finally:
        conn.close()

def get_school_by_code(school_code):
    """학교 코드로 학교 정보 조회"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM schools WHERE school_code = ?', (school_code,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return dict(result)
    return None

def search_schools(query, region_code=None, limit=10):
    """학교 검색 (자동완성용)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if region_code:
        cursor.execute('''
            SELECT school_code, school_name, region_code, address
            FROM schools 
            WHERE school_name LIKE ? AND region_code = ?
            ORDER BY school_name
            LIMIT ?
        ''', (f'%{query}%', region_code, limit))
    else:
        cursor.execute('''
            SELECT school_code, school_name, region_code, address
            FROM schools 
            WHERE school_name LIKE ?
            ORDER BY school_name
            LIMIT ?
        ''', (f'%{query}%', limit))
    
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return results

def get_meals_by_date(school_code, meal_date):
    """특정 날짜의 급식 정보 조회"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT meal_type, menu 
        FROM meals 
        WHERE school_code = ? AND meal_date = ?
    ''', (school_code, meal_date))
    
    results = cursor.fetchall()
    conn.close()
    
    meals = {
        "breakfast": "급식 정보 없음",
        "lunch": "급식 정보 없음",
        "dinner": "급식 정보 없음"
    }
    
    meal_type_map = {
        "1": "breakfast",
        "2": "lunch",
        "3": "dinner"
    }
    
    for row in results:
        meal_key = meal_type_map.get(row['meal_type'])
        if meal_key:
            meals[meal_key] = row['menu']
    
    return meals

def get_month_meals(school_code, year_month):
    """한 달 급식 정보 조회"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT meal_date, meal_type, menu 
        FROM meals 
        WHERE school_code = ? AND meal_date LIKE ?
        ORDER BY meal_date
    ''', (school_code, f'{year_month}%'))
    
    results = cursor.fetchall()
    conn.close()
    
    meals_dict = {}
    meal_type_map = {
        "1": "breakfast",
        "2": "lunch",
        "3": "dinner"
    }
    
    for row in results:
        date_str = row['meal_date']
        if date_str not in meals_dict:
            meals_dict[date_str] = {
                "breakfast": "급식 정보 없음",
                "lunch": "급식 정보 없음",
                "dinner": "급식 정보 없음"
            }
        
        meal_key = meal_type_map.get(row['meal_type'])
        if meal_key:
            meals_dict[date_str][meal_key] = row['menu']
    
    return meals_dict

def get_schools_by_region(region_code, school_level=None):
    """지역별 학교 목록 조회"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if school_level:
        cursor.execute('''
            SELECT * FROM schools 
            WHERE region_code = ? AND school_level = ?
            ORDER BY school_name
        ''', (region_code, school_level))
    else:
        cursor.execute('''
            SELECT * FROM schools 
            WHERE region_code = ?
            ORDER BY school_name
        ''', (region_code,))
    
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return results

def log_sync_start(sync_type, region_code=None):
    """동기화 시작 로그"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO sync_log (sync_type, region_code, status, started_at)
        VALUES (?, ?, 'running', ?)
    ''', (sync_type, region_code, datetime.now()))
    
    sync_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return sync_id

def log_sync_complete(sync_id, status, message, synced_count=0, error_count=0):
    """동기화 완료 로그"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE sync_log 
        SET status = ?, message = ?, synced_count = ?, error_count = ?, completed_at = ?
        WHERE id = ?
    ''', (status, message, synced_count, error_count, datetime.now(), sync_id))
    
    conn.commit()
    conn.close()

def get_db_stats():
    """DB 통계 조회"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) as count FROM schools')
    school_count = cursor.fetchone()['count']
    
    cursor.execute('SELECT COUNT(*) as count FROM meals')
    meal_count = cursor.fetchone()['count']
    
    cursor.execute('''
        SELECT sync_type, status, completed_at 
        FROM sync_log 
        ORDER BY completed_at DESC 
        LIMIT 1
    ''')
    last_sync = cursor.fetchone()
    
    conn.close()
    
    return {
        'school_count': school_count,
        'meal_count': meal_count,
        'last_sync': dict(last_sync) if last_sync else None
    }

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    init_database()
    print("Database initialized successfully!")
    print(f"Database location: {DB_PATH}")
