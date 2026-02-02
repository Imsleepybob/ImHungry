import psycopg2
from psycopg2.extras import RealDictCursor
import os
from datetime import datetime
import logging

DATABASE_URL = os.environ.get('DATABASE_URL')

if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

logger = logging.getLogger(__name__)

def get_db_connection():
    try:
        conn = psycopg2.connect(
            DATABASE_URL,
            cursor_factory=RealDictCursor,
            sslmode="require"
        )
        return conn
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        raise

def init_database():
    """데이터베이스 초기화 - 학교 정보 테이블만 생성"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
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
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sync_log (
                id SERIAL PRIMARY KEY,
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
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_schools_name ON schools(school_name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_schools_region ON schools(region_code)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_schools_district ON schools(district)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_schools_level ON schools(school_level)')
        
        conn.commit()
        logger.info("Database initialized successfully")
    except Exception as e:
        conn.rollback()
        logger.error(f"Error initializing database: {e}")
        raise
    finally:
        cursor.close()
        conn.close()

def insert_school(school_data):
    """학교 정보 저장"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO schools 
            (school_code, school_name, region_code, region_name, address, district, school_level, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (school_code) 
            DO UPDATE SET 
                school_name = EXCLUDED.school_name,
                region_name = EXCLUDED.region_name,
                address = EXCLUDED.address,
                district = EXCLUDED.district,
                school_level = EXCLUDED.school_level,
                updated_at = EXCLUDED.updated_at
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
        conn.rollback()
        logger.error(f"Error inserting school: {e}")
        return False
    finally:
        cursor.close()
        conn.close()

def get_school_by_code(school_code):
    """학교 코드로 학교 정보 조회"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT * FROM schools WHERE school_code = %s', (school_code,))
        result = cursor.fetchone()
        return dict(result) if result else None
    finally:
        cursor.close()
        conn.close()

def search_schools(query, region_code=None, limit=10):
    """학교 검색 (자동완성용)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        if region_code:
            cursor.execute('''
                SELECT school_code, school_name, region_code, address
                FROM schools 
                WHERE school_name LIKE %s AND region_code = %s
                ORDER BY school_name
                LIMIT %s
            ''', (f'%{query}%', region_code, limit))
        else:
            cursor.execute('''
                SELECT school_code, school_name, region_code, address
                FROM schools 
                WHERE school_name LIKE %s
                ORDER BY school_name
                LIMIT %s
            ''', (f'%{query}%', limit))
        
        results = [dict(row) for row in cursor.fetchall()]
        return results
    finally:
        cursor.close()
        conn.close()

def get_schools_by_region(region_code, school_level=None):
    """지역별 학교 목록 조회"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        if school_level:
            cursor.execute('''
                SELECT * FROM schools 
                WHERE region_code = %s AND school_level = %s
                ORDER BY school_name
            ''', (region_code, school_level))
        else:
            cursor.execute('''
                SELECT * FROM schools 
                WHERE region_code = %s
                ORDER BY school_name
            ''', (region_code,))
        
        results = [dict(row) for row in cursor.fetchall()]
        return results
    finally:
        cursor.close()
        conn.close()

def get_schools_by_district(region_code, district, school_level=None):
    """구/시별 학교 목록 조회 (주변 학교 찾기용)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        if school_level:
            cursor.execute('''
                SELECT * FROM schools 
                WHERE region_code = %s AND district = %s AND school_level = %s
                ORDER BY school_name
            ''', (region_code, district, school_level))
        else:
            cursor.execute('''
                SELECT * FROM schools 
                WHERE region_code = %s AND district = %s
                ORDER BY school_name
            ''', (region_code, district))
        
        results = [dict(row) for row in cursor.fetchall()]
        return results
    finally:
        cursor.close()
        conn.close()

def log_sync_start(sync_type, region_code=None):
    """동기화 시작 로그"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO sync_log (sync_type, region_code, status, started_at)
            VALUES (%s, %s, 'running', %s)
            RETURNING id
        ''', (sync_type, region_code, datetime.now()))
        
        sync_id = cursor.fetchone()['id']
        conn.commit()
        return sync_id
    finally:
        cursor.close()
        conn.close()

def log_sync_complete(sync_id, status, message, synced_count=0, error_count=0):
    """동기화 완료 로그"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            UPDATE sync_log 
            SET status = %s, message = %s, synced_count = %s, error_count = %s, completed_at = %s
            WHERE id = %s
        ''', (status, message, synced_count, error_count, datetime.now(), sync_id))
        
        conn.commit()
    finally:
        cursor.close()
        conn.close()

def get_db_stats():
    """DB 통계 조회"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT COUNT(*) as count FROM schools')
        school_count = cursor.fetchone()['count']
        
        cursor.execute('''
            SELECT sync_type, status, completed_at 
            FROM sync_log 
            ORDER BY completed_at DESC 
            LIMIT 1
        ''')
        last_sync = cursor.fetchone()
        
        return {
            'school_count': school_count,
            'last_sync': dict(last_sync) if last_sync else None
        }
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    if not DATABASE_URL:
        print("ERROR: DATABASE_URL environment variable is not set!")
        print("Please set it to your PostgreSQL connection string.")
        exit(1)
    
    init_database()
    print("Database initialized successfully!")
    print(f"Connected to: {DATABASE_URL.split('@')[1] if '@' in DATABASE_URL else 'database'}")
