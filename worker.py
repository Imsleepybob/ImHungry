import os
import logging
import time
from datetime import datetime
from apscheduler.schedulers.blocking import BlockingScheduler

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

from database import init_database, get_db_stats
from sync_scheduler import sync_all_schools

def initial_sync():
    """최초 1회 실행: DB 초기화 및 데이터 동기화"""
    logger.info("=== 초기 동기화 시작 ===")
    
    try:
        logger.info("Step 1: 데이터베이스 테이블 생성")
        init_database()
        logger.info("✓ 테이블 생성 완료")
    except Exception as e:
        logger.error(f"✗ DB 초기화 실패: {e}")
        return
    
    try:
        stats = get_db_stats()
        if stats['school_count'] > 0:
            logger.info(f"학교 데이터가 이미 존재합니다 ({stats['school_count']}개). 학교 동기화 건너뜀")
        else:
            logger.info("Step 2: 전국 학교 정보 동기화 (약 10-15분 소요)")
            synced, errors = sync_all_schools()
            logger.info(f"✓ 학교 동기화 완료: {synced}개 성공, {errors}개 오류")
    except Exception as e:
        logger.error(f"✗ 학교 동기화 실패: {e}")
    
    logger.info("=== 초기 동기화 완료 ===")

def monthly_school_sync():
    """매월 1일 새벽 2시 실행: 학교 정보 업데이트"""
    logger.info("=== 월간 학교 정보 동기화 시작 ===")
    try:
        synced, errors = sync_all_schools()
        logger.info(f"✓ 학교 동기화 완료: {synced}개 성공, {errors}개 오류")
    except Exception as e:
        logger.error(f"✗ 학교 동기화 실패: {e}")

def main():
    logger.info("Background Worker 시작")
        from database import get_db_connection
    conn = get_db_connection()
    conn.close()

    initial_sync()
    
    scheduler = BlockingScheduler(timezone="Asia/Seoul")
    
    scheduler.add_job(monthly_school_sync, 'cron', day=1, hour=2, minute=0)
    
    logger.info("스케줄러 시작 - 자동 동기화 활성화")
    logger.info("  - 매월 1일 02:00: 학교 정보 업데이트")
    
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        logger.info("Background Worker 종료")

if __name__ == "__main__":
    if not os.environ.get('DATABASE_URL'):
        logger.error("DATABASE_URL 환경변수가 설정되지 않았습니다!")
        exit(1)
    main()
