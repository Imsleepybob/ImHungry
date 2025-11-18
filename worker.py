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
from sync_scheduler import sync_all_schools, sync_meals_for_current_month, sync_meals_for_next_month

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
    
    try:
        logger.info("Step 3: 이번 달 급식 정보 동기화 (약 30-60분 소요)")
        synced, errors = sync_meals_for_current_month()
        logger.info(f"✓ 급식 동기화 완료: {synced}개 성공, {errors}개 오류")
    except Exception as e:
        logger.error(f"✗ 급식 동기화 실패: {e}")
    
    logger.info("=== 초기 동기화 완료 ===")

def daily_meal_sync():
    """매일 새벽 3시 실행: 급식 정보 업데이트"""
    logger.info("=== 일일 급식 동기화 시작 ===")
    try:
        synced, errors = sync_meals_for_current_month()
        logger.info(f"✓ 급식 동기화 완료: {synced}개 성공, {errors}개 오류")
    except Exception as e:
        logger.error(f"✗ 급식 동기화 실패: {e}")

def monthly_school_sync():
    """매월 1일 새벽 2시 실행: 학교 정보 업데이트"""
    logger.info("=== 월간 학교 정보 동기화 시작 ===")
    try:
        synced, errors = sync_all_schools()
        logger.info(f"✓ 학교 동기화 완료: {synced}개 성공, {errors}개 오류")
    except Exception as e:
        logger.error(f"✗ 학교 동기화 실패: {e}")

def next_month_meal_sync():
    """매월 25일 새벽 4시 실행: 다음 달 급식 미리 가져오기"""
    logger.info("=== 다음 달 급식 동기화 시작 ===")
    try:
        synced, errors = sync_meals_for_next_month()
        logger.info(f"✓ 다음 달 급식 동기화 완료: {synced}개 성공, {errors}개 오류")
    except Exception as e:
        logger.error(f"✗ 다음 달 급식 동기화 실패: {e}")

def main():
    logger.info("Background Worker 시작")
    
    # 최초 1회 초기 동기화 실행
    initial_sync()
    
    # 스케줄러 설정
    scheduler = BlockingScheduler(timezone="Asia/Seoul")
    
    # 매일 새벽 3시: 급식 정보 업데이트
    scheduler.add_job(daily_meal_sync, 'cron', hour=3, minute=0)
    
    # 매월 1일 새벽 2시: 학교 정보 업데이트
    scheduler.add_job(monthly_school_sync, 'cron', day=1, hour=2, minute=0)
    
    # 매월 25일 새벽 4시: 다음 달 급식 미리 가져오기
    scheduler.add_job(next_month_meal_sync, 'cron', day=25, hour=4, minute=0)
    
    logger.info("스케줄러 시작 - 자동 동기화 활성화")
    logger.info("  - 매일 03:00: 급식 정보 업데이트")
    logger.info("  - 매월 1일 02:00: 학교 정보 업데이트")
    logger.info("  - 매월 25일 04:00: 다음 달 급식 미리 가져오기")
    
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        logger.info("Background Worker 종료")

if __name__ == "__main__":
    if not os.environ.get('DATABASE_URL'):
        logger.error("DATABASE_URL 환경변수가 설정되지 않았습니다!")
        exit(1)
    main()
