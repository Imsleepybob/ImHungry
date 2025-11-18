import os
import logging
import threading
from datetime import datetime

logger = logging.getLogger(__name__)

def run_initial_sync():
    """백그라운드에서 초기 동기화 실행"""
    from database import init_database, get_db_stats
    from sync_scheduler import sync_all_schools, sync_meals_for_current_month
    
    logger.info("=== 백그라운드 초기 동기화 시작 ===")
    
    try:
        init_database()
        logger.info("✓ 데이터베이스 테이블 확인 완료")
    except Exception as e:
        logger.error(f"✗ DB 초기화 실패: {e}")
        return
    
    try:
        stats = get_db_stats()
        
        # 학교 데이터가 없으면 동기화
        if stats['school_count'] == 0:
            logger.info("학교 데이터가 없습니다. 동기화 시작...")
            synced, errors = sync_all_schools()
            logger.info(f"✓ 학교 동기화 완료: {synced}개 성공, {errors}개 오류")
        else:
            logger.info(f"학교 데이터 존재 ({stats['school_count']}개). 동기화 건너뜀")
        
        # 급식 데이터 확인
        today = datetime.now()
        year_month = today.strftime("%Y%m")
        
        if stats['meal_count'] == 0:
            logger.info("급식 데이터가 없습니다. 동기화 시작...")
            synced, errors = sync_meals_for_current_month()
            logger.info(f"✓ 급식 동기화 완료: {synced}개 성공, {errors}개 오류")
        else:
            logger.info(f"급식 데이터 존재 ({stats['meal_count']}개). 동기화 건너뜀")
            
    except Exception as e:
        logger.error(f"✗ 동기화 실패: {e}")
    
    logger.info("=== 백그라운드 초기 동기화 완료 ===")

def startup_check():
    """서버 시작시 실행 - 비동기로 동기화"""
    if not os.environ.get('DATABASE_URL'):
        logger.warning("DATABASE_URL이 설정되지 않았습니다. DB 기능을 사용할 수 없습니다.")
        return
    
    try:
        from database import get_db_stats, init_database
        
        # 테이블 생성
        init_database()
        
        # DB 상태 확인
        stats = get_db_stats()
        logger.info(f"현재 DB 상태 - 학교: {stats['school_count']}개, 급식: {stats['meal_count']}개")
        
        # 데이터가 하나라도 없으면 백그라운드에서 동기화
        if stats['school_count'] == 0 or stats['meal_count'] == 0:
            logger.info("데이터가 부족합니다. 백그라운드 동기화를 시작합니다.")
            logger.info("서버는 정상적으로 시작되며, 동기화는 백그라운드에서 진행됩니다.")
            
            # 별도 스레드에서 실행
            sync_thread = threading.Thread(target=run_initial_sync, daemon=True)
            sync_thread.start()
        else:
            logger.info("데이터가 이미 존재합니다. 동기화를 건너뜁니다.")
            
    except Exception as e:
        logger.error(f"Startup check 실패: {e}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    startup_check()
