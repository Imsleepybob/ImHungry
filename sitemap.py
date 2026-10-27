import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from xml.sax.saxutils import escape

import requests
from flask import Response, abort

SITE_URL = os.environ.get('SITE_URL', 'https://geupsikalimi.com').strip().rstrip('/')
NEIS_SCHOOL_URL = 'https://open.neis.go.kr/hub/schoolInfo'
SCHOOL_KINDS = {'초등학교', '중학교', '고등학교', '특수학교'}
REFRESH_SECONDS = 30 * 86400
RETRY_SECONDS = 3600
CHECK_SECONDS = 6 * 3600
PAGE_SIZE = 1000
MAX_PAGES = 50
KST = timezone(timedelta(hours=9))
XML_NS = 'http://www.sitemaps.org/schemas/sitemap/0.9'
SCHOOL_CODE_PATTERN = re.compile(r'^[0-9A-Za-z]+$')


class SitemapStore:
    def __init__(self, api_key, regions, logger):
        self.api_key = api_key
        self.region_codes = list(regions.values())
        self.logger = logger
        self.lock = threading.Lock()
        self.entries = {}
        self.last_try = {}

    # NEIS 조회
    def fetch_codes(self, region_code):
        codes = set()
        seen = 0
        total = None
        for page in range(1, MAX_PAGES + 1):
            params = {
                'KEY': self.api_key, 'Type': 'json',
                'pIndex': page, 'pSize': PAGE_SIZE,
                'ATPT_OFCDC_SC_CODE': region_code,
            }
            response = requests.get(NEIS_SCHOOL_URL, params=params, timeout=20)
            response.raise_for_status()
            block = response.json().get('schoolInfo')
            if not block or len(block) < 2:
                if page == 1:
                    raise RuntimeError('NEIS 응답에 학교 정보가 없습니다')
                break
            rows = block[1].get('row', [])
            if not rows:
                break
            if total is None:
                try:
                    total = int(block[0]['head'][0]['list_total_count'])
                except (KeyError, IndexError, TypeError, ValueError):
                    total = None
            for row in rows:
                code = str(row.get('SD_SCHUL_CODE', '')).strip()
                if row.get('SCHUL_KND_SC_NM') in SCHOOL_KINDS and SCHOOL_CODE_PATTERN.match(code):
                    codes.add(code)
            seen += len(rows)
            if total is not None and seen >= total:
                break
            time.sleep(0.3)
        if total is not None and seen < total:
            raise RuntimeError(f'학교 목록이 불완전합니다 ({seen}/{total})')
        if not codes:
            raise RuntimeError('조건에 맞는 학교가 없습니다 (학교종류명 값 확인 필요)')
        return sorted(codes)

    # XML 생성
    def build_urlset(self, codes, lastmod):
        lines = ['<?xml version="1.0" encoding="UTF-8"?>', f'<urlset xmlns="{XML_NS}">']
        for code in codes:
            lines.append(f'  <url><loc>{SITE_URL}/meal/{escape(code)}</loc><lastmod>{lastmod}</lastmod></url>')
        lines.append('</urlset>')
        return '\n'.join(lines) + '\n'

    def main_xml(self):
        return (f'<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="{XML_NS}">\n'
                f'  <url><loc>{SITE_URL}/</loc></url>\n</urlset>\n')

    def index_xml(self):
        lines = ['<?xml version="1.0" encoding="UTF-8"?>', f'<sitemapindex xmlns="{XML_NS}">',
                 f'  <sitemap><loc>{SITE_URL}/sitemap-main.xml</loc></sitemap>']
        with self.lock:
            entries = dict(self.entries)
        for code in self.region_codes:
            entry = entries.get(code)
            lastmod = f'<lastmod>{entry["lastmod"]}</lastmod>' if entry else ''
            lines.append(f'  <sitemap><loc>{SITE_URL}/sitemap-{code}.xml</loc>{lastmod}</sitemap>')
        lines.append('</sitemapindex>')
        return '\n'.join(lines) + '\n'

    # 갱신 스케줄
    def refresh(self, region_code):
        self.last_try[region_code] = time.time()
        try:
            codes = self.fetch_codes(region_code)
        except Exception as e:
            self.logger.error(f'[sitemap] {region_code} 갱신 실패: {e}')
            return False
        lastmod = datetime.now(KST).strftime('%Y-%m-%d')
        entry = {
            'xml': self.build_urlset(codes, lastmod), 'count': len(codes),
            'codes': frozenset(codes), 'updated': time.time(), 'lastmod': lastmod,
        }
        with self.lock:
            old = self.entries.get(region_code)
            self.entries[region_code] = entry
        if old:
            self.logger.info(f'[sitemap] {region_code} 갱신: {len(codes)}개 (추가 {len(entry["codes"] - old["codes"])}, 제거 {len(old["codes"] - entry["codes"])})')
        else:
            self.logger.info(f'[sitemap] {region_code} 생성: {len(codes)}개')
        return True

    def get(self, region_code):
        with self.lock:
            return self.entries.get(region_code)

    def is_due(self, region_code, now):
        entry = self.get(region_code)
        if entry and now - entry['updated'] < REFRESH_SECONDS:
            return False
        return now - self.last_try.get(region_code, 0) >= RETRY_SECONDS

    def run_once(self):
        for region_code in self.region_codes:
            if self.is_due(region_code, time.time()):
                self.refresh(region_code)
                time.sleep(1)

    def run(self):
        while True:
            try:
                self.run_once()
            except Exception as e:
                self.logger.error(f'[sitemap] 갱신 루프 오류: {e}')
            time.sleep(CHECK_SECONDS)


def init_sitemap(app, api_key, regions):
    store = SitemapStore(api_key, regions, app.logger)

    def xml_response(body):
        response = Response(body, mimetype='application/xml')
        response.headers['Cache-Control'] = 'public, max-age=3600'
        return response

    @app.route('/sitemap.xml')
    def sitemap_index():
        return xml_response(store.index_xml())

    @app.route('/sitemap-main.xml')
    def sitemap_main():
        return xml_response(store.main_xml())

    @app.route('/sitemap-<region_code>.xml')
    def sitemap_region(region_code):
        if region_code not in store.region_codes:
            abort(404)
        entry = store.get(region_code)
        if not entry:
            response = Response('', status=503)
            response.headers['Retry-After'] = '300'
            return response
        return xml_response(entry['xml'])

    threading.Thread(target=store.run, daemon=True).start()
    return store
