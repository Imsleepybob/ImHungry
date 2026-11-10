import argparse
import collections
import json
import os
import sys
import time
from datetime import date

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build_school_geo import CODE_RE, SIDO, district, group_of, norm_name, rest_key, split_address

ENDPOINT = 'https://www.schoolinfo.go.kr/openApi.do'
KIND_CODES = ('02', '03', '04', '05')
YEAR_TYPES = ('63', '34')
PILOT_TYPES = ('0', '09', '10', '22', '34', '44', '51', '56', '58', '59', '62', '63', '73')


class Fetcher:
    def __init__(self, key, cache_dir, delay, offline, max_failures):
        self.key = key
        self.cache_dir = cache_dir
        self.delay = delay
        self.offline = offline
        self.max_failures = max_failures
        self.failures = 0
        self.calls = 0
        self.session = requests.Session()
        os.makedirs(cache_dir, exist_ok=True)

    def path(self, api_type, sido, sgg, kind, year):
        return os.path.join(self.cache_dir, f'{api_type}_{sgg}_{kind}_{year or 0}.json')

    def get(self, api_type, sido, sgg, kind, year=None):
        path = self.path(api_type, sido, sgg, kind, year)
        if os.path.exists(path):
            with open(path, encoding='utf-8') as handle:
                return json.load(handle)
        if self.offline:
            return {'resultCode': 'success', 'list': []}
        params = {'apiKey': self.key, 'apiType': api_type, 'sidoCode': sido, 'sggCode': sgg, 'schulKndCode': kind}
        if year:
            params['pbanYr'] = year
        wait = self.delay
        for attempt in range(5):
            time.sleep(wait)
            self.calls += 1
            try:
                response = self.session.get(ENDPOINT, params=params, timeout=30)
                if response.status_code >= 500:
                    raise requests.RequestException(f'HTTP {response.status_code}')
                data = response.json()
            except (requests.RequestException, ValueError) as error:
                wait = min(wait * 2 + 1, 60)
                print(f'  재시도 {attempt + 1}/5 ({error.__class__.__name__}), {wait:.0f}초 대기', flush=True)
                continue
            if data.get('resultCode') != 'success':
                self.failures += 1
                print(f'  응답 실패 apiType={api_type} sgg={sgg} kind={kind} year={year}: {data.get("resultMsg")}', flush=True)
                if self.failures >= self.max_failures:
                    raise SystemExit('연속 실패가 한도에 도달해 중단해요. 잠시 뒤 다시 실행하면 이어서 받아요.')
                return {'resultCode': data.get('resultCode'), 'resultMsg': data.get('resultMsg'), 'list': []}
            self.failures = 0
            with open(path, 'w', encoding='utf-8') as handle:
                json.dump(data, handle, ensure_ascii=False)
            return data
        raise SystemExit('네트워크 오류가 계속돼서 중단해요. 잠시 뒤 다시 실행하면 이어서 받아요.')


def read_regions(path):
    from openpyxl import load_workbook
    sheet = load_workbook(path, read_only=True, data_only=True).worksheets[0]
    regions = []
    for row in sheet.iter_rows(min_row=1, values_only=True):
        if not row or len(row) < 4:
            continue
        sido_name, sido_code, sgg_name, sgg_code = (str(item).strip() if item is not None else '' for item in row[:4])
        if not (sido_code.isdigit() and sgg_code.isdigit()) or sgg_code == '00000':
            continue
        regions.append({'sido_name': sido_name, 'sido': sido_code, 'sgg_name': sgg_name, 'sgg': sgg_code})
    return regions


def to_int(value):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def to_float(value):
    try:
        return round(float(value), 1)
    except (TypeError, ValueError):
        return None


def student_entry(row):
    return [to_int(row.get(f'COL_M{i}')) for i in range(1, 9)] + [to_int(row.get(f'COL_W{i}')) for i in range(1, 9)] + [to_int(row.get('SUM'))]


def meal_entry(row):
    entry = {}
    text = {'o': 'OPER_MET_CODE', 'v2': 'COL_2', 'v3': 'COL_3'}
    for short, field in text.items():
        value = (row.get(field) or '')
        value = value.strip() if isinstance(value, str) else ''
        if value and value != '-':
            entry[short] = value
    numbers = {'tot': 'HAKSAENGSU_TOT', 'mlsv': 'MLSV_STDNT_FGR', 'n': 'NTRST_FGR', 'ck': 'COOK_FGR', 'as': 'COOAS_FGR'}
    for short, field in numbers.items():
        if row.get(field) is not None and row.get(field) != '':
            entry[short] = to_int(row.get(field))
    rate = to_float(row.get('KS_RATE'))
    if rate is not None:
        entry['rate'] = rate
    places = [index for index in (4, 5, 6, 7) if str(row.get(f'COL_{index}') or '').strip()]
    if places:
        entry['p'] = places
    return entry


def collect(fetcher, regions, kinds, years, only):
    shards = {}
    disclosed = []
    total = len(regions)
    for position, region in enumerate(regions, 1):
        if only and region['sgg'] not in only:
            continue
        print(f'[{position}/{total}] {region["sido_name"]} {region["sgg_name"]}', flush=True)
        for kind in kinds:
            base = fetcher.get('0', region['sido'], region['sgg'], kind)
            schools = [row for row in base.get('list', []) if str(row.get('CLOSE_YN') or 'N').upper() != 'Y' and row.get('SCHUL_CODE')]
            if not schools:
                continue
            if len(schools) >= 500:
                print(f'  경고: 응답이 {len(schools)}건이에요. 페이지 처리 여부를 확인해야 해요.', flush=True)
            bucket = shards.setdefault(region['sgg'], {'area': '', 'kinds': {}})
            bucket['area'] = schools[0].get('ADRCD_NM') or f'{region["sido_name"]} {region["sgg_name"]}'
            entries = bucket['kinds'].setdefault(kind, {})
            for row in schools:
                entries[row['SCHUL_CODE']] = {'nm': row.get('SCHUL_NM') or '', 'st': {}, 'ml': {}}
                disclosed.append({
                    'sgg': region['sgg'], 'kind': kind, 'code': row['SCHUL_CODE'], 'name': row.get('SCHUL_NM') or '',
                    'group': SIDO.get(region['sido_name'], ''), 'rest': split_address(row.get('SCHUL_RDNMA')),
                })
            for year in years:
                for api_type, target, builder in (('63', 'st', student_entry), ('34', 'ml', meal_entry)):
                    data = fetcher.get(api_type, region['sido'], region['sgg'], kind, year)
                    for row in data.get('list', []):
                        code = row.get('SCHUL_CODE')
                        if code in entries:
                            built = builder(row)
                            if built:
                                entries[code][target][str(year)] = built
    return shards, disclosed


def match(disclosed, neis_rows):
    schools = []
    seen = set()
    for row in neis_rows:
        code = (row.get('SD_SCHUL_CODE') or '').strip()
        name = row.get('SCHUL_NM') or ''
        if not CODE_RE.match(code) or code == '0000000' or '(가칭)' in name or code in seen:
            continue
        seen.add(code)
        rest = split_address(row.get('ORG_RDNMA'))
        schools.append({'code': code, 'name': norm_name(name), 'group': group_of(row.get('ATPT_OFCDC_SC_NM')), 'rest': rest, 'key': rest_key(rest)})
    by_key = collections.defaultdict(list)
    by_district = collections.defaultdict(list)
    by_group = collections.defaultdict(list)
    for index, school in enumerate(schools):
        by_key[(school['name'], school['group'], school['key'])].append(index)
        by_district[(school['name'], school['group'], district(school['rest']))].append(index)
        by_group[(school['name'], school['group'])].append(index)
    count_district = collections.Counter((d['name'], d['group'], district(d['rest'])) for d in ({'name': norm_name(x['name']), 'group': x['group'], 'rest': x['rest']} for x in disclosed))
    count_group = collections.Counter((norm_name(x['name']), x['group']) for x in disclosed)
    used = set()
    mapping = {}
    tiers = collections.Counter()

    def assign(item, index, tier):
        used.add(index)
        mapping[schools[index]['code']] = [item['sgg'], item['kind'], item['code']]
        tiers[tier] += 1

    pending = []
    for item in disclosed:
        name = norm_name(item['name'])
        hits = [i for i in by_key.get((name, item['group'], rest_key(item['rest'])), []) if i not in used]
        if rest_key(item['rest']) and len(hits) == 1:
            assign(item, hits[0], 1)
        else:
            pending.append(item)
    still = []
    for item in pending:
        name = norm_name(item['name'])
        hits = [i for i in by_district.get((name, item['group'], district(item['rest'])), []) if i not in used]
        if item['rest'] and len(hits) == 1 and count_district[(name, item['group'], district(item['rest']))] == 1:
            assign(item, hits[0], 2)
        else:
            still.append(item)
    for item in still:
        name = norm_name(item['name'])
        hits = [i for i in by_group.get((name, item['group']), []) if i not in used]
        if len(hits) == 1 and count_group[(name, item['group'])] == 1:
            assign(item, hits[0], 3)
        else:
            tiers['miss'] += 1
    return mapping, tiers


def write_output(out_dir, shards, mapping, years, tiers):
    os.makedirs(out_dir, exist_ok=True)
    built = date.today().isoformat()
    for sgg, shard in shards.items():
        payload = {'v': 1, 'built': built, 'sgg': sgg, 'area': shard['area'], 'kinds': shard['kinds']}
        with open(os.path.join(out_dir, f'{sgg}.json'), 'w', encoding='utf-8') as handle:
            json.dump(payload, handle, ensure_ascii=False, separators=(',', ':'))
    index = {'v': 1, 'built': built, 'years': [int(y) for y in years], 'tiers': dict(tiers), 'map': dict(sorted(mapping.items()))}
    with open(os.path.join(out_dir, 'index.json'), 'w', encoding='utf-8') as handle:
        json.dump(index, handle, ensure_ascii=False, separators=(',', ':'))


def pilot(fetcher, regions, sgg, kind, years, path):
    region = next((r for r in regions if r['sgg'] == sgg), None)
    if region is None:
        raise SystemExit('시군구 코드를 찾을 수 없어요.')
    result = {}
    for api_type in PILOT_TYPES:
        result[api_type] = {}
        for year in ([None] if api_type == '0' else years):
            data = fetcher.get(api_type, region['sido'], region['sgg'], kind, year)
            rows = data.get('list', [])
            result[api_type][str(year or 0)] = {
                'resultCode': data.get('resultCode'), 'resultMsg': data.get('resultMsg'), 'count': len(rows), 'sample': rows[:3],
            }
            print(f'apiType={api_type} year={year}: {data.get("resultCode")} {len(rows)}건', flush=True)
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(result, handle, ensure_ascii=False, indent=1)
    print(f'{path} 파일을 올려 주세요.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--regions', required=True)
    parser.add_argument('--neis')
    parser.add_argument('--out', default='data/disclosure')
    parser.add_argument('--cache', default='.disclosure_cache')
    parser.add_argument('--years', default='2025,2024')
    parser.add_argument('--kinds', default=','.join(KIND_CODES))
    parser.add_argument('--delay', type=float, default=1.0)
    parser.add_argument('--max-failures', type=int, default=8)
    parser.add_argument('--only', default='')
    parser.add_argument('--pilot', default='')
    parser.add_argument('--offline', action='store_true')
    args = parser.parse_args()

    key = os.environ.get('SCHOOLINFO_KEY', '').strip()
    if not key and not args.offline:
        raise SystemExit('SCHOOLINFO_KEY 환경변수에 학교알리미 인증키를 넣어 주세요.')
    years = [y.strip() for y in args.years.split(',') if y.strip()]
    kinds = [k.strip() for k in args.kinds.split(',') if k.strip()]
    regions = read_regions(args.regions)
    fetcher = Fetcher(key, args.cache, args.delay, args.offline, args.max_failures)

    if args.pilot:
        pilot(fetcher, regions, args.pilot, kinds[0], years, 'disclosure_pilot.json')
        return
    if not args.neis:
        raise SystemExit('--neis neis_schools.json 경로가 필요해요.')
    with open(args.neis, encoding='utf-8') as handle:
        neis_rows = json.load(handle)
    only = {c.strip() for c in args.only.split(',') if c.strip()}
    shards, disclosed = collect(fetcher, regions, kinds, years, only)
    mapping, tiers = match(disclosed, neis_rows)
    write_output(args.out, shards, mapping, years, tiers)
    print(json.dumps({'schools': len(disclosed), 'matched': len(mapping), 'tiers': dict(tiers), 'calls': fetcher.calls}, ensure_ascii=False))


if __name__ == '__main__':
    main()
