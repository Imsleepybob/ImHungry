import collections
import csv
import json
import re
import sys
from datetime import date

SIDO = {
    '서울': '서울', '서울특별시': '서울', '부산': '부산', '부산광역시': '부산', '대구': '대구', '대구광역시': '대구',
    '인천': '인천', '인천광역시': '인천', '광주': '전남광주', '광주광역시': '전남광주', '전남': '전남광주',
    '전라남도': '전남광주', '전남광주통합특별시': '전남광주', '대전': '대전', '대전광역시': '대전',
    '울산': '울산', '울산광역시': '울산', '세종': '세종', '세종특별자치시': '세종', '경기': '경기', '경기도': '경기',
    '강원': '강원', '강원도': '강원', '강원특별자치도': '강원', '충북': '충북', '충청북도': '충북',
    '충남': '충남', '충청남도': '충남', '전북': '전북', '전라북도': '전북', '전북특별자치도': '전북',
    '전라특별자치도': '전북', '경북': '경북', '경상북도': '경북', '경남': '경남', '경상남도': '경남',
    '제주': '제주', '제주특별자치도': '제주',
}
CODE_RE = re.compile(r'^\d{5,10}$')


def norm_name(name):
    return re.sub(r'[\s·・ㆍ.\-]+', '', name or '')


def split_address(address):
    text = re.sub(r'\s+', ' ', (address or '').replace('\u3000', ' ')).strip().strip(',').strip()
    head, _, tail = text.partition(' ')
    if head in SIDO:
        return tail
    return text


def rest_key(rest):
    return re.sub(r'\s|\(.*?\)|호$', '', rest or '')


def district(rest):
    return (rest or '').split(' ')[0]


def group_of(org_name):
    name = re.sub(r'\(.*?\)', '', org_name or '').replace('교육청', '')
    return SIDO.get(name, '')


def read_csv(path):
    for encoding in ('utf-8-sig', 'cp949'):
        try:
            with open(path, encoding=encoding, newline='') as handle:
                return list(csv.DictReader(handle))
        except UnicodeDecodeError:
            continue
    raise SystemExit('CSV 인코딩을 읽을 수 없어요.')


def coordinates(row):
    try:
        lat = float(row['위도'])
        lng = float(row['경도'])
    except (KeyError, TypeError, ValueError):
        return None
    if not (33 <= lat <= 39 and 124 <= lng <= 132):
        return None
    return round(lat, 6), round(lng, 6)


def main(neis_path, csv_path, out_path):
    with open(neis_path, encoding='utf-8') as handle:
        neis_rows = json.load(handle)
    location_rows = []
    for row in read_csv(csv_path):
        point = coordinates(row)
        if point is None:
            continue
        rest = split_address(row.get('소재지도로명주소'))
        location_rows.append({
            'name': norm_name(row.get('학교명')),
            'group': group_of(row.get('시도교육청명')),
            'rest': rest,
            'key': rest_key(rest),
            'point': point,
        })

    by_key = collections.defaultdict(list)
    by_district = collections.defaultdict(list)
    by_group = collections.defaultdict(list)
    for index, row in enumerate(location_rows):
        by_key[(row['name'], row['group'], row['key'])].append(index)
        by_district[(row['name'], row['group'], district(row['rest']))].append(index)
        by_group[(row['name'], row['group'])].append(index)

    schools = []
    seen_codes = set()
    skipped = collections.Counter()
    for row in neis_rows:
        code = (row.get('SD_SCHUL_CODE') or '').strip()
        name = row.get('SCHUL_NM') or ''
        if not CODE_RE.match(code) or code == '0000000':
            skipped['code'] += 1
            continue
        if '(가칭)' in name:
            skipped['provisional'] += 1
            continue
        if code in seen_codes:
            skipped['duplicate'] += 1
            continue
        seen_codes.add(code)
        rest = split_address(row.get('ORG_RDNMA'))
        schools.append({
            'code': code,
            'kind': row.get('SCHUL_KND_SC_NM') or '',
            'name': norm_name(name),
            'group': group_of(row.get('ATPT_OFCDC_SC_NM')),
            'rest': rest,
            'key': rest_key(rest),
        })

    count_district = collections.Counter((s['name'], s['group'], district(s['rest'])) for s in schools)
    count_group = collections.Counter((s['name'], s['group']) for s in schools)

    used = set()
    result = {}
    tiers = collections.Counter()
    by_kind = collections.defaultdict(collections.Counter)

    def assign(school, index, tier):
        used.add(index)
        result[school['code']] = [location_rows[index]['point'][0], location_rows[index]['point'][1], tier]
        tiers[tier] += 1
        by_kind[school['kind']][tier] += 1

    pending = []
    for school in schools:
        hits = [i for i in by_key.get((school['name'], school['group'], school['key']), []) if i not in used]
        if school['key'] and len(hits) == 1:
            assign(school, hits[0], 1)
        else:
            pending.append(school)

    still = []
    for school in pending:
        hits = [i for i in by_district.get((school['name'], school['group'], district(school['rest'])), []) if i not in used]
        if school['rest'] and len(hits) == 1 and count_district[(school['name'], school['group'], district(school['rest']))] == 1:
            assign(school, hits[0], 2)
        else:
            still.append(school)

    for school in still:
        hits = [i for i in by_group.get((school['name'], school['group']), []) if i not in used]
        if len(hits) == 1 and count_group[(school['name'], school['group'])] == 1:
            assign(school, hits[0], 3)
        else:
            by_kind[school['kind']]['miss'] += 1
            tiers['miss'] += 1

    payload = {
        'version': 1,
        'built': date.today().isoformat(),
        'stats': {'schools': len(schools), 'locations': len(location_rows), 'tiers': dict(tiers), 'skipped': dict(skipped)},
        'rows': dict(sorted(result.items())),
    }
    with open(out_path, 'w', encoding='utf-8') as handle:
        json.dump(payload, handle, ensure_ascii=False, separators=(',', ':'))
    print(json.dumps(payload['stats'], ensure_ascii=False))
    for kind, counter in sorted(by_kind.items(), key=lambda item: -sum(item[1].values()))[:6]:
        print(kind, dict(counter))


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('사용법: python tools/build_school_geo.py neis_schools.json 위치표준데이터.csv data/school_geo.json')
    main(sys.argv[1], sys.argv[2], sys.argv[3])
