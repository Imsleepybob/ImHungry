import collections
import json
import os
import threading

DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'disclosure')
SHARD_LIMIT = 24
KIND_LABELS = {'02': '초등학교', '03': '중학교', '04': '고등학교', '05': '특수학교'}
PLACE_LABELS = {4: '식당', 5: '교실', 6: '식당과 교실', 7: '기타'}

_lock = threading.Lock()
_state = {'loaded': False, 'map': {}, 'built': '', 'years': []}
_shards = collections.OrderedDict()


def _read(path):
    try:
        with open(path, encoding='utf-8') as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def _load_index():
    with _lock:
        if _state['loaded']:
            return
        payload = _read(os.path.join(DIR, 'index.json')) or {}
        _state.update({
            'loaded': True,
            'map': payload.get('map', {}) if isinstance(payload.get('map'), dict) else {},
            'built': str(payload.get('built', '')),
            'years': payload.get('years', []),
        })


def _shard(sgg):
    with _lock:
        if sgg in _shards:
            _shards.move_to_end(sgg)
            return _shards[sgg]
    payload = _read(os.path.join(DIR, f'{sgg}.json'))
    with _lock:
        _shards[sgg] = payload
        _shards.move_to_end(sgg)
        while len(_shards) > SHARD_LIMIT:
            _shards.popitem(last=False)
    return payload


def _latest(by_year):
    years = sorted((y for y in by_year if by_year[y]), reverse=True)
    return years


def _students(school, peers):
    years = _latest(school.get('st', {}))
    if not years:
        return None
    year = years[0]
    row = school['st'][year]
    if len(row) < 17 or not row[16]:
        return None
    men = sum(row[0:8])
    women = sum(row[8:16])
    grades = []
    for index in range(6):
        total = row[index] + row[8 + index]
        if total:
            grades.append({'label': f'{index + 1}학년', 'm': row[index], 'w': row[8 + index], 'total': total})
    extra = []
    for index, label in ((6, '특수학급'), (7, '순회학급')):
        total = row[index] + row[8 + index]
        if total:
            extra.append({'label': label, 'm': row[index], 'w': row[8 + index], 'total': total})
    diff = None
    if len(years) > 1 and len(school['st'][years[1]]) >= 17 and school['st'][years[1]][16]:
        diff = row[16] - school['st'][years[1]][16]
    totals = [p['st'][year][16] for p in peers if year in p.get('st', {}) and len(p['st'][year]) >= 17 and p['st'][year][16]]
    average = round(sum(totals) / len(totals)) if len(totals) >= 3 else None
    return {
        'year': int(year), 'total': row[16], 'men': men, 'women': women, 'grades': grades, 'extra': extra,
        'diff': diff, 'avg': average, 'avg_count': len(totals),
    }


def _meal(school):
    years = _latest(school.get('ml', {}))
    if not years:
        return None
    year = years[0]
    row = school['ml'][year]
    operation = row.get('o') or ''
    vendors = [row[key] for key in ('v2', 'v3') if row.get(key)]
    staff = []
    for key, label in (('n', '영양(교)사'), ('ck', '조리사'), ('as', '조리원')):
        if row.get(key):
            staff.append(f'{label} {row[key]}명')
    places = [PLACE_LABELS[p] for p in row.get('p', []) if p in PLACE_LABELS]
    if not (operation or row.get('mlsv') or staff or places):
        return None
    return {
        'year': int(year), 'operation': operation, 'vendors': vendors, 'students': row.get('mlsv') or 0,
        'total': row.get('tot') or 0, 'rate': row.get('rate'), 'staff': ', '.join(staff), 'place': ', '.join(places),
    }


def lookup(code):
    if not _state['loaded']:
        _load_index()
    entry = _state['map'].get(code)
    if not entry or len(entry) != 3:
        return None
    sgg, kind, school_code = entry
    shard = _shard(sgg)
    if not shard:
        return None
    peers_map = shard.get('kinds', {}).get(kind, {})
    school = peers_map.get(school_code)
    if not school:
        return None
    peers = list(peers_map.values())
    students = _students(school, peers)
    meal = _meal(school)
    if not students and not meal:
        return None
    area = shard.get('area') or ''
    if students:
        students['area'] = area
        students['kind'] = KIND_LABELS.get(kind, '')
    return {'students': students, 'meal': meal, 'built': _state['built']}
