import collections
import json
import os
import threading

DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'disclosure')
SHARD_LIMIT = 24
KIND_LABELS = {'02': '초등학교', '03': '중학교', '04': '고등학교', '05': '특수학교'}
PLACE_LABELS = {4: '식당', 5: '교실', 6: '식당과 교실', 7: '기타'}
POSITION_LABELS = (
    ('1', '교장'), ('2', '교감'), ('15', '수석교사'), ('3', '보직교사'), ('4', '일반교사'), ('5', '특수교사'),
    ('6', '전문상담교사'), ('7', '사서교사'), ('8', '실기교사'), ('9', '보건교사'), ('10', '영양교사'),
    ('11', '기간제교사'), ('13', '강사'), ('14', '원어민강사'),
)
METHOD_LABELS = {1: '학교 주관 구매', 2: '공동 구매', 3: '개별 구매', 4: '기타', 6: '해당 없음'}

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


def _pick(school, key):
    by_year = school.get(key) or {}
    years = _latest(by_year)
    if not years:
        return None, None
    return int(years[0]), by_year[years[0]]


def _classes(school):
    year, row = _pick(school, 'cl')
    if not row or not (row.get('a') or row.get('p')):
        return None
    return {'year': year, 'count': row.get('c'), 'avg': row.get('a'), 'ratio': row.get('p'), 'teachers': row.get('t')}


def _moves(school):
    year, row = _pick(school, 'mv')
    if not row:
        return None
    return {'year': year, 'move_in': row.get('in', 0), 'move_out': row.get('out', 0)}


def _enroll(school):
    year, row = _pick(school, 'en')
    if not row or not row.get('t'):
        return None
    return {'year': year, 'total': row['t']}


def _teachers(school):
    year, row = _pick(school, 'tc')
    if not row or not row.get('t'):
        return None
    positions = [{'label': label, 'count': row['p'][key]} for key, label in POSITION_LABELS if row.get('p', {}).get(key)]
    return {'year': year, 'total': row['t'], 'men': row.get('m', 0), 'women': row.get('w', 0), 'leave': row.get('r', 0), 'positions': positions}


def _activities(school):
    club_year, club = _pick(school, 'cb')
    after_year, after = _pick(school, 'af')
    if not club and not after:
        return None
    return {'club_year': club_year, 'club': club, 'after_year': after_year, 'after': after}


def _format_day(day):
    return f'{day[0:4]}.{day[4:6]}.{day[6:8]}' if len(day) == 8 else ''


def _safety(school):
    year, row = _pick(school, 'sf')
    if not row or not row.get('n'):
        return None
    return {'year': year, 'total': row['n'], 'managed': row.get('o', 0), 'date': _format_day(row.get('d', '')), 'unmanaged': row.get('x', [])}


def _uniform(school):
    year, row = _pick(school, 'un')
    if not row:
        return None
    lines = []
    if 'ty' in row or 'su' in row or 'lf' in row or 'gw' in row:
        if row.get('ty'):
            lines.append(('교복 유형', row['ty']))
        for label, amount, method in (('정장형', row.get('su'), row.get('sm')), ('생활형', row.get('lf'), row.get('lm')), ('체육복', row.get('gw'), row.get('gm'))):
            if amount:
                lines.append((f'{label} 낙찰가', f'{amount:,}원' + (f' ({method})' if method else '')))
        if row.get('sp'):
            lines.append(('학생 1인당 구입 지원금', f'{row["sp"]:,}원'))
    else:
        winter = [METHOD_LABELS.get(code, '') for code in row.get('dm', [])]
        summer = [METHOD_LABELS.get(code, '') for code in row.get('hm', [])]
        if winter and winter != ['해당 없음']:
            lines.append(('동복 구매 방식', ', '.join(winter)))
        if row.get('dp'):
            lines.append(('동복 평균 가격', f'{row["dp"]:,}원'))
        if summer and summer != ['해당 없음']:
            lines.append(('하복 구매 방식', ', '.join(summer)))
        if row.get('hp'):
            lines.append(('하복 평균 가격', f'{row["hp"]:,}원'))
    if not lines:
        return None
    return {'year': year, 'lines': lines}


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
    extra = {
        'classes': _classes(school), 'moves': _moves(school), 'enroll': _enroll(school), 'teachers': _teachers(school),
        'activities': _activities(school), 'safety': _safety(school), 'uniform': _uniform(school),
    }
    if not students and not meal and not any(extra.values()):
        return None
    area = shard.get('area') or ''
    if students:
        students['area'] = area
        students['kind'] = KIND_LABELS.get(kind, '')
    return {'students': students, 'meal': meal, 'built': _state['built'], **extra}
