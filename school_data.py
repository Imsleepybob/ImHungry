import calendar
import json
import os
import re
import zlib
from datetime import date, datetime, timedelta

SCHOOL_CODE_RE = re.compile(r'^\d{5,10}$')
YMD_RE = re.compile(r'^\d{8}$')
ALLERGY_RE = re.compile(r'\(([0-9][0-9\.\s]*)\)')

ALLERGENS = {
    1: '난류', 2: '우유', 3: '메밀', 4: '땅콩', 5: '대두', 6: '밀', 7: '고등어',
    8: '게', 9: '새우', 10: '돼지고기', 11: '복숭아', 12: '토마토', 13: '아황산류',
    14: '호두', 15: '닭고기', 16: '쇠고기', 17: '오징어', 18: '조개류', 19: '잣',
}

KIND_TO_TIMETABLE = {
    '초등학교': 'elsTimetable',
    '중학교': 'misTimetable',
    '고등학교': 'hisTimetable',
    '특수학교': 'spsTimetable',
}

SCHEMA_TYPES = {
    '초등학교': 'ElementarySchool',
    '중학교': 'MiddleSchool',
    '고등학교': 'HighSchool',
}

GRADE_KEYS = (
    ('ONE_GRADE_EVENT_YN', 1), ('TW_GRADE_EVENT_YN', 2), ('THREE_GRADE_EVENT_YN', 3),
    ('FR_GRADE_EVENT_YN', 4), ('FIV_GRADE_EVENT_YN', 5), ('SIX_GRADE_EVENT_YN', 6),
)

WEEKDAYS = ('월', '화', '수', '목', '금', '토', '일')
WEEKDAY_FULL = ('월요일', '화요일', '수요일', '목요일', '금요일', '토요일', '일요일')
HOLIDAY_KINDS = ('공휴일', '휴업일')


def clean(value):
    if value is None:
        return ''
    return re.sub(r'\s+', ' ', str(value)).strip()


def today_ymd(now=None):
    return (now or datetime.now()).strftime('%Y%m%d')


def is_valid_school_row(row):
    code = clean(row.get('SD_SCHUL_CODE'))
    name = clean(row.get('SCHUL_NM'))
    region = clean(row.get('ATPT_OFCDC_SC_CODE'))
    return bool(SCHOOL_CODE_RE.match(code) and name and region)


def is_planned_school(row, today=None):
    founded = clean(row.get('FOND_YMD'))
    if name_is_provisional(row.get('SCHUL_NM')):
        return True
    return bool(YMD_RE.match(founded) and founded > (today or today_ymd()))


def name_is_provisional(name):
    return '(가칭)' in clean(name).replace(' ', '')


def short_school_name(name):
    name = clean(name)
    for suffix, short in (('여자고등학교', '여고'), ('여자중학교', '여중'), ('여자상업고등학교', '여상'),
                          ('고등학교', '고'), ('중학교', '중'), ('초등학교', '초')):
        if name.endswith(suffix) and len(name) > len(suffix):
            return name[:-len(suffix)] + short
    return ''


def _strip_school_name(text, school_name):
    if school_name:
        text = text.replace(school_name, '')
    text = re.sub(r'\(\s*[,\s]*\)', '', text)
    text = re.sub(r'\(\s*,\s*', '(', text)
    text = re.sub(r'\s*,\s*\)', ')', text)
    text = re.sub(r'\s*,\s*,+\s*', ', ', text)
    return text.strip(' ,')


def build_address(row):
    main = clean(row.get('ORG_RDNMA')).rstrip(', ').strip()
    detail = _strip_school_name(clean(row.get('ORG_RDNDA')), clean(row.get('SCHUL_NM')))
    if not main:
        return ''
    if detail:
        return clean(f'{main} {detail}')
    return main


def normalize_homepage(value):
    text = clean(value)
    if not text:
        return ''
    lowered = text.lower()
    if lowered in ('http://', 'https://', 'http:', 'https:', '-', '없음', 'null', 'none', 'n/a'):
        return ''
    if not re.match(r'^https?://', lowered):
        text = 'http://' + text
    match = re.match(r'^https?://([^\s/?#]+)', text, re.IGNORECASE)
    if not match or '.' not in match.group(1):
        return ''
    return text.rstrip('/') if text.count('/') <= 3 else text


def format_phone(value):
    text = clean(value)
    if not text:
        return '', ''
    first = re.split(r'[,/;]', text)[0]
    digits = re.sub(r'\D', '', first)
    if digits.startswith('82'):
        digits = '0' + digits[2:]
    if not digits.startswith('0') or not 8 <= len(digits) <= 11:
        return '', ''
    area_len = 2 if digits.startswith('02') else 3
    area, rest = digits[:area_len], digits[area_len:]
    if len(rest) == 7:
        shown = f'{area}-{rest[:3]}-{rest[3:]}'
    elif len(rest) == 8:
        shown = f'{area}-{rest[:4]}-{rest[4:]}'
    else:
        return '', ''
    return shown, digits


def build_profile(row):
    phone, phone_digits = format_phone(row.get('ORG_TELNO'))
    fax, _ = format_phone(row.get('ORG_FAXNO'))
    kind = clean(row.get('SCHUL_KND_SC_NM'))
    founded_ymd = clean(row.get('FOND_YMD'))
    anniv = clean(row.get('FOAS_MEMRD'))
    return {
        'code': clean(row.get('SD_SCHUL_CODE')),
        'name': clean(row.get('SCHUL_NM')),
        'short_name': short_school_name(row.get('SCHUL_NM')),
        'english_name': clean(row.get('ENG_SCHUL_NM')),
        'kind': kind,
        'region_code': clean(row.get('ATPT_OFCDC_SC_CODE')),
        'region_name': clean(row.get('ATPT_OFCDC_SC_NM')),
        'location': clean(row.get('LCTN_SC_NM')),
        'office': clean(row.get('JU_ORG_NM')),
        'founding': clean(row.get('FOND_SC_NM')),
        'zip': clean(row.get('ORG_RDNZC')),
        'address': build_address(row),
        'phone': phone,
        'phone_digits': phone_digits,
        'fax': fax,
        'homepage': normalize_homepage(row.get('HMPG_ADRES')),
        'coedu': clean(row.get('COEDU_SC_NM')),
        'hs_type': clean(row.get('HS_SC_NM')),
        'special': clean(row.get('SPCLY_PURPS_HS_ORD_NM')),
        'general_business': clean(row.get('HS_GNRL_BUSNS_SC_NM')),
        'industry_class': clean(row.get('INDST_SPECL_CCCCL_EXST_YN')) == 'Y',
        'entrance_term': clean(row.get('ENE_BFE_SEHF_SC_NM')),
        'day_night': clean(row.get('DGHT_SC_NM')),
        'founded_ymd': founded_ymd if YMD_RE.match(founded_ymd) else '',
        'anniversary': anniv if YMD_RE.match(anniv) else '',
        'updated_ymd': clean(row.get('LOAD_DTM'))[:8],
        'planned': is_planned_school(row),
    }


def format_ymd(ymd, with_year=True):
    text = clean(ymd)
    if not YMD_RE.match(text):
        return ''
    if with_year:
        return f'{int(text[:4])}년 {int(text[4:6])}월 {int(text[6:8])}일'
    return f'{int(text[4:6])}월 {int(text[6:8])}일'


def format_anniversary(value):
    text = clean(value)
    if YMD_RE.match(text):
        return f'{int(text[4:6])}월 {int(text[6:8])}일'
    if re.match(r'^\d{4}$', text):
        return f'{int(text[:2])}월 {int(text[2:])}일'
    return ''


def has_contact(profile):
    return bool(profile.get('phone') or profile.get('homepage'))


def indexable_by_profile(profile):
    return bool(
        profile.get('code') and profile.get('name') and profile.get('address')
        and has_contact(profile) and not profile.get('planned')
    )


def _split_lines(text):
    parts = re.split(r'<br\s*/?>|\n', str(text or ''))
    return [clean(part) for part in parts if clean(part)]


def _pairs(text):
    pairs = []
    for line in _split_lines(text):
        if ':' not in line:
            continue
        label, _, value = line.partition(':')
        label, value = clean(label), clean(value)
        if label and value:
            pairs.append((label, value))
    return pairs


def _to_int(value):
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    if number <= 0:
        return None
    return int(round(number))


def allergen_numbers(menu):
    found = set()
    for group in ALLERGY_RE.findall(str(menu or '')):
        for token in re.split(r'[\.\s]+', group):
            if token.isdigit() and 1 <= int(token) <= 19:
                found.add(int(token))
    return sorted(found)


def parse_meal_detail(row):
    calories = clean(row.get('CAL_INFO'))
    people = _to_int(row.get('MLSV_FGR'))
    nutrients = _pairs(row.get('NTR_INFO'))
    origins = _pairs(row.get('ORPLC_INFO'))
    numbers = allergen_numbers(row.get('DDISH_NM'))
    return {
        'calories': calories,
        'people': people,
        'nutrients': nutrients,
        'origins': origins,
        'allergens': [{'no': number, 'name': ALLERGENS[number]} for number in numbers],
    }


MEAL_TYPE_KEYS = {'1': 'breakfast', '2': 'lunch', '3': 'dinner'}


def build_meal_details(rows):
    details = {}
    for row in rows:
        key = MEAL_TYPE_KEYS.get(clean(row.get('MMEAL_SC_CODE')))
        date_str = clean(row.get('MLSV_YMD'))
        if not key or not YMD_RE.match(date_str):
            continue
        detail = parse_meal_detail(row)
        if detail['calories'] or detail['people'] or detail['nutrients'] or detail['origins'] or detail['allergens']:
            details.setdefault(date_str, {})[key] = detail
    return details


def meal_summary_text(menu, limit=70):
    items = []
    for line in re.split(r'\n|<br\s*/?>', str(menu or '')):
        item = ALLERGY_RE.sub('', line)
        item = re.sub(r'\s+', ' ', item).strip(' .,/')
        if item:
            items.append(item)
    text = ', '.join(items)
    if len(text) > limit:
        text = text[:limit].rstrip(' ,') + '…'
    return text


def _parse_ymd(value):
    return datetime.strptime(value, '%Y%m%d').date()


def group_schedule(rows):
    cleaned = []
    for row in rows:
        ymd = clean(row.get('AA_YMD'))
        name = clean(row.get('EVENT_NM'))
        if not YMD_RE.match(ymd) or not name:
            continue
        applied, existing = [], []
        for key, grade in GRADE_KEYS:
            flag = clean(row.get(key))
            if flag and flag != '*':
                existing.append(grade)
            if flag == 'Y':
                applied.append(grade)
        cleaned.append({
            'ymd': ymd,
            'name': name,
            'content': clean(row.get('EVENT_CNTNT')),
            'kind': clean(row.get('SBTR_DD_SC_NM')),
            'course': clean(row.get('DGHT_CRSE_SC_NM')),
            'applied': applied,
            'existing': existing,
        })
    cleaned.sort(key=lambda item: (item['ymd'], item['name']))
    events = []
    for item in cleaned:
        merged = False
        for event in events:
            if (event['name'] == item['name'] and event['kind'] == item['kind']
                    and event['applied'] == item['applied'] and event['course'] == item['course']
                    and _parse_ymd(item['ymd']) - _parse_ymd(event['end']) == timedelta(days=1)):
                event['end'] = item['ymd']
                event['days'] += 1
                merged = True
                break
        if not merged:
            events.append({
                'name': item['name'], 'content': item['content'], 'kind': item['kind'],
                'course': item['course'], 'applied': item['applied'], 'existing': item['existing'],
                'start': item['ymd'], 'end': item['ymd'], 'days': 1,
            })
    for event in events:
        event['all_grades'] = bool(event['existing']) and event['applied'] == event['existing']
        event['routine'] = event['name'] == '토요휴업일'
        start, end = _parse_ymd(event['start']), _parse_ymd(event['end'])
        event['start_label'] = f'{start.month}월 {start.day}일({WEEKDAYS[start.weekday()]})'
        event['end_label'] = f'{end.month}월 {end.day}일({WEEKDAYS[end.weekday()]})'
        event['grade_label'] = grade_label(event)
    return events


def grade_label(event):
    if event['all_grades'] or not event['applied']:
        return '전 학년' if event['all_grades'] else ''
    return ', '.join(f'{grade}학년' for grade in event['applied'])


def _grade_sort_key(value):
    return (0, int(value)) if str(value).isdigit() else (1, str(value))


def summarize_classes(rows):
    grades = {}
    courses, orders = [], []
    for row in rows:
        grade = clean(row.get('GRADE'))
        class_name = clean(row.get('CLASS_NM'))
        dept = clean(row.get('DDDEP_NM'))
        course = clean(row.get('DGHT_CRSE_SC_NM'))
        order = clean(row.get('ORD_SC_NM'))
        if not grade and not class_name:
            continue
        bucket = grades.setdefault(grade, {'count': 0, 'depts': {}})
        bucket['count'] += 1
        if dept:
            bucket['depts'][dept] = bucket['depts'].get(dept, 0) + 1
        if course and course not in courses:
            courses.append(course)
        if order and order not in orders:
            orders.append(order)
    result = []
    for grade in sorted(grades, key=_grade_sort_key):
        bucket = grades[grade]
        result.append({
            'grade': grade,
            'count': bucket['count'],
            'depts': sorted(bucket['depts'].items(), key=lambda item: (-item[1], item[0])),
        })
    all_depts = {}
    for item in result:
        for dept, count in item['depts']:
            all_depts[dept] = all_depts.get(dept, 0) + count
    return {
        'total': sum(item['count'] for item in result),
        'grades': result,
        'courses': courses,
        'orders': orders,
        'departments': sorted(all_depts.items(), key=lambda item: (-item[1], item[0])),
    }


def class_options(rows):
    seen = set()
    options = []
    for row in rows:
        grade = clean(row.get('GRADE'))
        dept = clean(row.get('DDDEP_NM'))
        class_name = clean(row.get('CLASS_NM'))
        if not class_name:
            continue
        key = (grade, dept, class_name)
        if key in seen:
            continue
        seen.add(key)
        options.append({'grade': grade, 'dept': dept, 'cls': class_name})
    options.sort(key=lambda item: (_grade_sort_key(item['grade']), item['dept'], _grade_sort_key(item['cls'])))
    return options


def room_options(rows):
    seen = set()
    options = []
    for row in rows:
        grade = clean(row.get('GRADE'))
        dept = clean(row.get('DDDEP_NM'))
        room = clean(row.get('CLRM_NM'))
        if not room:
            continue
        key = (grade, dept, room)
        if key in seen:
            continue
        seen.add(key)
        options.append({'grade': grade, 'dept': dept, 'room': room})
    options.sort(key=lambda item: (_grade_sort_key(item['grade']), item['dept'], _grade_sort_key(item['room'])))
    return options


def option_label(option, key):
    parts = []
    if option.get('grade'):
        parts.append(f"{option['grade']}학년")
    if option.get('dept'):
        parts.append(option['dept'])
    value = option.get(key, '')
    if value:
        parts.append(f'{value}반' if str(value).isdigit() and key == 'cls' else str(value))
    return ' '.join(parts)


def academic_year_and_semester(day):
    year = day.year if day.month >= 3 else day.year - 1
    semester = '1' if 3 <= day.month <= 8 else '2'
    return str(year), semester


def week_range(day):
    if day.weekday() >= 5:
        day = day + timedelta(days=7 - day.weekday())
    monday = day - timedelta(days=day.weekday())
    return monday, monday + timedelta(days=4)


def build_timetable_grid(rows, monday):
    cells = {}
    periods = set()
    for row in rows:
        ymd = clean(row.get('ALL_TI_YMD'))
        period = clean(row.get('PERIO'))
        subject = clean(row.get('ITRT_CNTNT'))
        if not YMD_RE.match(ymd) or not period.isdigit():
            continue
        periods.add(int(period))
        cells[(ymd, int(period))] = subject
    days = []
    for offset in range(5):
        day = monday + timedelta(days=offset)
        days.append({'ymd': day.strftime('%Y%m%d'), 'label': f'{day.month}/{day.day}({WEEKDAYS[day.weekday()]})',
                     'md': f'{day.month}/{day.day}', 'wd': WEEKDAYS[day.weekday()]})
    period_list = sorted(periods)
    table = []
    for period in period_list:
        table.append({'period': period, 'cells': [cells.get((day['ymd'], period), '') for day in days]})
    return {'days': days, 'rows': table, 'empty': not cells}


INDEX_MODES = ('off', 'gate', 'on')


def indexing_mode():
    mode = (os.environ.get('SCHOOL_PAGE_INDEXING') or 'gate').strip().lower()
    return mode if mode in INDEX_MODES else 'gate'


def indexing_allowed(profile, mode=None):
    mode = mode or indexing_mode()
    if mode == 'off' or profile.get('planned'):
        return False
    if mode == 'on':
        return True
    return indexable_by_profile(profile)


def sitemap_item(row, mode=None):
    if not is_valid_school_row(row):
        return None
    profile = build_profile(row)
    if not indexing_allowed(profile, mode):
        return None
    updated = profile['updated_ymd']
    lastmod = f'{updated[:4]}-{updated[4:6]}-{updated[6:8]}' if YMD_RE.match(updated) else ''
    return profile['code'], lastmod


def meal_seo(school_name, area, ymd, meals, details):
    name = clean(school_name)
    names = name
    area = clean(area)
    if area:
        title = f'{names} 급식 메뉴 - {area} 오늘 급식과 이번 주 급식 | 급식알리미'
    else:
        title = f'{names} 급식 메뉴 - 오늘 급식과 이번 주 급식 | 급식알리미'
    chosen = None
    for key, label in (('lunch', '중식'), ('dinner', '석식'), ('breakfast', '조식')):
        value = (meals or {}).get(key)
        if value and value != '급식 정보 없음':
            chosen = (key, label, value)
            break
    description = f'{names}의 오늘 급식과 이번 주 급식 메뉴, 열량, 알레르기 정보를 확인하세요.'
    if chosen and YMD_RE.match(clean(ymd)):
        key, label, value = chosen
        day = _parse_ymd(ymd)
        day_label = f'{day.month}월 {day.day}일({WEEKDAYS[day.weekday()]})'
        summary = meal_summary_text(value, 80)
        calories = ((details or {}).get(key) or {}).get('calories', '')
        extra = f' 열량 {calories}.' if calories else ''
        description = f'{day_label} {name} {label}은 {summary}.{extra} 이번 주 급식과 알레르기 정보도 확인하세요.'
    return title, description


def build_calendar(year, month, events, today=None):
    today_text = (today or date.today()).strftime('%Y%m%d')
    offset = (date(year, month, 1).weekday() + 1) % 7
    total = calendar.monthrange(year, month)[1]
    cells = [None] * offset
    for day in range(1, total + 1):
        ymd = f'{year}{month:02d}{day:02d}'
        weekday = (offset + day - 1) % 7
        items = []
        for event in events:
            if event['start'] <= ymd <= event['end']:
                holiday = event['kind'] in HOLIDAY_KINDS
                span = ''
                if event['days'] > 1:
                    span = f"{event['start_label']} ~ {event['end_label']}"
                kind = event['kind'] if event['kind'] and event['kind'] != '해당없음' else ''
                items.append({
                    'name': event['name'], 'content': event['content'], 'grade': event['grade_label'],
                    'kind': kind, 'range': span, 'holiday': holiday,
                })
        items.sort(key=lambda item: (not item['holiday'], item['name']))
        real_weekday = date(year, month, day).weekday()
        cells.append({
            'day': day,
            'ymd': ymd,
            'weekday': weekday,
            'events': items,
            'is_today': ymd == today_text,
            'holiday': any(item['holiday'] for item in items),
            'title': f'{month}월 {day}일 {WEEKDAY_FULL[real_weekday]}',
            'payload': [
                {'n': item['name'], 'c': item['content'], 'g': item['grade'], 'k': item['kind'],
                 'r': item['range'], 'h': item['holiday']}
                for item in items
            ],
        })
    while len(cells) % 7:
        cells.append(None)
    return [cells[index:index + 7] for index in range(0, len(cells), 7)]



DETAIL_FIELDS = ('MLSV_YMD', 'MMEAL_SC_CODE', 'CAL_INFO', 'MLSV_FGR', 'NTR_INFO', 'ORPLC_INFO', 'DDISH_NM')


def pack_meal_details(rows):
    compact = []
    for row in rows:
        if clean(row.get('MMEAL_SC_CODE')) not in MEAL_TYPE_KEYS:
            continue
        compact.append([row.get(field) for field in DETAIL_FIELDS])
    if not compact:
        return None
    return zlib.compress(json.dumps(compact, ensure_ascii=False, separators=(',', ':')).encode('utf-8'), 6)


def unpack_meal_details(blob):
    if not blob:
        return {}
    try:
        rows = json.loads(zlib.decompress(blob).decode('utf-8'))
    except (zlib.error, ValueError):
        return {}
    return build_meal_details([dict(zip(DETAIL_FIELDS, values)) for values in rows])
