import calendar
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta

from flask import abort, make_response, redirect, render_template, request, url_for

import neis_api
import school_data as sd

HOUR = 3600
LEVELS_WITH_DEPARTMENTS = ('고등학교', '특수학교')
MEAL_LABELS = (('breakfast', '조식'), ('lunch', '중식'), ('dinner', '석식'))
TABS = (
    ('overview', '학교 정보', 'school_overview'),
    ('schedule', '학사일정', 'school_schedule_page'),
    ('classes', '학급·학과', 'school_classes_page'),
    ('timetable', '시간표', 'school_timetable_page'),
)


class LookupFailed(Exception):
    pass


def init_school_pages(app, ctx):
    site_url = ctx['site_url'].rstrip('/')
    regions = ctx['regions']
    kst = ctx['kst']
    parse_row = ctx['parse_school_row']
    nearby = ctx['get_nearby_schools']
    meals_fn = ctx['get_month_meals']
    details_fn = ctx['get_month_meal_details']
    region_full = ctx['region_full_name']

    mode = sd.indexing_mode()

    profile_cache = neis_api.TTLCache(4000)
    data_cache = neis_api.TTLCache(6000)
    executor = ThreadPoolExecutor(max_workers=6)

    def now():
        return datetime.now(kst)

    def indexing_allowed(profile):
        return sd.indexing_allowed(profile, mode)

    def cached_fetch(key, endpoint, params, ttl, empty_ttl=HOUR, timeout=5):
        hit = data_cache.get(key)
        if hit is not None:
            return hit
        try:
            rows, code = neis_api.fetch_rows(endpoint, params, timeout=timeout)
        except Exception as exc:
            app.logger.error(f'NEIS {endpoint} 조회 실패 ({key}): {exc}')
            return data_cache.get(key, allow_stale=True)
        if rows:
            data_cache.set(key, rows, ttl)
            return rows
        if code == 'INFO-200':
            data_cache.set(key, [], empty_ttl)
            return []
        app.logger.warning(f'NEIS {endpoint} 응답에 데이터가 없습니다 ({key}, code={code or "unknown"})')
        return data_cache.get(key, allow_stale=True)

    def load_profile(code):
        if not sd.SCHOOL_CODE_RE.match(code or ''):
            return None
        hit = profile_cache.get(code)
        if hit is not None:
            return hit if hit.get('profile') else None
        try:
            rows, result = neis_api.fetch_rows('schoolInfo', {'pIndex': 1, 'pSize': 1, 'SD_SCHUL_CODE': code})
        except Exception as exc:
            app.logger.error(f'NEIS schoolInfo 조회 실패 (code={code}): {exc}')
            stale = profile_cache.get(code, allow_stale=True)
            if stale is not None:
                return stale if stale.get('profile') else None
            raise LookupFailed() from exc
        valid = [row for row in rows if sd.is_valid_school_row(row)]
        if not valid:
            if result in ('', 'INFO-200'):
                profile_cache.set(code, {}, 600)
                return None
            raise LookupFailed()
        row = valid[0]
        entry = {'profile': sd.build_profile(row), 'parsed': parse_row(row)}
        profile_cache.set(code, entry, 6 * HOUR)
        return entry

    def school_params(profile, **extra):
        params = {'pIndex': 1, 'pSize': 1000, 'ATPT_OFCDC_SC_CODE': profile['region_code'], 'SD_SCHUL_CODE': profile['code']}
        params.update(extra)
        return params

    def load_classes(profile):
        year, _ = sd.academic_year_and_semester(now().date())
        return cached_fetch(f"class:{profile['code']}:{year}", 'classInfo', school_params(profile, AY=year), 12 * HOUR)

    def load_majors(profile):
        return cached_fetch(f"major:{profile['code']}", 'schoolMajorinfo', school_params(profile), 24 * HOUR)

    def load_tracks(profile):
        return cached_fetch(f"track:{profile['code']}", 'schulAflcoinfo', school_params(profile), 24 * HOUR)

    def load_rooms(profile):
        year, semester = sd.academic_year_and_semester(now().date())
        return cached_fetch(f"room:{profile['code']}:{year}:{semester}", 'tiClrminfo',
                            school_params(profile, AY=year, SEM=semester), 12 * HOUR)

    def load_schedule_month(profile, year, month):
        last = calendar.monthrange(year, month)[1]
        first_ymd, last_ymd = f'{year}{month:02d}01', f'{year}{month:02d}{last:02d}'
        return cached_fetch(f"sched:{profile['code']}:{year}{month:02d}", 'SchoolSchedule',
                            school_params(profile, AA_FROM_YMD=first_ymd, AA_TO_YMD=last_ymd), 6 * HOUR)

    def load_today_meal(profile):
        today = now().strftime('%Y%m%d')
        month = meals_fn(profile['code'], profile['region_code']) or {}
        details = details_fn(profile['code'], profile['region_code']) or {}
        meals = month.get(today)
        detail = details.get(today, {})
        items = []
        if meals:
            for key, label in MEAL_LABELS:
                menu = meals.get(key)
                if menu and menu != '급식 정보 없음':
                    items.append({'key': key, 'label': label, 'menu': menu, 'detail': detail.get(key)})
        return {'date': today, 'items': items}

    def run_parallel(*calls):
        futures = [executor.submit(call) for call in calls]
        results = []
        for future in futures:
            try:
                results.append(future.result(timeout=9))
            except Exception as exc:
                app.logger.error(f'학교 페이지 병렬 조회 실패: {exc}')
                results.append(None)
        return results

    def region_name_of(profile):
        return next((name for name, code in regions.items() if code == profile['region_code']), None)

    def area_label(profile, parsed):
        region_name = region_name_of(profile)
        return ' '.join(part for part in (region_name, parsed.get('district')) if part)

    def shorten(text, limit):
        text = ' '.join(text.split())
        return text if len(text) <= limit else text[:limit - 1].rstrip() + '…'

    def schema_type(parsed):
        return sd.SCHEMA_TYPES.get(parsed.get('school_level'), 'School')

    def breadcrumbs(profile, parsed, region_name, page_name=None, page_url=None):
        items = [('급식알리미', f'{site_url}/'), ('학교 목록', f"{site_url}{url_for('schools_index')}")]
        level = parsed.get('school_level')
        if region_name:
            items.append((region_full(region_name), f"{site_url}{url_for('schools_by_region', region_name=region_name)}"))
            if level:
                items.append((level, f"{site_url}{url_for('schools_by_region_and_level', region_name=region_name, school_level=level)}"))
        items.append((profile['name'], f"{site_url}{url_for('school_overview', code=profile['code'])}"))
        if page_name:
            items.append((page_name, page_url))
        return {
            '@context': 'https://schema.org',
            '@type': 'BreadcrumbList',
            'itemListElement': [
                {'@type': 'ListItem', 'position': index, 'name': name, 'item': link}
                for index, (name, link) in enumerate(items, 1)
            ],
        }

    def school_ld(profile, parsed, region_name):
        data = {
            '@context': 'https://schema.org',
            '@type': schema_type(parsed),
            'name': profile['name'],
            'url': f"{site_url}{url_for('school_overview', code=profile['code'])}",
            'address': {'@type': 'PostalAddress', 'addressCountry': 'KR'},
        }
        alternates = [value for value in (profile['short_name'], profile['english_name']) if value]
        if alternates:
            data['alternateName'] = alternates
        if profile['address']:
            data['address']['streetAddress'] = profile['address']
        if profile['zip']:
            data['address']['postalCode'] = profile['zip']
        if region_name:
            data['address']['addressRegion'] = region_full(region_name)
        if parsed.get('district'):
            data['address']['addressLocality'] = parsed['district']
        if profile['phone_digits']:
            data['telephone'] = '+82-' + profile['phone_digits'][1:]
        if profile['homepage']:
            data['sameAs'] = profile['homepage']
        return data

    def base_context(entry, tab, canonical_path, robots_index, title, description, extra_ld=None):
        profile, parsed = entry['profile'], entry['parsed']
        region_name = region_name_of(profile)
        tabs = [
            {'key': key, 'label': label, 'url': url_for(endpoint, code=profile['code']), 'active': key == tab}
            for key, label, endpoint in TABS
        ]
        return {
            'profile': profile,
            'parsed': parsed,
            'region_name': region_name,
            'area': area_label(profile, parsed),
            'tabs': tabs,
            'meal_url': url_for('school_meal_view', school_code=profile['code']),
            'canonical_url': f'{site_url}{canonical_path}',
            'robots': 'index,follow' if robots_index else 'noindex,follow',
            'page_title': title,
            'page_description': shorten(description, 160),
            'ld_blocks': extra_ld or [],
            'regions': regions,
            'today_label': sd.format_ymd(now().strftime('%Y%m%d')),
            'updated_label': sd.format_ymd(profile['updated_ymd']),
        }

    def respond(template, context, indexable, max_age=600):
        response = make_response(render_template(template, **context))
        response.headers['Cache-Control'] = f'public, max-age={max_age}'
        if not indexable:
            response.headers['X-Robots-Tag'] = 'noindex, follow'
        return response

    def lookup_or_error(code):
        try:
            entry = load_profile(code)
        except LookupFailed:
            response = make_response(render_template(
                'error.html', error_code=503, error_title='학교 정보를 불러오지 못했어요',
                error_description='NEIS 서버 응답이 지연되고 있어요. 잠시 후 다시 시도해 주세요.'), 503)
            response.headers['Retry-After'] = '60'
            response.headers['Cache-Control'] = 'no-store'
            return None, response
        if entry is None:
            abort(404)
        return entry, None

    def title_with_names(profile):
        short = f"({profile['short_name']})" if profile['short_name'] else ''
        return f"{profile['name']}{short}"

    @app.route('/school/<code>')
    def school_overview(code):
        entry, error = lookup_or_error(code)
        if error:
            return error
        profile, parsed = entry['profile'], entry['parsed']
        today_ymd = now().strftime('%Y%m%d')
        nxt = now().replace(day=1) + timedelta(days=32)
        classes_rows, sched_now, sched_next, meal = run_parallel(
            lambda: load_classes(profile),
            lambda: load_schedule_month(profile, now().year, now().month),
            lambda: load_schedule_month(profile, nxt.year, nxt.month),
            lambda: load_today_meal(profile),
        )
        class_summary = sd.summarize_classes(classes_rows or [])
        events = sd.group_schedule((sched_now or []) + (sched_next or []))
        upcoming = [event for event in events if event['end'] >= today_ymd and not event['routine']][:8]
        area = area_label(profile, parsed)
        level = parsed.get('school_level') or ''
        facts = ' '.join(part for part in (profile['founding'], profile['coedu'], level) if part)
        description = f"{area} {facts} {profile['name']}의 학교 정보예요. 학급 수, 학사일정, 시간표, 오늘 급식 메뉴와 연락처·위치를 한곳에서 확인하세요."
        if class_summary['total']:
            description = f"{area} {facts} {profile['name']}. 학급 {class_summary['total']}개. 학사일정, 시간표, 오늘 급식 메뉴와 연락처·위치를 확인하세요."
        title = f"{title_with_names(profile)} 학교 정보 - {area} {level} | 급식알리미".replace('  ', ' ')
        region_name = region_name_of(profile)
        context = base_context(
            entry, 'overview', url_for('school_overview', code=code), indexing_allowed(profile), title, description,
            [school_ld(profile, parsed, region_name), breadcrumbs(profile, parsed, region_name)],
        )
        siblings = []
        try:
            siblings = nearby(parsed)[:6]
        except Exception as exc:
            app.logger.error(f'주변 학교 조회 실패 ({code}): {exc}')
        context.update({
            'class_summary': class_summary,
            'upcoming': upcoming,
            'meal': meal,
            'siblings': siblings,
            'level': level,
            'has_timetable': level in sd.KIND_TO_TIMETABLE,
            'anniversary': sd.format_anniversary(profile['anniversary']),
            'founded_label': sd.format_ymd(profile['founded_ymd']),
            'tab': 'overview',
        })
        return respond('school_overview.html', context, context['robots'].startswith('index'))

    def parse_month_arg(value):
        text = (value or '').strip()
        if len(text) == 6 and text.isdigit():
            year, month = int(text[:4]), int(text[4:])
            if 2000 <= year <= 2100 and 1 <= month <= 12:
                return year, month
        return None

    @app.route('/school/<code>/schedule')
    def school_schedule_page(code):
        entry, error = lookup_or_error(code)
        if error:
            return error
        profile, parsed = entry['profile'], entry['parsed']
        current = now()
        chosen = parse_month_arg(request.args.get('ym'))
        year, month = chosen or (current.year, current.month)
        is_current = (year, month) == (current.year, current.month)
        rows = load_schedule_month(profile, year, month)
        events = sd.group_schedule(rows or [])
        visible = [event for event in events if not event['routine']]
        routine_count = len(events) - len(visible)
        first = date(year, month, 1)
        prev_month = first - timedelta(days=1)
        next_month = first + timedelta(days=32)
        area = area_label(profile, parsed)
        title = f"{title_with_names(profile)} 학사일정 {year}년 {month}월 | 급식알리미"
        description = f"{area} {profile['name']}의 {year}년 {month}월 학사일정이에요. 시험, 방학, 개교기념일, 학교 행사를 날짜별로 확인하세요."
        if visible:
            names = ', '.join(dict.fromkeys(event['name'] for event in visible[:4]))
            description = f"{profile['name']} {year}년 {month}월 학사일정: {names} 등. 시험, 방학, 학교 행사를 날짜별로 확인하세요."
        indexable = indexing_allowed(profile) and is_current and bool(visible)
        canonical = url_for('school_schedule_page', code=code)
        region_name = region_name_of(profile)
        context = base_context(
            entry, 'schedule', canonical, indexable, title, description,
            [breadcrumbs(profile, parsed, region_name, '학사일정', f'{site_url}{canonical}')],
        )
        context.update({
            'events': visible,
            'routine_count': routine_count,
            'year': year,
            'month': month,
            'load_failed': rows is None,
            'prev_url': url_for('school_schedule_page', code=code, ym=f'{prev_month.year}{prev_month.month:02d}'),
            'next_url': url_for('school_schedule_page', code=code, ym=f'{next_month.year}{next_month.month:02d}'),
            'today_url': url_for('school_schedule_page', code=code),
            'is_current': is_current,
            'tab': 'schedule',
        })
        return respond('school_schedule.html', context, indexable, max_age=300)

    @app.route('/school/<code>/classes')
    def school_classes_page(code):
        entry, error = lookup_or_error(code)
        if error:
            return error
        profile, parsed = entry['profile'], entry['parsed']
        level = parsed.get('school_level') or ''
        with_departments = level in LEVELS_WITH_DEPARTMENTS
        classes_rows, majors_rows, tracks_rows = run_parallel(
            lambda: load_classes(profile),
            (lambda: load_majors(profile)) if with_departments else (lambda: []),
            (lambda: load_tracks(profile)) if with_departments else (lambda: []),
        )
        summary = sd.summarize_classes(classes_rows or [])
        majors = []
        seen = set()
        active_depts = {name for name, _ in summary['departments']}
        for row in majors_rows or []:
            name = sd.clean(row.get('DDDEP_NM'))
            course = sd.clean(row.get('DGHT_CRSE_SC_NM'))
            order = sd.clean(row.get('ORD_SC_NM'))
            key = (name, course, order)
            if not name or key in seen:
                continue
            seen.add(key)
            majors.append({'name': name, 'course': course, 'order': order, 'active': name in active_depts})
        majors.sort(key=lambda item: (not item['active'], item['name']))
        tracks = []
        seen_tracks = set()
        for row in tracks_rows or []:
            key = (sd.clean(row.get('ORD_SC_NM')), sd.clean(row.get('DGHT_CRSE_SC_NM')))
            if key in seen_tracks or not key[0]:
                continue
            seen_tracks.add(key)
            tracks.append({'order': key[0], 'course': key[1]})
        area = area_label(profile, parsed)
        title = f"{title_with_names(profile)} 학급·학과 정보 | 급식알리미"
        description = f"{area} {profile['name']}의 학년별 학급 수와 학과, 계열 정보예요."
        if summary['total']:
            description = f"{profile['name']}의 학급은 모두 {summary['total']}개예요. 학년별 학급 수와 학과, 계열 정보를 확인하세요."
        indexable = indexing_allowed(profile) and bool(summary['total'])
        canonical = url_for('school_classes_page', code=code)
        region_name = region_name_of(profile)
        context = base_context(
            entry, 'classes', canonical, indexable, title, description,
            [breadcrumbs(profile, parsed, region_name, '학급·학과', f'{site_url}{canonical}')],
        )
        context.update({
            'summary': summary,
            'majors': majors,
            'tracks': tracks,
            'load_failed': classes_rows is None,
            'with_departments': with_departments,
            'academic_year': sd.academic_year_and_semester(now().date())[0],
            'tab': 'classes',
        })
        return respond('school_classes.html', context, indexable, max_age=1800)

    def parse_selection(raw, options, keys):
        parts = (raw or '').split('|')
        if len(parts) != 3:
            return None
        for option in options:
            if (option['grade'], option['dept'], option[keys]) == tuple(parts):
                return option
        return None

    def parse_date_arg(value):
        text = (value or '').strip()
        for pattern in ('%Y-%m-%d', '%Y%m%d'):
            try:
                return datetime.strptime(text, pattern).date()
            except ValueError:
                continue
        return None

    @app.route('/school/<code>/timetable')
    def school_timetable_page(code):
        entry, error = lookup_or_error(code)
        if error:
            return error
        profile, parsed = entry['profile'], entry['parsed']
        level = parsed.get('school_level') or ''
        endpoint = sd.KIND_TO_TIMETABLE.get(level)
        classes_rows = load_classes(profile) if endpoint else []
        class_opts = sd.class_options(classes_rows or [])
        use_rooms = level in LEVELS_WITH_DEPARTMENTS
        room_opts = sd.room_options(load_rooms(profile) or []) if (endpoint and use_rooms) else []
        view = 'room' if (request.args.get('view') == 'room' and room_opts) else 'class'
        options = room_opts if view == 'room' else class_opts
        key = 'room' if view == 'room' else 'cls'
        selected = parse_selection(request.args.get('sel'), options, key)
        today = now().date()
        chosen_day = parse_date_arg(request.args.get('d')) or today
        monday, friday = sd.week_range(chosen_day)
        grid = None
        message = ''
        if endpoint and selected:
            year, semester = sd.academic_year_and_semester(monday)
            params = school_params(
                profile, AY=year, SEM=semester,
                TI_FROM_YMD=monday.strftime('%Y%m%d'), TI_TO_YMD=friday.strftime('%Y%m%d'),
            )
            if selected['grade']:
                params['GRADE'] = selected['grade']
            if selected['dept'] and use_rooms:
                params['DDDEP_NM'] = selected['dept']
            if view == 'room':
                params['CLRM_NM'] = selected['room']
            else:
                params['CLASS_NM'] = selected['cls']
            cache_key = f"tt:{profile['code']}:{'|'.join(str(params[name]) for name in sorted(params))}"
            rows = data_cache.get(cache_key)
            if rows is None:
                try:
                    rows, result = neis_api.fetch_rows(endpoint, params, timeout=6)
                    if rows or result == 'INFO-200':
                        data_cache.set(cache_key, rows, 600 if rows else 900)
                    else:
                        message = '시간표를 불러오지 못했어요. 잠시 후 다시 시도해주세요.'
                except Exception as exc:
                    app.logger.error(f'NEIS {endpoint} 조회 실패 (code={code}): {exc}')
                    rows = None
                    message = '시간표를 불러오지 못했어요. 잠시 후 다시 시도해주세요.'
            if rows is not None:
                grid = sd.build_timetable_grid(rows, monday)
                if grid['empty'] and not message:
                    message = '이 기간의 시간표가 NEIS에 등록되어 있지 않아요. 학교에서 시간표를 등록하지 않았거나 방학·휴업일일 수 있어요.'
        area = area_label(profile, parsed)
        title = f"{title_with_names(profile)} 시간표 | 급식알리미"
        description = f"{area} {profile['name']}의 반별 주간 시간표를 확인하세요."
        canonical = url_for('school_timetable_page', code=code)
        region_name = region_name_of(profile)
        context = base_context(
            entry, 'timetable', canonical, False, title, description,
            [breadcrumbs(profile, parsed, region_name, '시간표', f'{site_url}{canonical}')],
        )
        selected_value = ''
        if selected:
            selected_value = f"{selected['grade']}|{selected['dept']}|{selected[key]}"
        groups = []
        for option in options:
            label = f"{option['grade']}학년" if option['grade'] else '전체'
            if not groups or groups[-1]['label'] != label:
                groups.append({'label': label, 'items': []})
            groups[-1]['items'].append({
                'value': f"{option['grade']}|{option['dept']}|{option[key]}",
                'label': sd.option_label(option, key),
            })
        context.update({
            'supported': bool(endpoint),
            'groups': groups,
            'selected_value': selected_value,
            'view': view,
            'can_room_view': bool(room_opts),
            'grid': grid,
            'message': message,
            'chosen_day': chosen_day.strftime('%Y-%m-%d'),
            'week_label': f"{monday.month}월 {monday.day}일 ~ {friday.month}월 {friday.day}일",
            'prev_week': (monday - timedelta(days=7)).strftime('%Y-%m-%d'),
            'next_week': (monday + timedelta(days=7)).strftime('%Y-%m-%d'),
            'tab': 'timetable',
        })
        return respond('school_timetable.html', context, False, max_age=60)

    def saved_school_redirect(target):
        code = request.cookies.get('school_code', '')
        if sd.SCHOOL_CODE_RE.match(code):
            return redirect(url_for(target, code=code))
        return redirect(url_for('schools_index'))

    @app.route('/timetable')
    def timetable_shortcut():
        return saved_school_redirect('school_timetable_page')

    @app.route('/schedule')
    def schedule_shortcut():
        return saved_school_redirect('school_schedule_page')

    return {
        'load_profile': load_profile,
        'indexing_allowed': indexing_allowed,
        'mode': mode,
        'cache_sizes': lambda: {'profile': profile_cache.size(), 'data': data_cache.size()},
    }