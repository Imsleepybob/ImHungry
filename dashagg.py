import copy
import re
from collections import defaultdict
from datetime import date, datetime, timedelta

SCHOOL_PATH_RE = re.compile(r'^/meal/(\w+)$')
REFERRER_RE = re.compile(r'https?://([^/]+)')
EVENT_COUNTERS = ('btn_month', 'btn_nearby', 'btn_share', 'btn_notification')
ANN_EVENTS = {'ann_view': 0, 'ann_close': 1}

CAPS = {
    'ips': 20000,
    'user_ips': 5000,
    'user_paths': 600,
    'bot_paths': 600,
    'bot_ips': 1500,
    'bot_ip_paths': 30,
    'schools': 4000,
    'referrers': 300,
    'crawler_names': 300,
    'pwa_ips': 2000,
    'pwa_schools': 2000,
    'pwa_uids': 4000,
}


def new_agg():
    return {
        'n': 0,
        'ips': {},
        'status': {},
        'crawlers': 0,
        'users': 0,
        'crawler_names': {},
        'bot_ips': {},
        'bot_paths': {},
        'user_ips': {},
        'user_paths': {},
        'schools': {},
        'referrers': {},
        'devices': {},
        'os': {},
        'browsers': {},
        'ev': {'theme': {}, 'search_method': {}, 'btn_month': 0, 'btn_nearby': 0, 'btn_share': 0, 'btn_notification': 0, 'ann': {}},
        'pwa': {'visits': 0, 'ips': {}, 'schools': {}, 'uid_visits': {}},
    }


def _inc(mapping, key, amount=1):
    mapping[key] = mapping.get(key, 0) + amount


def add_access(agg, ip, status, path, referrer, kind, name, device=None, os_name=None, browser=None):
    agg['n'] += 1
    _inc(agg['ips'], ip)
    _inc(agg['status'], status)
    if kind == 'bot':
        agg['crawlers'] += 1
        _inc(agg['crawler_names'], name)
        entry = agg['bot_ips'].setdefault(ip, {'t': 0, 'p': {}, 'c': 'Unknown'})
        entry['t'] += 1
        _inc(entry['p'], path)
        entry['c'] = name
        _inc(agg['bot_paths'], path)
        return
    _inc(agg['user_ips'], ip)
    _inc(agg['user_paths'], path)
    school = SCHOOL_PATH_RE.match(path)
    if school:
        _inc(agg['schools'], school.group(1))
    if referrer and referrer != 'N/A':
        host = REFERRER_RE.match(referrer)
        if host:
            _inc(agg['referrers'], host.group(1))
    agg['users'] += 1
    _inc(agg['devices'], device)
    _inc(agg['os'], os_name)
    _inc(agg['browsers'], browser)


def add_event(agg, event, value):
    ev = agg['ev']
    if event == 'theme':
        _inc(ev['theme'], value)
    elif event == 'search_method':
        _inc(ev['search_method'], value)
    elif event in EVENT_COUNTERS:
        ev[event] += 1
    elif event in ANN_EVENTS:
        key = re.sub(r'[^0-9a-fA-F]', '', str(value))[:32]
        if key:
            entry = ev.setdefault('ann', {}).setdefault(key, [0, 0])
            entry[ANN_EVENTS[event]] += 1


def add_pwa(agg, ip, uid, code, ts):
    pwa = agg['pwa']
    pwa['visits'] += 1
    entry = pwa['ips'].setdefault(ip, {'v': 0, 'u': [], 's': {}, 'l': ''})
    entry['v'] += 1
    if ts > entry['l']:
        entry['l'] = ts
    if uid:
        if uid not in entry['u']:
            entry['u'].append(uid)
        _inc(pwa['uid_visits'], uid)
    if code:
        _inc(entry['s'], code)
        school = pwa['schools'].setdefault(code, {'v': 0, 'u': []})
        school['v'] += 1
        if uid and uid not in school['u']:
            school['u'].append(uid)


def _merge_counts(target, source):
    for key, value in source.items():
        target[key] = target.get(key, 0) + value


def merge(target, source):
    target['n'] += source['n']
    target['crawlers'] += source['crawlers']
    target['users'] += source['users']
    for key in ('ips', 'status', 'crawler_names', 'bot_paths', 'user_ips', 'user_paths', 'schools', 'referrers', 'devices', 'os', 'browsers'):
        _merge_counts(target[key], source[key])
    for ip, entry in source['bot_ips'].items():
        mine = target['bot_ips'].setdefault(ip, {'t': 0, 'p': {}, 'c': 'Unknown'})
        mine['t'] += entry['t']
        _merge_counts(mine['p'], entry['p'])
        mine['c'] = entry['c'] or mine['c']
    for key in ('theme', 'search_method'):
        _merge_counts(target['ev'][key], source['ev'][key])
    for key in EVENT_COUNTERS:
        target['ev'][key] += source['ev'][key]
    for key, counts in source['ev'].get('ann', {}).items():
        mine = target['ev'].setdefault('ann', {}).setdefault(key, [0, 0])
        mine[0] += counts[0]
        mine[1] += counts[1]
    target_pwa, source_pwa = target['pwa'], source['pwa']
    target_pwa['visits'] += source_pwa['visits']
    _merge_counts(target_pwa['uid_visits'], source_pwa['uid_visits'])
    for ip, entry in source_pwa['ips'].items():
        mine = target_pwa['ips'].setdefault(ip, {'v': 0, 'u': [], 's': {}, 'l': ''})
        mine['v'] += entry['v']
        mine['l'] = max(mine['l'], entry['l'])
        for uid in entry['u']:
            if uid not in mine['u']:
                mine['u'].append(uid)
        _merge_counts(mine['s'], entry['s'])
    for code, entry in source_pwa['schools'].items():
        mine = target_pwa['schools'].setdefault(code, {'v': 0, 'u': []})
        mine['v'] += entry['v']
        for uid in entry['u']:
            if uid not in mine['u']:
                mine['u'].append(uid)
    return target


def _top(mapping, limit):
    if len(mapping) <= limit:
        return dict(mapping)
    return dict(sorted(mapping.items(), key=lambda item: item[1], reverse=True)[:limit])


def compact(agg):
    out = copy.deepcopy(agg)
    for key, cap in (('ips', 'ips'), ('user_ips', 'user_ips'), ('user_paths', 'user_paths'), ('bot_paths', 'bot_paths'),
                     ('schools', 'schools'), ('referrers', 'referrers'), ('crawler_names', 'crawler_names')):
        out[key] = _top(out[key], CAPS[cap])
    if len(out['bot_ips']) > CAPS['bot_ips']:
        out['bot_ips'] = dict(sorted(out['bot_ips'].items(), key=lambda item: item[1]['t'], reverse=True)[:CAPS['bot_ips']])
    for entry in out['bot_ips'].values():
        entry['p'] = _top(entry['p'], CAPS['bot_ip_paths'])
    pwa = out['pwa']
    if len(pwa['ips']) > CAPS['pwa_ips']:
        pwa['ips'] = dict(sorted(pwa['ips'].items(), key=lambda item: item[1]['v'], reverse=True)[:CAPS['pwa_ips']])
    if len(pwa['schools']) > CAPS['pwa_schools']:
        pwa['schools'] = dict(sorted(pwa['schools'].items(), key=lambda item: item[1]['v'], reverse=True)[:CAPS['pwa_schools']])
    pwa['uid_visits'] = _top(pwa['uid_visits'], CAPS['pwa_uids'])
    return out


def window_dates(today, days):
    cutoff = today - timedelta(days=days)
    return cutoff, [(cutoff + timedelta(days=i)).isoformat() for i in range((today - cutoff).days + 1)]


def _sorted(mapping, limit=None):
    items = sorted(mapping.items(), key=lambda item: item[1], reverse=True)
    return items[:limit] if limit else items


def finalize(day_aggs, today, days, school_name, cache_stats, security_stats):
    total = new_agg()
    requests_by_day = {}
    pwa_by_day = {}
    today_requests = 0
    pwa_today = 0
    for day, agg in sorted(day_aggs.items()):
        merge(total, agg)
        if agg['n']:
            requests_by_day[day] = agg['n']
        if agg['pwa']['visits']:
            pwa_by_day[day] = agg['pwa']['visits']
        if day == today.isoformat():
            today_requests = agg['n']
            pwa_today = agg['pwa']['visits']

    names = {}
    for code in total['schools']:
        names[code] = school_name(code)

    pwa = total['pwa']
    pwa_stats = {
        'devices': len(pwa['uid_visits']),
        'returning_devices': sum(1 for count in pwa['uid_visits'].values() if count >= 2),
        'ips': len(pwa['ips']),
        'visits': pwa['visits'],
        'today_visits': pwa_today,
        'ip_list': [
            {
                'ip': ip,
                'visits': entry['v'],
                'devices': len(entry['u']),
                'schools': [(school_name(code), count) for code, count in _sorted(entry['s'])],
                'last_seen': entry['l'][:16].replace('T', ' '),
            }
            for ip, entry in sorted(pwa['ips'].items(), key=lambda item: item[1]['v'], reverse=True)
        ],
        'school_list': [
            (school_name(code), entry['v'], len(entry['u']))
            for code, entry in sorted(pwa['schools'].items(), key=lambda item: item[1]['v'], reverse=True)
        ],
        'by_day': dict(sorted(pwa_by_day.items())[-14:]),
    }

    return {
        'total_requests': total['n'],
        'unique_ips': len(total['ips']),
        'today_requests': today_requests,
        'crawlers': total['crawlers'],
        'users': total['users'],
        'requests_by_day': dict(sorted(requests_by_day.items())[-14:]),
        'status_codes': dict(sorted(total['status'].items())),
        'top_user_paths': _sorted(total['user_paths'], 15),
        'all_user_paths': _sorted(total['user_paths']),
        'top_bot_paths': _sorted(total['bot_paths'], 15),
        'all_bot_paths': _sorted(total['bot_paths']),
        'top_schools': [(names.get(c, c), v) for c, v in _sorted(total['schools'], 10)],
        'all_schools': [(names.get(c, c), v) for c, v in _sorted(total['schools'])],
        'top_ips': _sorted(total['user_ips'], 10),
        'all_ips': _sorted(total['user_ips']),
        'top_referrers': _sorted(total['referrers'], 10),
        'all_referrers': _sorted(total['referrers']),
        'devices': dict(total['devices']),
        'os_names': dict(_sorted(total['os'])),
        'browsers': dict(total['browsers']),
        'top_crawlers': _sorted(total['crawler_names'], 15),
        'all_crawlers': _sorted(total['crawler_names']),
        'bot_ip_list': [
            {'ip': ip, 'total': entry['t'], 'crawler_name': entry['c'], 'top_paths': _sorted(entry['p'], 5)}
            for ip, entry in sorted(total['bot_ips'].items(), key=lambda item: item[1]['t'], reverse=True)
        ],
        'events': {
            'theme': dict(total['ev']['theme']),
            'search_method': dict(total['ev']['search_method']),
            'btn_month': total['ev']['btn_month'],
            'btn_nearby': total['ev']['btn_nearby'],
            'btn_share': total['ev']['btn_share'],
            'btn_notification': total['ev']['btn_notification'],
            'ann': {key: {'views': counts[0], 'closes': counts[1]} for key, counts in total['ev'].get('ann', {}).items()},
        },
        'cache_stats': cache_stats,
        'security': security_stats,
        'pwa': pwa_stats,
        'days': days,
    }
