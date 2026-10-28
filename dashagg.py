import copy
import hashlib
import ipaddress
import os
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
    'rel_ips': 5000,
    'rel_paths': 30,
    'rel_uas': 5,
}

try:
    REL_RETENTION_DAYS = max(1, int(os.environ.get('DASH_REL_DAYS') or 30))
except ValueError:
    REL_RETENTION_DAYS = 30
REL_LIVE_LIMIT = 10000
REL_LIVE_PATHS = 120
REL_LIVE_UAS = 12
REL_LIVE_UA_NAMES = 5000


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
        'rel': {},
        'ua_names': {},
        'ev': {'theme': {}, 'search_method': {}, 'btn_month': 0, 'btn_nearby': 0, 'btn_share': 0, 'btn_notification': 0, 'ann': {}},
        'pwa': {'visits': 0, 'ips': {}, 'schools': {}, 'uid_visits': {}},
    }


def _inc(mapping, key, amount=1):
    mapping[key] = mapping.get(key, 0) + amount


def group_key(ip):
    if ':' in ip:
        try:
            addr = ipaddress.IPv6Address(ip)
        except ValueError:
            return ip
        if addr.ipv4_mapped:
            return group_key(str(addr.ipv4_mapped))
        return str(ipaddress.IPv6Address((int(addr) >> 64) << 64))
    parts = ip.split('.')
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        return '.'.join(parts[:3]) + '.0'
    return ip


def group_label(key):
    if ':' in key:
        return key + '/64'
    parts = key.split('.')
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        return key + '/24'
    return key


def group_matcher(key):
    if ':' in key:
        head = key.split(':', 1)[0].lower().lstrip('0')
        return lambda ip: ':' in ip and ip.split(':', 1)[0].lower().lstrip('0') == head and group_key(ip) == key
    prefix = key[:key.rfind('.') + 1]
    return lambda ip: ip.startswith(prefix) and group_key(ip) == key


def ua_id(ua):
    return hashlib.blake2s(ua.encode('utf-8', 'replace'), digest_size=5).hexdigest()


def _add_rel(agg, ip, path, ua, clock):
    rel = agg['rel']
    key = group_key(ip)
    entry = rel.get(key)
    if entry is None:
        if len(rel) >= REL_LIVE_LIMIT:
            return
        entry = {'n': 0, 'f': clock, 'l': clock, 'p': {}, 'u': {}}
        rel[key] = entry
    entry['n'] += 1
    if clock:
        if not entry['f'] or clock < entry['f']:
            entry['f'] = clock
        if clock > entry['l']:
            entry['l'] = clock
    paths = entry['p']
    if path in paths or len(paths) < REL_LIVE_PATHS:
        paths[path] = paths.get(path, 0) + 1
    if ua:
        uid = ua_id(ua)
        uas = entry['u']
        names = agg['ua_names']
        if uid in uas or len(uas) < REL_LIVE_UAS:
            if uid in names or len(names) < REL_LIVE_UA_NAMES:
                names.setdefault(uid, ua[:200])
                uas[uid] = uas.get(uid, 0) + 1


def add_access(agg, ip, status, path, referrer, kind, name, device=None, os_name=None, browser=None, ua='', clock=''):
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
    _add_rel(agg, ip, path[:200], ua, clock)
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


def _merge_rel(target, source):
    mine_rel = target.setdefault('rel', {})
    for ip, entry in (source.get('rel') or {}).items():
        mine = mine_rel.get(ip)
        if mine is None:
            mine_rel[ip] = {'n': entry['n'], 'f': entry['f'], 'l': entry['l'], 'p': dict(entry['p']), 'u': dict(entry['u'])}
            continue
        mine['n'] += entry['n']
        if entry['f'] and (not mine['f'] or entry['f'] < mine['f']):
            mine['f'] = entry['f']
        mine['l'] = max(mine['l'], entry['l'])
        _merge_counts(mine['p'], entry['p'])
        _merge_counts(mine['u'], entry['u'])
    names = target.setdefault('ua_names', {})
    for uid, name in (source.get('ua_names') or {}).items():
        names.setdefault(uid, name)


def merge(target, source, with_rel=True):
    if with_rel:
        _merge_rel(target, source)
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
    if 'rel' in out:
        rel = out['rel']
        if len(rel) > CAPS['rel_ips']:
            rel = dict(sorted(rel.items(), key=lambda item: item[1]['n'], reverse=True)[:CAPS['rel_ips']])
            out['rel'] = rel
        used = set()
        for entry in rel.values():
            entry['p'] = _top(entry['p'], CAPS['rel_paths'])
            entry['u'] = _top(entry['u'], CAPS['rel_uas'])
            used.update(entry['u'])
        out['ua_names'] = {uid: name for uid, name in out.get('ua_names', {}).items() if uid in used}
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
        merge(total, agg, with_rel=False)
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
    uid_ips = defaultdict(set)
    for ip, entry in pwa['ips'].items():
        for uid in entry['u']:
            uid_ips[uid].add(group_key(ip))
    multi_ip_devices = sorted(
        ({'uid': uid, 'ips': len(ips), 'visits': pwa['uid_visits'].get(uid, 0)} for uid, ips in uid_ips.items() if len(ips) >= 2),
        key=lambda row: (row['ips'], row['visits']), reverse=True)
    pwa_stats = {
        'multi_ip_devices': multi_ip_devices,
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
            (school_name(code), entry['v'], len(entry['u']), code)
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
        'top_schools': [(names.get(c, c), v, c) for c, v in _sorted(total['schools'], 10)],
        'all_schools': [(names.get(c, c), v, c) for c, v in _sorted(total['schools'])],
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


def _stamp(day, clock):
    return f'{day} {clock}'.strip()


def ip_profile(raw, ip):
    key = group_key(ip)
    match = group_matcher(key)
    out = {'ip': ip, 'key': key, 'label': group_label(key), 'total': 0, 'days': [], 'paths': {}, 'uas': {}, 'schools': {},
           'first': '', 'last': '', 'partial': False, 'pwa_visits': 0, 'pwa_last': '', 'uids': {}}
    for day, aggs in sorted(raw.items()):
        day_total = 0
        for agg in aggs:
            rel = agg.get('rel')
            entry = rel.get(key) if rel is not None else None
            if entry:
                day_total += entry['n']
                _merge_counts(out['paths'], entry['p'])
                names = agg.get('ua_names') or {}
                for uid, count in entry['u'].items():
                    row = out['uas'].setdefault(uid, {'name': names.get(uid, ''), 'n': 0})
                    row['n'] += count
                    if not row['name']:
                        row['name'] = names.get(uid, '')
                if entry['f'] and (not out['first'] or _stamp(day, entry['f']) < out['first']):
                    out['first'] = _stamp(day, entry['f'])
                if entry['l'] and _stamp(day, entry['l']) > out['last']:
                    out['last'] = _stamp(day, entry['l'])
            else:
                legacy = sum(count for other, count in agg['user_ips'].items() if match(other))
                day_total += legacy
                if legacy and rel is not None:
                    out['partial'] = True
            for other, pwa in agg['pwa']['ips'].items():
                if not match(other):
                    continue
                out['pwa_visits'] += pwa['v']
                out['pwa_last'] = max(out['pwa_last'], pwa['l'])
                for uid in pwa['u']:
                    out['uids'].setdefault(uid, {'visits': 0, 'ips': {}})
                for code, count in pwa['s'].items():
                    out['schools'].setdefault(code, {'web': 0, 'pwa': 0})['pwa'] += count
        if day_total:
            out['days'].append({'day': day, 'total': day_total})
            out['total'] += day_total
            if not out['first'] or day < out['first'][:10]:
                out['first'] = day
            if day > out['last'][:10]:
                out['last'] = day
    for path, count in out['paths'].items():
        found = SCHOOL_PATH_RE.match(path)
        if found:
            out['schools'].setdefault(found.group(1), {'web': 0, 'pwa': 0})['web'] += count
    if out['uids']:
        for aggs in raw.values():
            for agg in aggs:
                for uid in out['uids']:
                    out['uids'][uid]['visits'] += agg['pwa']['uid_visits'].get(uid, 0)
                for other, entry in agg['pwa']['ips'].items():
                    other_key = group_key(other)
                    if other_key == key:
                        continue
                    for uid in entry['u']:
                        if uid in out['uids']:
                            ips = out['uids'][uid]['ips']
                            ips[other_key] = max(ips.get(other_key, ''), entry['l'])
    return out


def school_profile(raw, code):
    path_key = '/meal/' + code
    out = {'code': code, 'web_visits': 0, 'ips': [], 'pwa_visits': 0, 'pwa_devices': set(), 'pwa_ips': {}, 'tracked': False}
    ips = {}
    for day, aggs in sorted(raw.items()):
        for agg in aggs:
            out['web_visits'] += agg['schools'].get(code, 0)
            rel = agg.get('rel')
            if rel is not None:
                out['tracked'] = True
                for key, entry in rel.items():
                    count = entry['p'].get(path_key)
                    if not count:
                        continue
                    row = ips.setdefault(key, {'ip': key, 'n': 0, 'last': ''})
                    row['n'] += count
                    row['last'] = max(row['last'], _stamp(day, entry['l']))
            school = agg['pwa']['schools'].get(code)
            if school:
                out['pwa_visits'] += school['v']
                out['pwa_devices'].update(school['u'])
            for ip, entry in agg['pwa']['ips'].items():
                count = entry['s'].get(code)
                if count:
                    key = group_key(ip)
                    out['pwa_ips'][key] = out['pwa_ips'].get(key, 0) + count
    out['ips'] = sorted(ips.values(), key=lambda row: row['n'], reverse=True)
    out['pwa_devices'] = sorted(out['pwa_devices'])
    return out


def ua_profile(raw, uid):
    out = {'uid': uid, 'name': '', 'total': 0, 'ips': [], 'tracked': False}
    ips = {}
    for day, aggs in sorted(raw.items()):
        for agg in aggs:
            rel = agg.get('rel')
            if rel is None:
                continue
            out['tracked'] = True
            name = (agg.get('ua_names') or {}).get(uid)
            if name and not out['name']:
                out['name'] = name
            for key, entry in rel.items():
                count = entry['u'].get(uid)
                if not count:
                    continue
                row = ips.setdefault(key, {'ip': key, 'n': 0, 'last': ''})
                row['n'] += count
                row['last'] = max(row['last'], _stamp(day, entry['l']))
                out['total'] += count
    out['ips'] = sorted(ips.values(), key=lambda row: row['n'], reverse=True)
    return out


def ua_index(raw, limit=None):
    names, counts = {}, {}
    ips = defaultdict(set)
    for aggs in raw.values():
        for agg in aggs:
            for uid, name in (agg.get('ua_names') or {}).items():
                names.setdefault(uid, name)
            for key, entry in (agg.get('rel') or {}).items():
                for uid, count in entry['u'].items():
                    counts[uid] = counts.get(uid, 0) + count
                    ips[uid].add(key)
    rows = [{'uid': uid, 'name': names.get(uid, ''), 'n': count, 'ips': len(ips[uid])} for uid, count in counts.items()]
    rows.sort(key=lambda row: row['n'], reverse=True)
    return rows[:limit] if limit else rows


def device_profile(raw, uid):
    out = {'uid': uid, 'visits': 0, 'days': [], 'ips': {}, 'schools': {}}
    for day, aggs in sorted(raw.items()):
        day_visits = 0
        for agg in aggs:
            day_visits += agg['pwa']['uid_visits'].get(uid, 0)
            for ip, entry in agg['pwa']['ips'].items():
                if uid in entry['u']:
                    row = out['ips'].setdefault(group_key(ip), {'last': '', 'days': set()})
                    row['last'] = max(row['last'], entry['l'])
                    row['days'].add(day)
            for code, entry in agg['pwa']['schools'].items():
                if uid in entry['u']:
                    out['schools'][code] = out['schools'].get(code, 0) + 1
        if day_visits:
            out['days'].append({'day': day, 'visits': day_visits})
            out['visits'] += day_visits
    for row in out['ips'].values():
        row['days'] = len(row['days'])
    return out
