import json
import os
import threading

PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'school_geo.json')

_lock = threading.Lock()
_state = {'loaded': False, 'rows': {}, 'built': '', 'stats': {}}


def _load():
    with _lock:
        if _state['loaded']:
            return
        rows = {}
        built = ''
        stats = {}
        try:
            with open(PATH, encoding='utf-8') as handle:
                payload = json.load(handle)
            rows = {code: (float(item[0]), float(item[1]), int(item[2])) for code, item in payload.get('rows', {}).items()}
            built = str(payload.get('built', ''))
            stats = payload.get('stats', {})
        except (OSError, ValueError, KeyError, IndexError, TypeError):
            rows = {}
        _state.update({'loaded': True, 'rows': rows, 'built': built, 'stats': stats})


def lookup(code):
    if not _state['loaded']:
        _load()
    item = _state['rows'].get(code)
    if item is None:
        return None
    return {'lat': item[0], 'lng': item[1], 'tier': item[2]}


def info():
    if not _state['loaded']:
        _load()
    return {'built': _state['built'], 'count': len(_state['rows']), 'stats': _state['stats']}
