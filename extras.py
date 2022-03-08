# -*- coding: utf-8 -*-

"""
Copyright (C) Zato Source s.r.o. https://zato.io

Licensed under LGPLv3, see LICENSE.txt for terms and conditions.
"""
# cp /opt/zato/3.2.0/code/zato-web-admin/src/zato/admin/web/templatetags/extras.py
# stdlib
import os

# Django
from django import template
from django.utils.safestring import mark_safe
import json
from datetime import datetime
import sqlite3
# ################################################################################################################################

register = template.Library()

# ################################################################################################################################
# Taken from https://djangosnippets.org/snippets/38/ and slightly updated

@register.filter
def bunchget(obj, args):
    """ Try to get an attribute from an object.

    Example: {% if block|bunchget:"editable,True" %}

    Beware that the default is always a string, if you want this
    to return False, pass an empty second argument:
    {% if block|bunchget:"editable," %}
    """
    args = str(args).split(',')
    if len(args) == 1:
        (attribute, default) = [args[0], '']
    else:
        (attribute, default) = args

    if attribute in obj:
        return obj[attribute]

    return default

# ################################################################################################################################

# Taken from https://stackoverflow.com/a/16609498



@register.simple_tag
def url_replace(request, field, value):
    dict_ = request.GET.copy()
    dict_[field] = value

    return dict_.urlencode()

# ################################################################################################################################

@register.filter
def no_value_indicator(value):
    return value or mark_safe('<span class="form_hint">---</span>')

# ################################################################################################################################

@register.filter
def format_float(value, digits=5):

    if not value:
        return 0

    value = str(value)
    as_float = float(value)
    as_int = int(as_float)

    if as_int == as_float:
        result = as_int
    else:
        result = round(as_float, digits)

    result = str(result)

    return result

# ################################################################################################################################

@register.filter
def stats_float(value):
    return value if value else '< 0.01'


@register.filter
def nira_stats(value):
    return get_statistics()

def is_today(str_date):
    TIME_FORMAT = "%B %d, %Y %H:%M:%S"
    DATE_FORMAT = "%B %d, %Y"
    today = datetime.now().strftime(DATE_FORMAT)
    c = to_datetime(str_date).strftime(DATE_FORMAT)
    if today == c:
        return 1
    else:
        return 0

def to_datetime(str_date):
    TIME_FORMAT = "%B %d, %Y %H:%M:%S"
    return datetime.strptime(str_date, TIME_FORMAT)

def get_statistics():
    try:
        conn = get_conn()
        if conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            sql = '''SELECT * FROM statistics'''
            cur.execute(sql)
            rows = cur.fetchall()
            stats = {}
            count = 1
            for row in rows:
                a = stats.get(row['api'])
                if a is not None:
                    d = to_datetime(row['time_accessed'])
                    b = to_datetime(a['time_accessed'])
                    if d > b:
                        a['time_accessed'] = row['time_accessed']
                    a['total_today'] = a['total_today'] + is_today(row['time_accessed'])
                    a['total_all_time'] = a['total_all_time'] + 1
                    count -= 1
                else:
                    stats[row['api']] = {
                        'id': count,
                        'user': row['username'],
                        'api': row['api'],
                        'time_accessed': row['time_accessed'],
                        'total_today': is_today(row['time_accessed']),
                        'total_all_time': 1
                    }
                    count += 1
            return [v for i, v in stats.items()]
    except Exception:
        pass
    return None

def get_conn():
    sqlite_db = r"/opt/zato/3.2.0/code/zato_sqlite.db"

    """ create a database connection to a SQLite database """
    try:
        return sqlite3.connect(sqlite_db)
    except Error as e:
        return None
# ################################################################################################################################

@register.filter
def get_item(elems, idx):
    try:
        value = elems[idx]
        return value
    except Exception:
        return None

# ################################################################################################################################

@register.filter
def endswith(value, suffix):
    if value and suffix:
        return value.endswith(suffix)

# ################################################################################################################################

@register.filter
def get_os_variable(_ignored, name):
    return os.environ.get(name)

# ################################################################################################################################
