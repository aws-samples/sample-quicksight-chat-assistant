"""Compile a structured aggregate query into one parameterized, read-only SELECT. Pure functions, no I/O.

The model never writes SQL. It sends {metrics, dimensions, time, filters, order_by, limit}; unknown keys are refused,
every identifier must be a known dataset column (mapped to its physical expression), every aggregate and operator
comes from a fixed list, and every value is a bound parameter: a string of at most MAX_VALUE_LENGTH characters or a
finite number (lists only for in / not_in / between; is_null / not_null take none). The relation is always one
quoted table, never custom SQL.
"""

import math
import re

AGGS = {"sum": "SUM({})", "avg": "AVG({})", "min": "MIN({})", "max": "MAX({})", "count": "COUNT({})",
        "count_distinct": "COUNT(DISTINCT {})"}
GRAINS = ("hour", "day", "week", "month", "quarter", "year")
OPS = ("eq", "ne", "in", "not_in", "gt", "gte", "lt", "lte", "between", "contains", "is_null", "not_null")
LIST_OPS, NULL_OPS = ("in", "not_in", "between"), ("is_null", "not_null")
MAX_METRICS, MAX_DIMENSIONS, MAX_FILTERS, MAX_POLICY_FILTERS, MAX_IN_VALUES, MAX_LIMIT = 10, 3, 12, 50, 200, 500
MAX_VALUE_LENGTH = 500
DATE_ONLY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SPEC_KEYS = {"metrics", "dimensions", "time", "filters", "order_by", "limit"}
METRIC_KEYS, TIME_KEYS, ORDER_KEYS = {"column", "agg"}, {"column", "grain"}, {"name", "desc"}
FILTER_KEYS = {"column", "op", "value", "values"}


class QueryError(ValueError):
    pass


class Dialect:
    """Identifier quoting, time truncation and parameter style for one engine."""

    name = "base"

    def quote(self, identifier):
        raise NotImplementedError

    def trunc(self, expression, grain):
        raise NotImplementedError

    def param(self, name):
        raise NotImplementedError

    def contains(self, expression, placeholder):
        raise NotImplementedError

    def next_day(self, placeholder):
        raise NotImplementedError


class Postgres(Dialect):
    name = "postgresql"

    def quote(self, identifier):
        return '"' + identifier.replace('"', '""') + '"'

    def trunc(self, expression, grain):
        return f"date_trunc('{grain}', {expression})"

    def param(self, name):
        return f":{name}"  # pg8000.native named parameters

    def contains(self, expression, placeholder):
        return f"CAST({expression} AS TEXT) ILIKE {placeholder}"

    def next_day(self, placeholder):
        return f"(CAST({placeholder} AS DATE) + 1)"


class MySQL(Dialect):
    name = "mysql"

    def quote(self, identifier):
        return "`" + identifier.replace("`", "``") + "`"

    def trunc(self, expression, grain):
        # Literal % must be doubled because PyMySQL formats the statement with pyformat parameters.
        return {
            "hour": f"DATE_FORMAT({expression}, '%%Y-%%m-%%d %%H:00:00')",
            "day": f"DATE({expression})",
            "week": f"DATE_SUB(DATE({expression}), INTERVAL WEEKDAY({expression}) DAY)",
            "month": f"DATE_FORMAT({expression}, '%%Y-%%m-01')",
            "quarter": f"MAKEDATE(YEAR({expression}), 1) + INTERVAL (QUARTER({expression}) - 1) QUARTER",
            "year": f"DATE_FORMAT({expression}, '%%Y-01-01')",
        }[grain]

    def param(self, name):
        return f"%({name})s"

    def contains(self, expression, placeholder):
        return f"CAST({expression} AS CHAR) LIKE {placeholder}"

    def next_day(self, placeholder):
        return f"(DATE({placeholder}) + INTERVAL 1 DAY)"


DIALECTS = {"postgresql": Postgres(), "mysql": MySQL()}


def _escape_like(value):
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


INDEXED = re.compile(r"^values\s*\[\s*(\d)\s*\]$")


def _list_value(flt, listed):
    """The list operand of in / not_in / between. Some models garble the key name ("values[]", "values 范围内",
    "values[0]" + "values[1]"); accept those rather than burning a model round trip on a retry. `listed` is one
    representation (_operand refuses mixed ones): one "values..." key, or only indexed keys values[0], values[1]..."""
    if not listed:
        return flt.get("value")
    indexed = sorted((int(m.group(1)), flt[k]) for k in listed if (m := INDEXED.match(k.strip())))
    if len(indexed) < len(listed):
        return flt[listed[0]]
    if [i for i, _ in indexed] == list(range(len(indexed))):  # contiguous from 0, no duplicates
        return [v for _, v in indexed]
    return None


def _known_keys(obj, allowed, where):
    """Refuse keys outside `allowed`; filters also keep the garbled "values..." names _list_value accepts."""
    unknown = [str(k) for k in obj if k not in allowed
               and not (allowed is FILTER_KEYS and isinstance(k, str) and k.strip().startswith("values"))]
    if unknown:
        raise QueryError(f"{where} 不支持的字段：{', '.join(unknown)[:200]}")


def _scalar(value):
    """A bound value: a string of at most MAX_VALUE_LENGTH characters or a finite number (not a bool)."""
    if isinstance(value, str) and len(value) <= MAX_VALUE_LENGTH:
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value):
        return value
    raise QueryError(f"过滤值只能是字符串（最多 {MAX_VALUE_LENGTH} 个字符）或有限的数字")


def _operand(flt, op):
    """The filter's operand in the shape its operator takes, and nothing else: none for is_null / not_null, a list for
    in / not_in / between ("values", one garbled "values..." key, indexed values[0], values[1]..., or "value"), one
    scalar "value" for the rest. An operand counts as given when its key is present, even with a null value."""
    listed = [k for k in flt if isinstance(k, str) and k.strip().startswith("values")]
    given = "value" in flt
    if op in NULL_OPS:
        if given or listed:
            raise QueryError(f"{op} 不需要 value 或 values")
        return None
    if op in LIST_OPS:
        if given and listed:
            raise QueryError(f'{op} 只用 "values"，不要同时给 value')
        if len(listed) > 1 and any(not INDEXED.match(k.strip()) for k in listed):  # two lists, or a list + indexed
            raise QueryError(f'{op} 只能给一个列表 "values": [...]，不要重复或混用 values 键')
        return _list_value(flt, listed)  # schema: "values" is the list form
    if listed:
        raise QueryError(f'{op} 需要单个 "value"；列表（values）只用于 in、not_in 和 between')
    value = flt.get("value")
    if value is None or isinstance(value, (list, dict)):
        raise QueryError(f"{op} 需要单个值")
    return _scalar(value)


def compile_query(spec, columns, source, dialect, mandatory_filters=None, policy_columns=None):
    """Return (sql, params, output_columns, limit).

    `columns` is the caller-visible map. `mandatory_filters` is trusted policy derived from the authorized QuickSight
    definition and may reference only `policy_columns`; those columns remain unavailable everywhere else.
    """
    if not isinstance(spec, dict):
        raise QueryError("查询参数必须是对象")
    _known_keys(spec, SPEC_KEYS, "查询")
    if "table" not in (source or {}):
        raise QueryError("只支持基于表（RelationalTable）的数据集")
    params, counter = {}, [0]

    def bind(value):
        name = f"p{counter[0]}"
        counter[0] += 1
        params[name] = value
        return dialect.param(name)

    def column(name, purpose, available=None):
        available = columns if available is None else available
        info = available.get(name) if isinstance(name, str) else None
        if info is None:
            raise QueryError(f"{purpose}引用了不存在或不可用的列：{name}")
        return dialect.quote(info["expr"]), info

    metrics = spec.get("metrics") or []
    if not isinstance(metrics, list) or not 1 <= len(metrics) <= MAX_METRICS:
        raise QueryError(f"metrics 需要 1 到 {MAX_METRICS} 个")
    dimensions = spec.get("dimensions") or []
    if not isinstance(dimensions, list) or len(dimensions) > MAX_DIMENSIONS:
        raise QueryError(f"dimensions 最多 {MAX_DIMENSIONS} 个")
    filters = spec.get("filters") or []
    if not isinstance(filters, list) or len(filters) > MAX_FILTERS:
        raise QueryError(f"filters 最多 {MAX_FILTERS} 个")
    mandatory_filters = mandatory_filters or []
    if not isinstance(mandatory_filters, list) or len(mandatory_filters) > MAX_POLICY_FILTERS:
        raise QueryError(f"分析的强制过滤器最多支持 {MAX_POLICY_FILTERS} 个")
    policy_columns = policy_columns or columns
    try:
        limit = max(1, min(MAX_LIMIT, int(spec.get("limit") or 200)))
    except (TypeError, ValueError, OverflowError) as error:
        raise QueryError("limit 必须是整数") from error

    select, group, out = [], [], []
    time = spec.get("time")
    if time:
        if not isinstance(time, dict) or time.get("grain") not in GRAINS:
            raise QueryError(f"time.grain 只能是 {', '.join(GRAINS)}")
        _known_keys(time, TIME_KEYS, "time")
        expression, info = column(time.get("column"), "time ")
        if info["type"] not in ("DATETIME", "DATE"):
            raise QueryError(f"{time['column']} 不是日期时间列")
        select.append(f"{dialect.trunc(expression, time['grain'])} AS {dialect.quote('__time')}")
        group.append("1")
        out.append({"name": time["column"], "role": "time", "grain": time["grain"]})
    for name in dimensions:
        expression, _info = column(name, "dimensions ")
        select.append(f"{expression} AS {dialect.quote('__d' + str(len(out)))}")
        group.append(str(len(select)))
        out.append({"name": name, "role": "dimension"})
    used = {}
    for metric in metrics:
        if not isinstance(metric, dict) or not isinstance(metric.get("agg"), str) or metric["agg"] not in AGGS:
            raise QueryError(f"metrics[].agg 只能是 {', '.join(AGGS)}")
        _known_keys(metric, METRIC_KEYS, "metrics[]")
        agg, name = metric["agg"], metric.get("column")
        if agg == "count" and name in (None, "", "*"):
            expression, label = "*", "count"
        else:
            expression, info = column(name, "metrics ")
            if agg in ("sum", "avg") and info["type"] not in ("INTEGER", "DECIMAL"):
                raise QueryError(f"{name} 不是数值列，不能做 {agg}")
            label = name if name not in used else f"{agg}_{name}"
        used[name] = True
        if label in [o["name"] for o in out]:
            label = f"{agg}_{label}"
        select.append(f"{AGGS[agg].format(expression)} AS {dialect.quote('__m' + str(len(out)))}")
        out.append({"name": label, "role": "metric", "column": name, "agg": agg})

    where = []
    for index, flt in enumerate([*filters, *mandatory_filters]):
        if not isinstance(flt, dict) or flt.get("op") not in OPS:
            raise QueryError(f"filters[].op 只能是 {', '.join(OPS)}")
        _known_keys(flt, FILTER_KEYS, "filters[]")
        available = columns if index < len(filters) else policy_columns
        expression, info = column(flt.get("column"), "filters ", available)
        op = flt["op"]
        value = _operand(flt, op)
        is_time = info["type"] in ("DATETIME", "DATE")
        if op in NULL_OPS:
            where.append(f"{expression} IS {'NOT ' if op == 'not_null' else ''}NULL")
            continue
        if op in ("in", "not_in"):
            if not isinstance(value, list) or not 1 <= len(value) <= MAX_IN_VALUES:
                raise QueryError(f'{op} 需要 "values": [...]（键名正好是 values，1 到 {MAX_IN_VALUES} 个值）')
            placeholders = ", ".join(bind(_scalar(v)) for v in value)
            where.append(f"{expression} {'NOT ' if op == 'not_in' else ''}IN ({placeholders})")
            continue
        if op == "between":
            if not isinstance(value, list) or len(value) != 2:
                raise QueryError('between 需要 "values": ["最小值", "最大值"]（键名正好是 values，两个元素）；'
                                 '也可以改用一个 gte 加一个 lte 条件')
            low, high = _scalar(value[0]), _scalar(value[1])
            if is_time and isinstance(high, str) and DATE_ONLY.match(high):
                where.append(f"{expression} >= {bind(low)} AND {expression} < {dialect.next_day(bind(high))}")
            else:
                where.append(f"{expression} BETWEEN {bind(low)} AND {bind(high)}")
            continue
        if op == "contains":
            where.append(dialect.contains(expression, bind("%" + _escape_like(str(value)) + "%")))
            continue
        if is_time and op == "lte" and isinstance(value, str) and DATE_ONLY.match(value):
            # A date-only upper bound on a timestamp includes that whole day, as QuickSight's date filters do.
            where.append(f"{expression} < {dialect.next_day(bind(value))}")
            continue
        symbol = {"eq": "=", "ne": "<>", "gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[op]
        where.append(f"{expression} {symbol} {bind(value)}")

    schema, name = source["table"]
    relation = (dialect.quote(schema) + "." if schema else "") + dialect.quote(name)

    order = []
    for item in spec.get("order_by") or []:
        if not isinstance(item, dict):
            raise QueryError("order_by 每项需要 {name, desc}")
        _known_keys(item, ORDER_KEYS, "order_by[]")
        names = [o["name"] for o in out]
        if item.get("name") not in names:
            raise QueryError(f"order_by 只能用输出列：{', '.join(names)}")
        order.append(f"{names.index(item['name']) + 1} {'DESC' if item.get('desc') else 'ASC'}")
    if not order:
        order = [str(i + 1) for i, o in enumerate(out) if o["role"] != "metric"] or ["1"]

    # Only quoted known identifiers and fixed SQL fragments are formatted in; every value is a bound parameter.
    sql = f"SELECT {', '.join(select)} FROM {relation}"  # nosec B608
    if where:
        sql += " WHERE " + " AND ".join(where)
    if group:
        sql += " GROUP BY " + ", ".join(group)
    sql += " ORDER BY " + ", ".join(order) + f" LIMIT {limit + 1}"  # one extra row tells whether it was truncated
    return sql, params, out, limit
