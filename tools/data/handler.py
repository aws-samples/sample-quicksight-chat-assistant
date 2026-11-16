"""Gateway Lambda target: read-only, aggregate queries on the datasets of the analysis the chat is embedded in.

Tools (the Runtime adds `_caller` and `_analysis` to every call):
- describe_dataset(dataset_id)       columns, types, whether direct querying is supported and why not
- query_dataset(dataset_id, ...)     structured aggregate query compiled to one parameterized SELECT
- distinct_values(dataset_id, column, search?)   up to 50 values, e.g. to check a control value exists

Access rules: the caller must be allowed to view the analysis (or a dashboard published from it), the dataset must
be one the analysis uses, the dataset must pass dataset.plan() (one relational table; no custom SQL, RLS, dataset
filters or joins), and only CLS-permitted visual/reachable-control columns from the exact authorized analysis or
published dashboard definition can be described, queried or listed. Reproducible whole-analysis filters are enforced
as policy predicates. Database credentials come only from the assistant's own Secrets Manager secret
`<DATASOURCE_SECRET_PREFIX><DataSourceId>` holding a dedicated SELECT-only user and an operator-approved target/TLS
pin (`./qsca datasource-secret`); the QuickSight data source's own secret is never used.
"""

import datetime as dt
import decimal
import json
import os
import ssl
import time

import boto3

import caller
import dataset as ds
import definition as defs
import logging_utils
import sqlcompile
from caller import ToolError, log

SECRET_PREFIX = os.environ.get("DATASOURCE_SECRET_PREFIX", "quicksight-chat-assistant/datasource/")
CA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rds-ca.pem")
qs = caller.qs
_connections = {}
# query_dataset input: the QuerySpec, the dataset and the fields the Runtime sets in code (agent/main.py WithCaller).
QUERY_ARGS = {"dataset_id", "_caller", "_analysis", "_parameters", "_preview_capability", *sqlcompile.SPEC_KEYS}
DATABASE_STRING_LIMIT = 2000


def _dataset(args, preview_query=None):
    """Check access and return (dataset description, caller-scoped plan) for args['dataset_id']."""
    email, aid, dashboard_id = caller.require_viewer(args)
    dataset_id = str(args.get("dataset_id") or "")
    _name, definition = caller.viewer_definition(aid, dashboard_id)
    used = {d["DataSetArn"].rsplit("/", 1)[-1] for d in definition.get("DataSetIdentifierDeclarations", [])}
    if dataset_id not in used:
        raise ToolError(f"数据集 {dataset_id} 不属于当前分析；可用的数据集：{', '.join(sorted(used))}")
    description = caller.cached(f"ds:{dataset_id}", lambda: qs.describe_data_set(
        AwsAccountId=caller.ACCOUNT, DataSetId=dataset_id)["DataSet"])
    queryable = defs.viewer_columns(definition).get(dataset_id, set())
    if preview_query is not None:
        caller.verify_preview_capability(args.get("_preview_capability"), email, aid, preview_query)
        queryable = queryable | {metric.get("column") for metric in preview_query.get("metrics", [])
                                 if isinstance(metric, dict) and metric.get("column")}
    try:
        plan = ds.plan(description, caller.principals(email), referenced=queryable)
        plan["_definition"] = definition
        plan["_dataset_id"] = dataset_id
        plan["_parameters"] = args.get("_parameters") if isinstance(args.get("_parameters"), dict) else {}
        return description, plan
    except ds.Unsupported as error:
        raise ToolError(f"内置查询不支持这个数据集：{error}。如已接入其他数据工具（如 MCP），请改用它们。") from error


def _secret(data_source):
    """Return the assistant-owned credential record, including its operator-approved target pin."""
    name = SECRET_PREFIX + data_source["DataSourceId"]
    try:
        secret = json.loads(boto3.client("secretsmanager").get_secret_value(SecretId=name)["SecretString"])
        if not isinstance(secret, dict):
            raise ValueError("secret is not an object")
        return secret
    except Exception as error:  # noqa: BLE001 - reported to the admin below
        raise ToolError(f"找不到数据源 {data_source['DataSourceId']} 的数据库凭证。请管理员用只有 SELECT 权限的数据库用户运行 "
                        f"./qsca datasource-secret {data_source['DataSourceId']}（Secrets Manager 里的 {name}）。"
                        f"({type(error).__name__})") from error


def _target(source, info):
    target = {"data_source_arn": source.get("Arn"), "engine": info.get("engine"), "host": info.get("host"),
              "port": int(info.get("port") or 0), "database": info.get("database"), "tls_required": True}
    if info.get("rds_instance"):
        target["rds_instance"] = info["rds_instance"]
    return target


def _connect(data_source_arn):
    data_source_id = data_source_arn.rsplit("/", 1)[-1]
    source = qs.describe_data_source(AwsAccountId=caller.ACCOUNT, DataSourceId=data_source_id)["DataSource"]
    try:
        info = ds.connection(source)
    except ds.Unsupported as error:
        raise ToolError(f"内置查询不支持这个数据源：{error}") from error
    if "rds_instance" in info:
        rds = boto3.client("rds", endpoint_url=os.environ.get("RDS_ENDPOINT_URL") or None)
        instance = rds.describe_db_instances(DBInstanceIdentifier=info["rds_instance"])["DBInstances"][0]
        info["host"], info["port"] = instance["Endpoint"]["Address"], instance["Endpoint"]["Port"]
        engine = str(instance.get("Engine") or "").lower()
        if "postgres" in engine:
            info["engine"] = "postgresql"
        elif engine in ("mysql", "mariadb", "aurora-mysql"):
            info["engine"] = "mysql"
        else:
            raise ToolError(f"RDS 引擎 {engine or 'unknown'} 不受内置查询支持")
    current = _target(source, info)
    record = _secret(source)
    if record.get("target") != current:
        raise ToolError(f"数据源 {data_source_id} 的地址、数据库、引擎或 TLS 设置与管理员批准的凭证绑定不一致；"
                        f"请管理员核对后重新运行 ./qsca datasource-secret {data_source_id}")
    try:
        user, password = record["username"], record["password"]
        if not isinstance(user, str) or not isinstance(password, str):
            raise TypeError("credentials must be strings")
    except (KeyError, TypeError) as error:
        raise ToolError(f"数据源 {data_source_id} 的凭证格式不正确；请重新运行 ./qsca datasource-secret {data_source_id}") from error

    cached = _connections.get(data_source_id)
    if cached:
        try:
            cached["ping"]()
            return cached
        except Exception:  # noqa: BLE001 - stale connection, reconnect
            _connections.pop(data_source_id, None)

    context = ssl.create_default_context()
    if os.path.exists(CA_FILE):
        context.load_verify_locations(CA_FILE)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    if info["engine"] == "postgresql":
        import pg8000.native
        conn = pg8000.native.Connection(user=user, password=password, host=info["host"], port=info["port"],
                                        database=info["database"], ssl_context=context, timeout=30,
                                        application_name="quicksight-chat-assistant")
        tls_status = conn.run("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
        if not tls_status or tls_status[0][0] is not True:
            conn.close()
            raise ToolError("数据库会话没有建立 TLS，已在执行查询前中止")
        conn.run("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
        conn.run("SET statement_timeout = 20000")  # milliseconds

        def run(sql, params):
            rows = conn.run(sql, **params)
            return [c["name"] for c in conn.columns], rows
        entry = {"engine": "postgresql", "run": run, "ping": lambda: conn.run("SELECT 1"), "close": conn.close}
    else:
        import pymysql
        from pymysql.constants import CLIENT

        class VerifiedTlsConnection(pymysql.connections.Connection):
            def _request_authentication(self):
                # connect() reads the server greeting before this hook. Abort before any authentication response if
                # the server cannot negotiate TLS; PyMySQL otherwise permits a silent plaintext fallback.
                if not self.ssl or not self.server_capabilities & CLIENT.SSL:
                    raise pymysql.err.OperationalError("database server does not support required TLS")
                return super()._request_authentication()

        conn = VerifiedTlsConnection(host=info["host"], port=info["port"], user=user, password=password,
                                     database=info["database"], ssl=context, connect_timeout=15, read_timeout=60,
                                     autocommit=False, charset="utf8mb4")
        if not getattr(conn, "_secure", False):
            conn.close()
            raise ToolError("数据库连接没有建立 TLS，已在执行查询前中止")
        with conn.cursor() as cursor:
            cursor.execute("SHOW STATUS LIKE 'Ssl_cipher'")
            tls_status = cursor.fetchone()
            if not tls_status or not tls_status[1]:
                conn.close()
                raise ToolError("数据库会话没有可验证的 TLS 密码套件，已在执行查询前中止")
            cursor.execute("SET SESSION max_execution_time = 20000")  # milliseconds
            cursor.execute("SET SESSION TRANSACTION READ ONLY")

        def run(sql, params):
            with conn.cursor() as cursor:
                cursor.execute(sql, params)
                rows = cursor.fetchall()
                names = [d[0] for d in cursor.description]
            conn.rollback()
            return names, rows
        entry = {"engine": "mysql", "run": run, "ping": conn.ping, "close": conn.close}
    _connections[data_source_id] = entry
    return entry


def _plain(value):
    if isinstance(value, decimal.Decimal):
        return float(value)
    if isinstance(value, (dt.datetime, dt.date)):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")[:DATABASE_STRING_LIMIT]
    if isinstance(value, str):
        return value[:DATABASE_STRING_LIMIT]
    return value


def describe_dataset(args):
    description, plan = _dataset(args)
    return {"dataset_id": description["DataSetId"], "name": description.get("Name"),
            "import_mode": description.get("ImportMode"),
            "columns": [{"name": n, "type": c["type"]} for n, c in sorted(plan["columns"].items())],
            "hidden_columns": plan["hidden"], "notes": plan["notes"],
            "note": "SPICE 数据集查询的是数据源里的当前数据，可能比 SPICE 上次刷新更新。" if description.get("ImportMode") == "SPICE" else ""}


def _execute(plan, spec):
    try:
        mandatory = defs.mandatory_filters(plan["_definition"], plan["_dataset_id"], plan.get("_parameters"))
    except defs.DefinitionUnsupported as error:
        raise ToolError(str(error)) from error
    denied_policy_columns = sorted({item.get("column") for item in mandatory if isinstance(item, dict)}
                                   - set(plan["_policy_columns"]))
    if denied_policy_columns:
        raise ToolError("分析的强制过滤器使用了当前用户无权访问的列，已拒绝直接查询")
    conn = _connect(plan["data_source_arn"])
    dialect = sqlcompile.DIALECTS[conn["engine"]]
    try:
        sql, params, out, limit = sqlcompile.compile_query(
            spec, plan["columns"], plan["source"], dialect, mandatory_filters=mandatory,
            policy_columns=plan["_policy_columns"])
    except sqlcompile.QueryError as error:
        raise ToolError(str(error)) from error
    started = time.time()
    try:
        # The one execution point of generated SQL: compile_query formats in only quoted planned identifiers and fixed
        # allowlisted fragments, and every value stays a bound driver parameter.
        _names, rows = conn["run"](sql, params)  # nosemgrep: python.lang.security.audit.formatted-sql-query.formatted-sql-query
    except Exception:
        _connections.pop(plan["data_source_arn"].rsplit("/", 1)[-1], None)
        raise
    truncated = len(rows) > limit
    rows = [{o["name"]: _plain(v) for o, v in zip(out, row)} for row in rows[:limit]]
    return {"columns": out, "rows": rows, "row_count": len(rows), "truncated": truncated,
            "elapsed_ms": int((time.time() - started) * 1000)}


def query_dataset(args):
    unknown = sorted(str(k) for k in args if k not in QUERY_ARGS)
    if unknown:  # refused, not dropped: the compiler only sees the QuerySpec keys below
        raise ToolError(f"query_dataset 不支持的参数：{', '.join(unknown)[:200]}。只接受 dataset_id、"
                        + "、".join(sorted(sqlcompile.SPEC_KEYS)))
    request_query = {k: args[k] for k in ("dataset_id", *sqlcompile.SPEC_KEYS) if k in args}
    spec = {k: args.get(k) for k in ("metrics", "dimensions", "time", "filters", "order_by", "limit")}
    description, plan = (_dataset(args, request_query) if args.get("_preview_capability") else _dataset(args))
    result = _execute(plan, spec)
    log(event="query", dataset=description["DataSetId"], rows=result["row_count"], ms=result["elapsed_ms"])
    if description.get("ImportMode") == "SPICE":
        result["note"] = "数据直接取自数据源，可能比仪表盘的 SPICE 数据更新"
    return result


def distinct_values(args):
    _description, plan = _dataset(args)
    column = args.get("column")
    filters = [{"column": column, "op": "contains", "value": args["search"]}] if args.get("search") else []
    result = _execute(plan, {"metrics": [{"agg": "count"}], "dimensions": [column], "filters": filters,
                             "order_by": [{"name": "count", "desc": True}], "limit": 50})
    return {"column": column, "values": [r[column] for r in result["rows"]], "truncated": result["truncated"]}


TOOLS = {"describe_dataset": describe_dataset, "query_dataset": query_dataset, "distinct_values": distinct_values}


def handler(event, context):
    event = dict(event or {})
    name = event.pop("__tool", "")
    custom = getattr(getattr(context, "client_context", None), "custom", None) or {}
    if custom.get("bedrockAgentCoreToolName"):
        name = custom["bedrockAgentCoreToolName"].split("___", 1)[-1]
    tool = TOOLS.get(name)
    if tool is None:
        return {"error": f"unknown tool {name!r}"}
    try:
        # QuickSight definitions contain datetimes (e.g. date parameter defaults); Lambda only returns plain JSON.
        return json.loads(json.dumps(tool(event), ensure_ascii=False, default=str))
    except ToolError as error:
        log(event="tool_refused", tool=name, **logging_utils.exception_fields(error))
        return {"error": str(error)}
    except Exception as error:  # noqa: BLE001 - never leak stack traces to the model
        log(event="tool_failed", tool=name, **logging_utils.exception_fields(error))
        return {"error": f"查询失败：{type(error).__name__}"}
