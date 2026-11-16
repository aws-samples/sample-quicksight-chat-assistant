"""Work out, from QuickSight metadata only, how to query a dataset directly at its source, or why that is unsafe.

Supported in this version: a dataset with exactly one physical table, a relational table (RelationalTable), on a
PostgreSQL / Aurora PostgreSQL / MySQL / Aurora MySQL / MariaDB / RDS (PostgreSQL or MySQL) data source, whose logical
table only projects, renames, casts or tags columns. Custom SQL datasets are refused (their SQL would have to be
embedded in the query). Anything that would change which rows a user sees in QuickSight - joins, dataset filters,
row-level security, column-level security the caller is not granted - is refused, because querying the source
directly would bypass it. Calculated columns are hidden (QuickSight expressions are not SQL), and caller-visible
columns come only from visual field wells and reachable controls in the authorized definition.
"""

import definition as defs

ENGINES = {"POSTGRESQL": "postgresql", "AURORA_POSTGRESQL": "postgresql", "MYSQL": "mysql", "AURORA": "mysql",
           "MARIADB": "mysql"}
PARAM_KEYS = {"PostgreSqlParameters": "postgresql", "AuroraPostgreSqlParameters": "postgresql",
              "MySqlParameters": "mysql", "AuroraParameters": "mysql", "MariaDbParameters": "mysql",
              "RdsParameters": None}
IGNORED_TRANSFORMS = ("CastColumnTypeOperation", "TagColumnOperation", "UntagColumnOperation",
                      "OverrideDatasetParameterOperation")


class Unsupported(Exception):
    """The dataset cannot be queried safely by the built-in tool; the message says why."""


def plan(dataset, caller_arns, referenced=None):
    """Build a direct-query plan after RLS, transform, CLS and caller-visible column checks.

    `referenced` is the viewer-queryable set from the authorized definition. The returned public `columns` map is
    limited to it; `_policy_columns` contains additional CLS-permitted columns only for mandatory filter compilation.
    """
    for key in ("RowLevelPermissionDataSet", "RowLevelPermissionTagConfiguration"):
        if key in dataset:
            policy = dataset.get(key)
            if not isinstance(policy, dict) or policy.get("Status") != "DISABLED":
                raise Unsupported("数据集的行级权限状态不是明确的 DISABLED，直接查询数据源会绕过它")
    physical = dataset.get("PhysicalTableMap") or {}
    if len(physical) != 1:
        raise Unsupported(f"数据集有 {len(physical)} 个物理表（含联接），暂不支持直接查询")
    physical_id, table = next(iter(physical.items()))
    kind, body = next(iter(table.items()))
    if kind == "RelationalTable":
        source = {"table": (body.get("Schema"), body["Name"])}
        input_columns = {c["Name"]: c["Type"] for c in body.get("InputColumns", [])}
    elif kind == "CustomSql":
        raise Unsupported("自定义 SQL（Custom SQL）数据集不受支持，请改用基于表（RelationalTable）的数据集")
    else:
        raise Unsupported(f"物理表类型 {kind} 暂不支持（如 S3 文件）")

    logical = dataset.get("LogicalTableMap") or {}
    if len(logical) > 1:
        raise Unsupported("数据集有多个逻辑表（含联接），暂不支持直接查询")
    names = {name: name for name in input_columns}  # current name -> physical column
    types = dict(input_columns)
    hidden, notes = [], []
    for table_body in logical.values():
        if table_body.get("Source", {}).get("PhysicalTableId") != physical_id:
            raise Unsupported("逻辑表不是直接来自物理表（含联接），暂不支持直接查询")
        for transform in table_body.get("DataTransforms", []):
            op, args = next(iter(transform.items()))
            if op == "RenameColumnOperation":
                old, new = args["ColumnName"], args["NewColumnName"]
                if old in names:
                    names[new] = names.pop(old)
                    types[new] = types.pop(old)
            elif op == "ProjectOperation":
                keep = set(args.get("ProjectedColumns", []))
                hidden += [n for n in names if n not in keep]
                names = {n: p for n, p in names.items() if n in keep}
            elif op == "CreateColumnsOperation":
                hidden += [c["ColumnName"] for c in args.get("Columns", [])]
            elif op == "FilterOperation":
                raise Unsupported("数据集定义了过滤条件，直接查询数据源会绕过它")
            elif op not in IGNORED_TRANSFORMS:
                raise Unsupported(f"数据集里有暂不支持的转换 {op}")
    output_types = {c["Name"]: c["Type"] for c in dataset.get("OutputColumns", [])}
    allowed = defs.cls_columns(dataset, caller_arns, names)
    for name in set(names) - allowed:
        names.pop(name)
        hidden.append(name)
        notes.append(f"列 {name} 受列级权限限制，已隐藏")
    # Mandatory predicates may use non-visible columns, but never a column CLS denies to this caller.
    policy_columns = {name: {"expr": physical_name, "type": output_types.get(name, _qs_type(types.get(name)))}
                      for name, physical_name in names.items()}
    columns = dict(policy_columns)
    if referenced is not None:
        if any(name not in referenced for name in columns):
            notes.append("只列出当前查看资源的图表或可用控件列")
        columns = {name: info for name, info in columns.items() if name in referenced}
        hidden = [name for name in hidden if name in referenced]
    return {"data_source_arn": body["DataSourceArn"], "source": source, "columns": columns,
            "_policy_columns": policy_columns, "hidden": sorted(set(hidden)), "notes": notes}


def _qs_type(input_type):
    return {"STRING": "STRING", "INTEGER": "INTEGER", "DECIMAL": "DECIMAL", "DATETIME": "DATETIME",
            "BIT": "INTEGER", "BOOLEAN": "INTEGER", "JSON": "STRING"}.get(input_type or "", "STRING")


def connection(data_source):
    """data_source: DescribeDataSource()["DataSource"]. Returns {"engine", "host"|"rds_instance", "port", "database", "ssl"}."""
    parameters = data_source.get("DataSourceParameters") or {}
    if not parameters:
        raise Unsupported(f"数据源类型 {data_source.get('Type')} 暂不支持")
    key, values = next(iter(parameters.items()))
    if key not in PARAM_KEYS:
        raise Unsupported(f"数据源类型 {data_source.get('Type')} 暂不支持（第一版支持 PostgreSQL 和 MySQL 系）")
    engine = PARAM_KEYS[key] or ENGINES.get(data_source.get("Type", ""))
    out = {"engine": engine, "database": values.get("Database"), "ssl": True}
    if (data_source.get("SslProperties") or {}).get("DisableSsl") is True:
        raise Unsupported("数据源明确禁用了 TLS；内置查询只允许经过证书验证的 TLS")
    if key == "RdsParameters":
        out["rds_instance"] = values["InstanceId"]
    else:
        out["host"], out["port"] = values["Host"], int(values.get("Port") or (5432 if engine == "postgresql" else 3306))
    return out
