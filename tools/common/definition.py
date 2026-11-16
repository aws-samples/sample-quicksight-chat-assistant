"""Read a QuickSight analysis definition generically: visuals, parameters, controls, parameter-driven filters, and
what a visual plots in terms the data tool understands. Pure functions, no AWS calls."""

import copy
import datetime as dt
import decimal
import re

# ifelse(${pX} = 'label', {column}, ..., default): the usual "pick a metric with a control" calculated field.
SWITCH_BRANCH = re.compile(r"\$\{(\w+)\}\s*=\s*'((?:[^'\\]|\\.)*)'\s*,\s*\{?([A-Za-z_]\w*)\}?")

CHART_KINDS = {"bar": "BarChartVisual", "line": "LineChartVisual"}
KIND_NAMES = {"BarChartVisual": "柱状图", "LineChartVisual": "折线图", "PieChartVisual": "饼图", "TableVisual": "表格",
              "PivotTableVisual": "透视表", "KPIVisual": "KPI", "ComboChartVisual": "组合图", "ScatterPlotVisual": "散点图",
              "CustomContentVisual": "自定义内容", "InsightVisual": "洞察", "HeatMapVisual": "热力图",
              "GaugeChartVisual": "仪表", "FilledMapVisual": "填充地图", "GeospatialMapVisual": "地图",
              "TreeMapVisual": "树状图", "FunnelChartVisual": "漏斗图", "WaterfallVisual": "瀑布图",
              "HistogramVisual": "直方图", "BoxPlotVisual": "箱线图", "SankeyDiagramVisual": "桑基图",
              "WordCloudVisual": "词云", "RadarChartVisual": "雷达图"}
GRAINS = {"YEAR": "year", "QUARTER": "quarter", "MONTH": "month", "WEEK": "week", "DAY": "day", "HOUR": "hour",
          "MINUTE": "minute"}
AGGS = {"SUM": "sum", "AVERAGE": "avg", "MIN": "min", "MAX": "max", "COUNT": "count", "DISTINCT_COUNT": "count_distinct",
        "MEDIAN": None, "STDEV": None, "STDEVP": None, "VAR": None, "VARP": None}
SHARED_CHART_KEYS = ("SortConfiguration", "Legend", "DataLabels", "Tooltip", "VisualPalette", "Interactions")
KEEP_VISUAL_KEYS = ("VisualId", "Title", "Subtitle", "Actions", "ColumnHierarchies", "VisualContentAltText")
ALL_SENTINELS = {"", "all", "[all]", "all values", "select all", "null", "undefined", "全部", "全选", "所有", "全部值"}


def visuals(definition):
    """Yield (sheet, visual, kind, body) for every visual in every sheet."""
    for sheet in definition.get("Sheets", []):
        for visual in sheet.get("Visuals", []):
            kind, body = next(iter(visual.items()))
            yield sheet, visual, kind, body


def text(title):
    fmt = (title or {}).get("FormatText") or {}
    return fmt.get("PlainText") or fmt.get("RichText") or ""


def dataset_ids(definition):
    """Dataset identifier (as used in field wells) -> dataset id."""
    return {d["Identifier"]: d["DataSetArn"].rsplit("/", 1)[-1] for d in definition.get("DataSetIdentifierDeclarations", [])}


COLUMN_REFERENCE = re.compile(r"(?<!\$)\{([^{}]+)\}")  # {column} in a calculated field; ${parameter} is not one
# QuickSight string literals take single or double quotes; an unterminated one runs to the end (read as text).
STRING_LITERAL = re.compile(r"'(?:[^'\\]|\\.?)*(?:'|$)|\"(?:[^\"\\]|\\.?)*(?:\"|$)", re.S)


def expression_columns(expression):
    """Column names referenced by one calculated expression, excluding brace text in string literals."""
    if not isinstance(expression, str):
        return set()
    code = STRING_LITERAL.sub("''", expression)
    names = set(COLUMN_REFERENCE.findall(code)) | {column for _parameter, _label, column in SWITCH_BRANCH.findall(code)}
    return {name.strip() for name in names}


def referenced_columns(definition):
    """{dataset id: set of column names} the analysis uses: every {DataSetIdentifier, ColumnName} object anywhere in
    the definition (field wells, filters, controls, sorts, ...) plus the columns its calculated fields read outside
    string literals (a metric-switch preview queries those). The data tool offers only these columns."""
    ids = dataset_ids(definition)
    out = {}

    def walk(node):
        if isinstance(node, dict):
            identifier, column = node.get("DataSetIdentifier"), node.get("ColumnName")
            if isinstance(identifier, str) and isinstance(column, str) and identifier in ids:
                out.setdefault(ids[identifier], set()).add(column)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
    walk(definition)
    for field in definition.get("CalculatedFields", []):
        if field.get("DataSetIdentifier") in ids:
            out.setdefault(ids[field["DataSetIdentifier"]], set()).update(expression_columns(field.get("Expression")))
    return out


class DefinitionUnsupported(ValueError):
    """The definition contains a policy that direct source queries cannot reproduce exactly."""


def viewer_columns(definition):
    """Dataset id -> columns a viewer can discover or select from visuals and reachable controls.

    Filter-only, sort-only and calculated-field dependency columns are intentionally excluded. They may still be
    used internally to enforce mandatory predicates, but are never offered in a caller QuerySpec.
    """
    ids = dataset_ids(definition)
    out = {}

    def add(column):
        if not isinstance(column, dict):
            return
        identifier, name = column.get("DataSetIdentifier"), column.get("ColumnName")
        if identifier in ids and isinstance(name, str):
            out.setdefault(ids[identifier], set()).add(name)

    def walk(node):
        if isinstance(node, dict):
            add(node.get("Column"))
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    for _sheet, _visual, _kind, body in visuals(definition):
        # Only field wells are viewer-visible query/edit inputs. Walking the whole visual would also admit columns
        # used only by actions or other hidden visual configuration, contradicting this boundary.
        walk((body.get("ChartConfiguration") or {}).get("FieldWells") or {})
    for sheet in definition.get("Sheets", []):
        for control in sheet.get("ParameterControls", []):
            _kind, body = next(iter(control.items()))
            add((body.get("SelectableValues") or {}).get("LinkToDataSetColumn"))
    return out


def cls_columns(dataset, caller_arns, candidates):
    """Filter candidate names through QuickSight column-level permission rules after any shared cache read."""
    candidates = set(candidates)
    restricted, granted = set(), set()
    principals = set(caller_arns)
    for rule in dataset.get("ColumnLevelPermissionRules") or []:
        names = set(rule.get("ColumnNames") or [])
        restricted.update(names)
        if principals & set(rule.get("Principals") or []):
            granted.update(names)
    return candidates - (restricted - granted)


def _policy_value(value):
    return value.isoformat() if hasattr(value, "isoformat") and callable(value.isoformat) else value


def _parameter_specs(definition):
    """Parameter declarations plus the controls a viewer can actually reach."""
    out = {}
    for declaration in definition.get("ParameterDeclarations", []):
        kind, body = next(iter(declaration.items()))
        defaults = body.get("DefaultValues") or {}
        static = defaults.get("StaticValues") or []
        multi = body.get("ParameterValueType") == "MULTI_VALUED"
        default = list(static) if multi and static else (static[0] if static else None)
        out[body["Name"]] = {"type": kind.replace("ParameterDeclaration", "").lower(),
                             "default": default, "multi": multi, "controls": []}
    for sheet in definition.get("Sheets", []):
        for control in sheet.get("ParameterControls", []):
            kind, body = next(iter(control.items()))
            info = out.get(body.get("SourceParameterName"))
            if info is not None:
                info["controls"].append((kind, body))
    return out


def _coerce_parameter_scalar(info, value):
    """Validate one URL-supplied value against its QuickSight declaration and return a bounded SQL operand."""
    kind = info["type"]
    if kind == "string":
        if not isinstance(value, str) or len(value) > 500:
            raise DefinitionUnsupported("分析控件的字符串值格式不正确")
        return value
    if kind == "integer":
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise DefinitionUnsupported("分析控件的整数值格式不正确")
        if isinstance(value, str) and not re.fullmatch(r"[+-]?\d+", value):
            raise DefinitionUnsupported("分析控件的整数值格式不正确")
        return int(value)
    if kind == "decimal":
        if isinstance(value, bool) or not isinstance(value, (int, float, decimal.Decimal, str)):
            raise DefinitionUnsupported("分析控件的数值格式不正确")
        try:
            parsed = decimal.Decimal(str(value))
        except decimal.InvalidOperation as error:
            raise DefinitionUnsupported("分析控件的数值格式不正确") from error
        if not parsed.is_finite():
            raise DefinitionUnsupported("分析控件的数值格式不正确")
        return format(parsed, "f")
    if kind == "datetime":
        value = _policy_value(value)
        if not isinstance(value, str) or len(value) > 500:
            raise DefinitionUnsupported("分析控件的日期时间值格式不正确")
        try:
            dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise DefinitionUnsupported("分析控件的日期时间值格式不正确") from error
        return value
    raise DefinitionUnsupported(f"分析参数类型 {kind} 无法精确复现")


def _validated_parameter_value(info, value, check_choices):
    if info["multi"]:
        if not isinstance(value, list) or not 1 <= len(value) <= 200:
            raise DefinitionUnsupported("分析控件的多选值格式不正确")
        parsed = [_coerce_parameter_scalar(info, item) for item in value]
    else:
        if isinstance(value, list):
            raise DefinitionUnsupported("分析控件的单选值格式不正确")
        parsed = _coerce_parameter_scalar(info, value)
    choices = []
    if check_choices:
        for _kind, control in info["controls"]:
            listed = (control.get("SelectableValues") or {}).get("Values")
            if listed:
                choices.extend(_coerce_parameter_scalar(info, item) for item in listed)
    selected = parsed if isinstance(parsed, list) else [parsed]
    if choices and any(item not in choices for item in selected):
        raise DefinitionUnsupported("分析控件的值不在已声明的静态选项中")
    return parsed


def _parameter_values(definition, supplied):
    """Resolve fixed-filter parameters from complete declarations and validated viewer controls only."""
    if supplied is not None and not isinstance(supplied, dict):
        raise DefinitionUnsupported("分析控件参数格式不正确")
    specs = _parameter_specs(definition)
    values = {}
    for name, info in specs.items():
        if info["default"] is not None:
            try:
                values[name] = _validated_parameter_value(info, info["default"], False)
            except DefinitionUnsupported:
                pass  # a mandatory filter that needs this declaration will fail closed as missing below
    for name, value in (supplied or {}).items():
        if value in (None, ""):
            continue
        info = specs.get(name)
        if info is None or not info["controls"]:
            continue  # URL values cannot override hidden or undeclared parameters
        select_all_visible = any(
            (((control.get("DisplayOptions") or {}).get("SelectAllOptions") or {}).get("Visibility") == "VISIBLE")
            for _kind, control in info["controls"])
        supplied_all = is_all(value)
        parsed = _validated_parameter_value(info, value, not supplied_all)
        if supplied_all and not select_all_visible:
            continue  # a crafted Select All value cannot replace the trusted declaration default
        values[name] = parsed
    return values


def _static_or_parameter(value, parameter_values):
    if not isinstance(value, dict):
        return None, False
    if "StaticValue" in value:
        return _policy_value(value["StaticValue"]), True
    parameter = value.get("Parameter")
    if parameter and parameter in parameter_values:
        return _policy_value(parameter_values[parameter]), True
    return None, False


def mandatory_filters(definition, dataset_id, supplied_parameters=None):
    """Return enabled whole-analysis predicates for one dataset, or fail when exact reproduction is impossible."""
    identifiers = dataset_ids(definition)
    values = _parameter_values(definition, supplied_parameters)
    out = []
    for group in definition.get("FilterGroups", []):
        status = group.get("Status", "ENABLED")
        if status == "DISABLED":
            continue
        if status != "ENABLED":
            raise DefinitionUnsupported("分析过滤器状态无法确认，直接查询已拒绝")
        scope = group.get("ScopeConfiguration") or {}
        if "AllSheets" not in scope:
            raise DefinitionUnsupported("分析有只作用于部分工作表或图表的过滤器，直接查询无法确定同一作用域")
        if group.get("CrossDataset", "SINGLE_DATASET") != "SINGLE_DATASET":
            raise DefinitionUnsupported("分析有跨数据集过滤器，直接查询无法精确复现")
        if group.get("Operator", "AND") != "AND":
            raise DefinitionUnsupported("分析过滤器使用了 OR 组合，直接查询无法精确复现")
        for wrapped in group.get("Filters") or []:
            if not isinstance(wrapped, dict) or len(wrapped) != 1:
                raise DefinitionUnsupported("分析包含无法识别的过滤器")
            kind, body = next(iter(wrapped.items()))
            column = body.get("Column") or {}
            identifier, name = column.get("DataSetIdentifier"), column.get("ColumnName")
            target = identifiers.get(identifier)
            if target != dataset_id:
                continue
            if not isinstance(name, str):
                raise DefinitionUnsupported("分析过滤器缺少数据列")
            filters = []
            null_option = body.get("NullOption")
            if kind == "CategoryFilter":
                configuration = body.get("Configuration") or {}
                if "CustomFilterConfiguration" in configuration:
                    item = configuration["CustomFilterConfiguration"] or {}
                    null_option = item.get("NullOption")
                    if item.get("ParameterName"):
                        value, present = values.get(item["ParameterName"]), item["ParameterName"] in values
                    else:
                        value, present = item.get("CategoryValue"), "CategoryValue" in item
                    if not present:
                        raise DefinitionUnsupported("分析分类过滤器的参数没有可用值")
                    if not is_all(value):
                        operator = item.get("MatchOperator", "EQUALS")
                        if operator not in ("EQUALS", "DOES_NOT_EQUAL"):
                            raise DefinitionUnsupported("分析包含不支持的分类过滤运算")
                        filters.append({"column": name, "op": "eq" if operator == "EQUALS" else "ne", "value": value})
                elif "CustomFilterListConfiguration" in configuration or "FilterListConfiguration" in configuration:
                    item = configuration.get("CustomFilterListConfiguration") or configuration.get("FilterListConfiguration") or {}
                    null_option = item.get("NullOption")
                    if item.get("ParameterName"):
                        selected, present = values.get(item["ParameterName"]), item["ParameterName"] in values
                    else:
                        selected, present = item.get("CategoryValues"), "CategoryValues" in item
                    if not present:
                        raise DefinitionUnsupported("分析分类列表过滤器的参数没有可用值")
                    if not is_all(selected):
                        selected = selected if isinstance(selected, list) else [selected]
                        if not 1 <= len(selected) <= 200:
                            raise DefinitionUnsupported("分析分类列表过滤器超过 200 个值，直接查询不受支持")
                        operator = item.get("MatchOperator", "CONTAINS")
                        if operator not in ("EQUALS", "DOES_NOT_EQUAL", "CONTAINS", "DOES_NOT_CONTAIN"):
                            raise DefinitionUnsupported("分析包含不支持的分类列表过滤运算")
                        positive = operator in ("EQUALS", "CONTAINS")
                        filters.append({"column": name, "op": "in" if positive else "not_in", "values": selected})
                else:
                    raise DefinitionUnsupported("分析包含无法复现的分类过滤器")
            elif kind in ("TimeRangeFilter", "NumericRangeFilter"):
                if kind == "TimeRangeFilter":
                    if body.get("ExcludePeriodConfiguration"):
                        raise DefinitionUnsupported("分析时间范围过滤器包含排除时段，直接查询无法精确复现")
                    granularity = body.get("TimeGranularity")
                    if granularity not in (None, "DAY", "SECOND", "MILLISECOND"):
                        raise DefinitionUnsupported("分析时间范围过滤器的粒度无法精确复现")
                elif body.get("AggregationFunction"):
                    raise DefinitionUnsupported("分析数值范围过滤器使用聚合值，直接查询无法精确复现")
                for key, inclusive, lower in (("RangeMinimumValue", body.get("IncludeMinimum", True), True),
                                               ("RangeMaximumValue", body.get("IncludeMaximum", True), False)):
                    if key not in body:
                        continue
                    value, present = _static_or_parameter(body.get(key), values)
                    if not present:
                        raise DefinitionUnsupported("分析范围过滤器的参数没有可用值")
                    if kind == "TimeRangeFilter" and body.get("TimeGranularity") == "DAY":
                        if not inclusive:
                            raise DefinitionUnsupported("按天时间范围的排除端点无法精确复现")
                        if isinstance(value, str):
                            value = value[:10]
                    op = ("gte" if inclusive else "gt") if lower else ("lte" if inclusive else "lt")
                    filters.append({"column": name, "op": op, "value": value})
            elif kind == "NumericEqualityFilter":
                if body.get("AggregationFunction"):
                    raise DefinitionUnsupported("分析数值等值过滤器使用聚合值，直接查询无法精确复现")
                if body.get("ParameterName"):
                    value, present = values.get(body["ParameterName"]), body["ParameterName"] in values
                else:
                    value, present = body.get("Value"), "Value" in body
                if not present:
                    raise DefinitionUnsupported("分析等值过滤器的参数没有可用值")
                operator = body.get("MatchOperator", "EQUALS")
                if operator not in ("EQUALS", "DOES_NOT_EQUAL"):
                    raise DefinitionUnsupported("分析包含不支持的等值过滤运算")
                filters.append({"column": name, "op": "eq" if operator == "EQUALS" else "ne", "value": value})
            elif kind == "TimeEqualityFilter":
                raise DefinitionUnsupported("分析包含带时间粒度的等值过滤器，直接查询无法精确复现")
            else:
                raise DefinitionUnsupported(f"分析包含无法复现的过滤器 {kind}")
            if null_option == "NULLS_ONLY":
                filters = [{"column": name, "op": "is_null"}]
            elif null_option == "NON_NULLS_ONLY" and not filters:
                filters = [{"column": name, "op": "not_null"}]
            elif null_option == "ALL_VALUES" and filters:
                raise DefinitionUnsupported("包含空值的过滤器需要 OR 语义，直接查询无法精确复现")
            elif null_option is None:
                raise DefinitionUnsupported("分析过滤器没有明确空值策略，直接查询无法精确复现")
            elif null_option not in ("ALL_VALUES", "NON_NULLS_ONLY"):
                raise DefinitionUnsupported("分析过滤器的空值策略无法复现")
            out.extend(filters)
    return out


def calculated_fields(definition):
    return {(c.get("DataSetIdentifier"), c["Name"]): c.get("Expression", "") for c in definition.get("CalculatedFields", [])}


def parameters(definition):
    """Parameter name -> {type, complete static default, control title, linked dataset column}."""
    out = {}
    for name, spec in _parameter_specs(definition).items():
        info = {"type": spec["type"], "default": spec["default"], "multi": spec["multi"]}
        for kind, body in spec["controls"]:
            info["control"] = text({"FormatText": {"PlainText": body.get("Title", "")}}) or body.get("Title")
            info["control_type"] = kind
            link = (body.get("SelectableValues") or {}).get("LinkToDataSetColumn")
            if link:
                info["values_from"] = {"dataset": link["DataSetIdentifier"], "column": link["ColumnName"]}
            listed = (body.get("SelectableValues") or {}).get("Values")
            if listed:
                info["choices"] = listed[:50]
        out[name] = info
    return out


def _filter_bindings(flt):
    """(column, [(role, parameter)]) for one filter, or None when no parameter drives it."""
    kind, body = next(iter(flt.items()))
    column = body.get("Column") or {}
    roles = []
    if kind == "CategoryFilter":
        configuration = body.get("Configuration") or {}
        custom = configuration.get("CustomFilterConfiguration") or {}
        if custom.get("ParameterName"):
            roles.append(("eq" if custom.get("MatchOperator", "EQUALS") == "EQUALS" else "ne", custom["ParameterName"]))
        listed = configuration.get("FilterListConfiguration") or {}
        if listed.get("ParameterName"):
            roles.append(("in", listed["ParameterName"]))
    elif kind in ("TimeRangeFilter", "NumericRangeFilter"):
        for key, role in (("RangeMinimumValue", "gte"), ("RangeMaximumValue", "lte")):
            if (body.get(key) or {}).get("Parameter"):
                roles.append((role, body[key]["Parameter"]))
    elif kind in ("NumericEqualityFilter", "TimeEqualityFilter"):
        if body.get("ParameterName"):
            roles.append(("eq", body["ParameterName"]))
    if not roles or not column.get("ColumnName"):
        return None
    return {"dataset": column.get("DataSetIdentifier"), "column": column["ColumnName"],
            "roles": [{"op": op, "parameter": p} for op, p in roles],
            "inclusive": {"min": body.get("IncludeMinimum", True), "max": body.get("IncludeMaximum", True)}}


def parameter_filters(definition):
    """Filters whose values come from parameters (what a control changes), with the visuals they apply to."""
    out = []
    for group in definition.get("FilterGroups", []):
        if group.get("Status", "ENABLED") != "ENABLED":
            continue
        scope = group.get("ScopeConfiguration", {})
        visual_ids = None  # None = all visuals
        selected = scope.get("SelectedSheets", {}).get("SheetVisualScopingConfigurations", [])
        if selected:
            visual_ids = set()
            for item in selected:
                if item.get("Scope") == "SELECTED_VISUALS":
                    visual_ids.update(item.get("VisualIds", []))
                else:
                    visual_ids = None
                    break
        for flt in group.get("Filters", []):
            binding = _filter_bindings(flt)
            if binding:
                binding["visuals"] = sorted(visual_ids) if visual_ids is not None else "all"
                binding["_mandatory"] = "AllSheets" in scope
                out.append(binding)
    return out


def _field(field):
    """One field-well entry -> {"column", "dataset", "kind", ...} in data-tool terms."""
    kind, body = next(iter(field.items()))
    column = body.get("Column") or {}
    out = {"column": column.get("ColumnName"), "dataset": column.get("DataSetIdentifier"), "field": kind}
    if kind == "DateDimensionField":
        out["grain"] = GRAINS.get(body.get("DateGranularity", "DAY"), "day")
    if kind == "NumericalMeasureField":
        name = (body.get("AggregationFunction") or {}).get("SimpleNumericalAggregation", "SUM")
        out["agg"] = AGGS.get(name)
    elif kind in ("CategoricalMeasureField", "DateMeasureField"):
        out["agg"] = "count_distinct" if body.get("AggregationFunction") == "DISTINCT_COUNT" else "count"
    return out


def _well_entries(body):
    wells = next(iter(((body.get("ChartConfiguration") or {}).get("FieldWells") or {}).values()), {}) or {}
    return [e for entries in wells.values() if isinstance(entries, list) for e in entries if isinstance(e, dict) and e]


def visual_summary(kind, body, definition, full=False):
    """What a visual shows: title, dimensions, measures. Used by describe_analysis (expressions shortened for the
    model) and the preview (full=True: metric-switch fields need every branch)."""
    configuration = body.get("ChartConfiguration") or {}
    wells = next(iter((configuration.get("FieldWells") or {}).values()), {}) or {}
    dims, measures, colors = [], [], []
    for key, entries in wells.items():
        if not isinstance(entries, list):
            continue
        parsed = [_field(e) for e in entries if isinstance(e, dict) and e]
        if key in ("Values", "Measures", "Value", "TargetValues", "Size", "Weight"):
            measures += parsed
        elif key in ("Colors", "Color", "SmallMultiples"):
            colors += parsed
        else:
            dims += parsed
    calculated = calculated_fields(definition)
    for field in dims + measures + colors:
        expression = calculated.get((field["dataset"], field["column"]))
        if expression is not None:
            field["calculated"] = expression if full else expression[:300]
    return {"visual_id": body.get("VisualId"), "type": kind, "type_name": KIND_NAMES.get(kind, kind),
            "title": text(body.get("Title")), "dimensions": dims, "measures": measures, "colors": colors,
            "can_switch_type": kind in CHART_KINDS.values(),
            "editable": kind in ("LineChartVisual", "BarChartVisual", "TableVisual")}


def convert(body, to_kind):
    """Rebuild a line or bar chart visual as the other type, keeping id, title, actions and field wells."""
    old = body.get("ChartConfiguration", {})
    wells = next(iter(old.get("FieldWells", {}).values()), {})
    picked = {k: wells[k] for k in ("Category", "Values", "Colors") if k in wells}
    common = {k: v for k, v in old.items() if k in SHARED_CHART_KEYS}
    keep = {k: body[k] for k in KEEP_VISUAL_KEYS if k in body}
    if to_kind == "BarChartVisual":
        config = {"FieldWells": {"BarChartAggregatedFieldWells": picked}, "Orientation": "VERTICAL",
                  "BarsArrangement": "CLUSTERED", **common}
    elif to_kind == "LineChartVisual":
        config = {"FieldWells": {"LineChartAggregatedFieldWells": picked}, "Type": "LINE", **common}
    else:
        raise ValueError(f"unsupported chart kind {to_kind}")
    return {to_kind: {**keep, "ChartConfiguration": config}}


def replace_chart_type(definition, visual_id, to_kind):
    """Change one visual in place; returns the old kind. Raises ValueError when not possible."""
    for sheet, visual, kind, body in visuals(definition):
        if body["VisualId"] != visual_id:
            continue
        if kind == to_kind:
            raise ValueError(f"{visual_id} 已经是{KIND_NAMES[to_kind]}")
        if kind not in CHART_KINDS.values():
            raise ValueError(f"{visual_id} 是{KIND_NAMES.get(kind, kind)}，目前只支持折线图和柱状图互换")
        sheet["Visuals"][sheet["Visuals"].index(visual)] = convert(body, to_kind)
        return kind
    raise ValueError(f"分析里没有图表 {visual_id}；先调用 describe_analysis 查看可用的 visual_id")


def is_all(value):
    return value is None or (isinstance(value, str) and value.strip().lower() in ALL_SENTINELS) or \
        (isinstance(value, str) and value.startswith("<<")) or \
        (isinstance(value, list) and len(value) == 1 and is_all(value[0]))


def resolve_switch(expression, parameter_values):
    """Column chosen by a parameter-switch calculated field for the current values, or None if it is not one."""
    body = expression.strip()
    if not body.lower().startswith("ifelse("):
        return None
    branches = SWITCH_BRANCH.findall(body)
    if not branches or len({p for p, _l, _c in branches}) != 1:
        return None
    parameter = branches[0][0]
    value = (parameter_values or {}).get(parameter)
    for _p, label, column in branches:
        if value == label:
            return column
    return None


def preview_query(definition, visual_id, parameter_values):
    """Turn a visual plus the current control values into a data-tool query, or explain why not.

    Returns {"query": {...}, "notes": [...]} or {"unsupported": reason}.
    """
    found = next(((kind, body) for _s, _v, kind, body in visuals(definition) if body["VisualId"] == visual_id), None)
    if not found:
        return {"unsupported": f"没有图表 {visual_id}"}
    # A parameter without a value from the embed URL uses its declared default, as QuickSight does.
    declared = parameters(definition)
    parameter_values = {**{n: str(i["default"])[:10] if i["type"] == "datetime" and i["default"] is not None else i["default"]
                           for n, i in declared.items() if i.get("default") is not None},
                        **{n: v for n, v in (parameter_values or {}).items() if v not in (None, "")}}
    summary = visual_summary(*found, definition, full=True)
    fields = summary["dimensions"] + summary["measures"] + summary["colors"]
    notes = []
    for f in fields:  # a metric-switch field reads one real column for the current control value
        if "calculated" in f:
            column = resolve_switch(f["calculated"], parameter_values)
            if column:
                notes.append(f"{f['column']} 按当前控件取 {column}")
                f["column"] = column
                del f["calculated"]
    calculated = [f["column"] for f in fields if "calculated" in f]
    if calculated:
        return {"unsupported": f"图表用了计算字段 {', '.join(calculated)}，聊天里无法按同样口径取数"}
    datasets = {f["dataset"] for f in fields}
    if len(datasets) != 1:
        return {"unsupported": "图表的字段来自多个数据集"}
    dataset = datasets.pop()
    is_table = found[0] == "TableVisual"
    if not summary["dimensions"] or not summary["measures"] or (len(summary["dimensions"]) > (3 if is_table else 1)):
        return {"unsupported": "只支持分类字段加若干数值字段的折线图、柱状图和表格"}
    if any(m.get("agg") is None for m in summary["measures"]):
        return {"unsupported": "图表用了聊天里不支持的聚合方式（如中位数、标准差）"}
    query = {"dataset": dataset, "metrics": [{"column": m["column"], "agg": m["agg"]} for m in summary["measures"]],
             "dimensions": [], "filters": [], "limit": 500}
    for dim in summary["dimensions"] + summary["colors"][:1]:
        if dim["field"] == "DateDimensionField" and "time" not in query:
            query["time"] = {"column": dim["column"], "grain": dim.get("grain", "day")}
        else:
            query["dimensions"].append(dim["column"])
    sort = (found[1].get("ChartConfiguration") or {}).get("SortConfiguration") or {}
    field_sort = next((s["FieldSort"] for s in (sort.get("CategorySort") or sort.get("RowSort") or []) if "FieldSort" in s), None)
    if field_sort:
        names = {next(iter(e.values()))["FieldId"]: next(iter(e.values()))["Column"]["ColumnName"]
                 for e in _well_entries(found[1])}
        target = names.get(field_sort["FieldId"])
        if target:  # output columns are named after their dataset column (see sqlcompile)
            query["order_by"] = [{"name": target, "desc": field_sort.get("Direction") == "DESC"}]
    for binding in parameter_filters(definition):
        if binding["_mandatory"] or binding["dataset"] != dataset or \
                (binding["visuals"] != "all" and visual_id not in binding["visuals"]):
            continue
        for role in binding["roles"]:
            value = (parameter_values or {}).get(role["parameter"])
            if is_all(value):
                continue
            op = role["op"]
            if op == "in" and not isinstance(value, list):
                value = [value]
            elif op != "in" and isinstance(value, list) and len(value) == 1:
                value = value[0]  # a single-valued control; the data tool takes lists only for in / not_in / between
            query["filters"].append({"column": binding["column"], "op": op, "value": value})
    if any(f["dataset"] != dataset for f in fields):
        notes.append("部分字段口径无法确认")
    return {"query": query, "notes": notes, "summary": summary}


def strip_for_model(definition, visible=None):
    """A compact view of the analysis containing only the caller's post-CLS columns and related metadata."""
    filters = parameter_filters(definition)
    scoped = copy.deepcopy(definition)
    if visible is not None:
        allowed = lambda identifier, column: column in visible.get(identifier, set())
        filters = [item for item in filters if allowed(item.get("dataset"), item.get("column"))]
        allowed_parameters = {role["parameter"] for item in filters for role in item["roles"]}
        for sheet in scoped.get("Sheets", []):
            controls = []
            for control in sheet.get("ParameterControls", []):
                _kind, body = next(iter(control.items()))
                link = (body.get("SelectableValues") or {}).get("LinkToDataSetColumn")
                if link and not allowed(link.get("DataSetIdentifier"), link.get("ColumnName")):
                    continue
                controls.append(control)
                if body.get("SourceParameterName"):
                    allowed_parameters.add(body["SourceParameterName"])
            sheet["ParameterControls"] = controls
        model_parameters = {name: info for name, info in parameters(scoped).items() if name in allowed_parameters}
    else:
        model_parameters = parameters(scoped)
    model_filters = [{key: value for key, value in item.items() if key != "_mandatory"} for item in filters]
    out = {"sheets": [], "parameters": model_parameters, "filters": copy.deepcopy(model_filters),
           "datasets": dataset_ids(definition)}
    for sheet in scoped.get("Sheets", []):
        summaries = [visual_summary(kind, body, scoped) for _sheet, _visual, kind, body
                     in visuals({"Sheets": [sheet]})]
        for summary in summaries:
            if visible is not None:
                for key in ("dimensions", "measures", "colors"):
                    summary[key] = [field for field in summary[key]
                                    if allowed(field.get("dataset"), field.get("column"))]
            for field in summary["dimensions"] + summary["measures"] + summary["colors"]:
                if "calculated" in field:
                    field.pop("calculated")
                    field["is_calculated"] = True
        out["sheets"].append({"name": sheet.get("Name"), "sheet_id": sheet.get("SheetId"), "visuals": summaries})
    return out
