"""Unit tests for the pure modules (no AWS). Run: python3 -m unittest discover -s tests/unit"""

import importlib.util
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for sub in ("tools/data", "tools/common", "agent"):
    sys.path.insert(0, os.path.join(ROOT, sub))

import charts  # noqa: E402
import dataset as ds  # noqa: E402
import definition as defs  # noqa: E402
import sqlcompile as sc  # noqa: E402

COLUMNS = {"station": {"expr": "station_code", "type": "STRING"}, "price": {"expr": "month_price", "type": "DECIMAL"},
           "t": {"expr": "data_time", "type": "DATETIME"}, "note": {"expr": "note", "type": "STRING"}}
TABLE = {"table": ("public", "trade")}


class SqlCompileTest(unittest.TestCase):
    def test_postgres_time_bucket_filters_and_params(self):
        sql, params, out, limit = sc.compile_query(
            {"metrics": [{"column": "price", "agg": "avg"}], "time": {"column": "t", "grain": "month"},
             "dimensions": ["station"],
             "filters": [{"column": "station", "op": "in", "values": ["A", "B"]},
                         {"column": "t", "op": "between", "value": ["2026-01-01", "2026-03-31"]}]},
            COLUMNS, TABLE, sc.DIALECTS["postgresql"])
        self.assertIn("date_trunc('month', \"data_time\")", sql)
        self.assertIn('FROM "public"."trade"', sql)
        self.assertIn('"station_code" IN (:p0, :p1)', sql)
        self.assertIn('"data_time" >= :p2 AND "data_time" < (CAST(:p3 AS DATE) + 1)', sql)  # inclusive end day
        self.assertEqual(params, {"p0": "A", "p1": "B", "p2": "2026-01-01", "p3": "2026-03-31"})
        self.assertEqual([o["name"] for o in out], ["t", "station", "price"])
        self.assertTrue(sql.endswith("LIMIT 201"))
        self.assertEqual(limit, 200)

    def test_tolerates_garbled_list_keys(self):
        # Key names actually sent by Kimi K3 for between; each used to cost a failed call and a model round trip.
        for flt in ({"values[]": ["2026-01-01", "2026-03-31"]}, {"values 范围内": ["2026-01-01", "2026-03-31"]},
                    {"values[1]": "2026-03-31", "values[0]": "2026-01-01"}):
            _sql, params, _out, _limit = sc.compile_query(
                {"metrics": [{"column": "price", "agg": "avg"}], "filters": [{"column": "t", "op": "between", **flt}]},
                COLUMNS, TABLE, sc.DIALECTS["postgresql"])
            self.assertEqual(params, {"p0": "2026-01-01", "p1": "2026-03-31"}, flt)
        with self.assertRaisesRegex(sc.QueryError, '"values"'):
            sc.compile_query({"metrics": [{"column": "price", "agg": "avg"}],
                              "filters": [{"column": "t", "op": "between", "values ": "2026-01-01"}]},
                             COLUMNS, TABLE, sc.DIALECTS["postgresql"])

    def test_mysql_quoting_and_percent_escaping(self):
        sql, params, _out, _limit = sc.compile_query(
            {"metrics": [{"agg": "count"}], "time": {"column": "t", "grain": "month"},
             "filters": [{"column": "note", "op": "contains", "value": "50%_off"}]},
            COLUMNS, TABLE, sc.DIALECTS["mysql"])
        self.assertIn("DATE_FORMAT(`data_time`, '%%Y-%%m-01')", sql)
        self.assertIn("FROM `public`.`trade`", sql)
        self.assertIn("LIKE %(p0)s", sql)
        self.assertEqual(params["p0"], "%50\\%\\_off%")

    def test_rejects_unknown_columns_aggregates_and_injection(self):
        dialect = sc.DIALECTS["postgresql"]
        bad = [
            {"metrics": [{"column": "price; DROP TABLE x", "agg": "sum"}]},
            {"metrics": [{"column": "price", "agg": "sum(price)); --"}]},
            {"metrics": [{"column": "station", "agg": "sum"}]},  # sum of a string column
            {"metrics": [{"column": "price", "agg": "sum"}], "filters": [{"column": "price", "op": "or 1=1", "value": 1}]},
            {"metrics": [{"column": "price", "agg": "sum"}], "time": {"column": "station", "grain": "day"}},
            {"metrics": []},
        ]
        for spec in bad:
            with self.assertRaises(sc.QueryError, msg=spec):
                sc.compile_query(spec, COLUMNS, TABLE, dialect)

    def test_rejects_unknown_keys_bad_values_and_custom_sql(self):
        dialect = sc.DIALECTS["postgresql"]
        metric = {"column": "price", "agg": "sum"}
        bad = [
            {"metrics": [metric], "raw_sql": "1"},
            {"metrics": [{**metric, "expr": "price*2"}]},
            {"metrics": [metric], "time": {"column": "t", "grain": "day", "tz": "x"}},
            {"metrics": [metric], "filters": [{"column": "station", "op": "eq", "value": "A", "or": "1=1"}]},
            {"metrics": [metric], "order_by": [{"name": "price", "desc": True, "nulls": "first"}]},
            {"metrics": [{"column": "price", "agg": ["sum"]}]},
        ]
        bad += [{"metrics": [metric], "filters": [{"column": "price", "op": "eq", "value": v}]}
                for v in (True, float("nan"), float("inf"), {"a": 1}, "x" * (sc.MAX_VALUE_LENGTH + 1), ["A", "B"])]
        bad += [{"metrics": [metric], "filters": [{"column": "station", "op": "in", "values": ["A", False]}]},
                {"metrics": [metric], "filters": [{"column": "price", "op": "between", "values": [float("nan"), 1]}]},
                {"metrics": [metric], "filters": [{"column": "price", "op": "between", "values": [[1], 2]}]},
                {"metrics": [metric], "limit": float("inf")}]
        for spec in bad:
            with self.assertRaises(sc.QueryError, msg=spec):
                sc.compile_query(spec, COLUMNS, TABLE, dialect)
        with self.assertRaises(sc.QueryError):
            sc.compile_query({"metrics": [metric]}, COLUMNS, {"sql": "SELECT * FROM x"}, dialect)
        _sql, params, _o, _l = sc.compile_query(  # numbers and a one-element list are still fine
            {"metrics": [metric], "filters": [{"column": "price", "op": "gt", "value": [1.5]},
                                              {"column": "station", "op": "eq", "value": "x" * sc.MAX_VALUE_LENGTH}]},
            COLUMNS, TABLE, dialect)
        self.assertEqual(params["p0"], 1.5)

    def test_values_are_never_inlined(self):
        sql, params, _o, _l = sc.compile_query(
            {"metrics": [{"column": "price", "agg": "sum"}], "filters": [{"column": "station", "op": "eq", "value": "x' OR '1'='1"}]},
            COLUMNS, TABLE, sc.DIALECTS["postgresql"])
        self.assertNotIn("OR '1'='1", sql)
        self.assertEqual(list(params.values()), ["x' OR '1'='1"])


def dataset_body(**extra):
    body = {"DataSetId": "d1", "ImportMode": "SPICE",
            "PhysicalTableMap": {"p1": {"RelationalTable": {"DataSourceArn": "arn:ds/s1", "Schema": "public", "Name": "trade",
                                                             "InputColumns": [{"Name": "station_code", "Type": "STRING"},
                                                                              {"Name": "price", "Type": "DECIMAL"},
                                                                              {"Name": "secret", "Type": "STRING"}]}}},
            "LogicalTableMap": {"l1": {"Source": {"PhysicalTableId": "p1"}, "DataTransforms": [
                {"RenameColumnOperation": {"ColumnName": "station_code", "NewColumnName": "station"}},
                {"CreateColumnsOperation": {"Columns": [{"ColumnName": "calc", "Expression": "price*2"}]}}]}},
            "OutputColumns": [{"Name": "station", "Type": "STRING"}, {"Name": "price", "Type": "DECIMAL"},
                              {"Name": "secret", "Type": "STRING"}, {"Name": "calc", "Type": "DECIMAL"}]}
    body.update(extra)
    return body


class DatasetPlanTest(unittest.TestCase):
    def test_renames_and_hides_calculated_columns(self):
        plan = ds.plan(dataset_body(), ["arn:user/a"])
        self.assertEqual(plan["columns"]["station"], {"expr": "station_code", "type": "STRING"})
        self.assertNotIn("calc", plan["columns"])
        self.assertIn("calc", plan["hidden"])
        self.assertEqual(plan["source"], {"table": ("public", "trade")})

    def test_refuses_row_level_security_filters_and_joins(self):
        with self.assertRaises(ds.Unsupported):
            ds.plan(dataset_body(RowLevelPermissionDataSet={"Arn": "x", "PermissionPolicy": "GRANT_ACCESS", "Status": "ENABLED"}), [])
        with self.assertRaises(ds.Unsupported):
            ds.plan(dataset_body(RowLevelPermissionTagConfiguration={"Status": "ENABLED", "TagRules": []}), [])
        filtered = dataset_body()
        filtered["LogicalTableMap"]["l1"]["DataTransforms"].append({"FilterOperation": {"ConditionExpression": "price > 0"}})
        with self.assertRaises(ds.Unsupported):
            ds.plan(filtered, [])
        joined = dataset_body()
        joined["PhysicalTableMap"]["p2"] = joined["PhysicalTableMap"]["p1"]
        with self.assertRaises(ds.Unsupported):
            ds.plan(joined, [])

    def test_disabled_rls_is_allowed(self):
        plan = ds.plan(dataset_body(RowLevelPermissionDataSet={"Arn": "x", "PermissionPolicy": "GRANT_ACCESS", "Status": "DISABLED"}), [])
        self.assertIn("price", plan["columns"])

    def test_column_level_security_hides_columns_for_others(self):
        rules = [{"Principals": ["arn:user/boss"], "ColumnNames": ["secret"]}]
        self.assertNotIn("secret", ds.plan(dataset_body(ColumnLevelPermissionRules=rules), ["arn:user/a"])["columns"])
        self.assertIn("secret", ds.plan(dataset_body(ColumnLevelPermissionRules=rules), ["arn:user/boss"])["columns"])

    def test_custom_sql_is_unsupported(self):
        custom = dataset_body(PhysicalTableMap={"p1": {"CustomSql": {"DataSourceArn": "arn:ds/s1", "Name": "q",
                                                                    "SqlQuery": "SELECT * FROM trade",
                                                                    "Columns": [{"Name": "price", "Type": "DECIMAL"}]}}})
        with self.assertRaisesRegex(ds.Unsupported, "Custom SQL"):
            ds.plan(custom, [])

    def test_only_columns_the_analysis_references(self):
        plan = ds.plan(dataset_body(), ["arn:user/a"], referenced={"station"})
        self.assertEqual(list(plan["columns"]), ["station"])
        self.assertEqual(plan["hidden"], [])  # unreferenced columns are not even named
        self.assertIn("只列出分析里用到的列", plan["notes"])
        self.assertEqual(set(ds.plan(dataset_body(), [])["columns"]), {"station", "price", "secret"})

    def test_connection_parameters(self):
        info = ds.connection({"Type": "POSTGRESQL", "DataSourceParameters": {"PostgreSqlParameters": {
            "Host": "db.example", "Port": 5432, "Database": "pivot"}}})
        self.assertEqual((info["engine"], info["host"], info["port"], info["ssl"]), ("postgresql", "db.example", 5432, True))
        with self.assertRaises(ds.Unsupported):
            ds.connection({"Type": "S3", "DataSourceParameters": {"S3Parameters": {}}})


def analysis_definition():
    col = lambda name: {"DataSetIdentifier": "trade", "ColumnName": name}
    return {
        "DataSetIdentifierDeclarations": [{"Identifier": "trade", "DataSetArn": "arn:aws-cn:quicksight:x:1:dataset/d1"}],
        "CalculatedFields": [{"DataSetIdentifier": "trade", "Name": "picked",
                              "Expression": "ifelse(${pMetric} = '价格', {price}, ${pMetric} = '电量', {elec}, NULL)"}],
        "ParameterDeclarations": [{"StringParameterDeclaration": {"Name": "pStation", "ParameterValueType": "SINGLE_VALUED",
                                                                  "DefaultValues": {"StaticValues": ["全部"]}}},
                                  {"StringParameterDeclaration": {"Name": "pMetric", "ParameterValueType": "SINGLE_VALUED"}}],
        "FilterGroups": [{"FilterGroupId": "g", "Status": "ENABLED", "CrossDataset": "SINGLE_DATASET",
                          "ScopeConfiguration": {"SelectedSheets": {"SheetVisualScopingConfigurations": [
                              {"SheetId": "s", "Scope": "ALL_VISUALS"}]}},
                          "Filters": [{"CategoryFilter": {"FilterId": "f", "Column": col("station"),
                                                          "Configuration": {"CustomFilterConfiguration": {
                                                              "MatchOperator": "EQUALS", "ParameterName": "pStation",
                                                              "NullOption": "NON_NULLS_ONLY"}}}}]}],
        "Sheets": [{"SheetId": "s", "Name": "主页",
                    "ParameterControls": [{"Dropdown": {"ParameterControlId": "c", "Title": "场站", "SourceParameterName": "pStation",
                                                        "SelectableValues": {"LinkToDataSetColumn": col("station")}}}],
                    "Visuals": [
                        {"LineChartVisual": {"VisualId": "v1", "Title": {"FormatText": {"PlainText": "趋势：<<$pMetric>>"}},
                                             "ChartConfiguration": {"FieldWells": {"LineChartAggregatedFieldWells": {
                                                 "Category": [{"DateDimensionField": {"FieldId": "d", "Column": col("t"), "DateGranularity": "DAY"}}],
                                                 "Values": [{"NumericalMeasureField": {"FieldId": "m", "Column": col("picked"),
                                                                                       "AggregationFunction": {"SimpleNumericalAggregation": "AVERAGE"}}}]}}}}},
                        {"BarChartVisual": {"VisualId": "v2", "ChartConfiguration": {"FieldWells": {"BarChartAggregatedFieldWells": {
                            "Category": [{"CategoricalDimensionField": {"FieldId": "s", "Column": col("station")}}],
                            "Values": [{"NumericalMeasureField": {"FieldId": "e", "Column": col("elec"),
                                                                  "AggregationFunction": {"SimpleNumericalAggregation": "MEDIAN"}}}]}},
                            "Orientation": "HORIZONTAL"}}},
                        {"KPIVisual": {"VisualId": "v3"}}]}]}


class DefinitionTest(unittest.TestCase):
    def test_parameters_controls_and_filters(self):
        d = analysis_definition()
        self.assertEqual(defs.parameters(d)["pStation"]["control"], "场站")
        self.assertEqual(defs.parameters(d)["pStation"]["values_from"], {"dataset": "trade", "column": "station"})
        bindings = defs.parameter_filters(d)
        self.assertEqual(bindings[0]["column"], "station")
        self.assertEqual(bindings[0]["roles"], [{"op": "eq", "parameter": "pStation"}])

    def test_preview_query_resolves_metric_switch_and_applies_controls(self):
        result = defs.preview_query(analysis_definition(), "v1", {"pMetric": "电量", "pStation": "ST1"})
        query = result["query"]
        self.assertEqual(query["metrics"], [{"column": "elec", "agg": "avg"}])
        self.assertEqual(query["time"], {"column": "t", "grain": "day"})
        self.assertEqual(query["filters"], [{"column": "station", "op": "eq", "value": "ST1"}])

    def test_preview_skips_all_values_and_reports_unsupported(self):
        query = defs.preview_query(analysis_definition(), "v1", {"pMetric": "价格", "pStation": "全部"})["query"]
        self.assertEqual(query["filters"], [])
        self.assertIn("unsupported", defs.preview_query(analysis_definition(), "v1", {"pMetric": "?"}))  # no branch matches
        self.assertIn("unsupported", defs.preview_query(analysis_definition(), "v2", {}))  # MEDIAN

    def test_preview_uses_parameter_defaults(self):
        d = analysis_definition()
        d["ParameterDeclarations"][1]["StringParameterDeclaration"]["DefaultValues"] = {"StaticValues": ["价格"]}
        query = defs.preview_query(d, "v1", {})["query"]
        self.assertEqual(query["metrics"], [{"column": "price", "agg": "avg"}])
        self.assertEqual(query["filters"], [])  # pStation default 全部 = no filter

    def test_switch_chart_type(self):
        d = analysis_definition()
        self.assertEqual(defs.replace_chart_type(d, "v1", "BarChartVisual"), "LineChartVisual")
        visual = d["Sheets"][0]["Visuals"][0]["BarChartVisual"]
        self.assertEqual(visual["VisualId"], "v1")
        self.assertIn("BarChartAggregatedFieldWells", visual["ChartConfiguration"]["FieldWells"])
        with self.assertRaises(ValueError):
            defs.replace_chart_type(d, "v3", "BarChartVisual")
        with self.assertRaises(ValueError):
            defs.replace_chart_type(d, "nope", "BarChartVisual")

    def test_referenced_columns(self):
        refs = defs.referenced_columns(analysis_definition())
        self.assertEqual(set(refs), {"d1"})
        # field wells, filters and controls, plus the real columns the metric-switch calculated field reads
        self.assertTrue({"station", "t", "price", "elec"} <= refs["d1"], refs)

    def test_model_view(self):
        view = defs.strip_for_model(analysis_definition())
        self.assertEqual(view["datasets"], {"trade": "d1"})
        self.assertEqual([v["visual_id"] for v in view["sheets"][0]["visuals"]], ["v1", "v2", "v3"])


def _data_handler():
    for key, value in (("ACCOUNT_ID", "1"), ("QS_REGION", "cn-north-1"), ("AWS_REGION", "cn-north-1"),
                       ("TOOL_SECRET_ID", "y")):
        os.environ.setdefault(key, value)
    spec = importlib.util.spec_from_file_location("data_handler", os.path.join(ROOT, "tools", "data", "handler.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DataHandlerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = _data_handler()

    def test_secret_is_only_the_assistant_secret(self):
        asked = []

        class Secrets:
            def get_secret_value(self, SecretId):  # noqa: N803
                asked.append(SecretId)
                if SecretId != "quicksight-chat-assistant/datasource/s1":
                    raise RuntimeError("not found")
                return {"SecretString": '{"username": "reader", "password": "p"}'}
        source = {"DataSourceId": "s1", "SecretArn": "arn:aws-cn:secretsmanager:cn-north-1:1:secret:qs-owned"}
        with mock.patch.object(self.data.boto3, "client", lambda *a, **k: Secrets()):
            self.assertEqual(self.data._secret(source), ("reader", "p"))
            with self.assertRaisesRegex(self.data.ToolError, "datasource-secret s2"):
                self.data._secret({**source, "DataSourceId": "s2"})
        self.assertEqual(asked, ["quicksight-chat-assistant/datasource/s1", "quicksight-chat-assistant/datasource/s2"])

    def test_describe_lists_only_referenced_columns(self):
        class QuickSight:
            def describe_analysis_definition(self, **_):
                return {"Definition": analysis_definition()}

            def describe_data_set(self, **_):
                return {"DataSet": dataset_body()}
        caller = self.data.caller
        with mock.patch.object(caller, "require_viewer", lambda args: ("a@example.com", "a1")), \
                mock.patch.object(caller, "cached", lambda key, loader, seconds=60: loader()), \
                mock.patch.object(caller, "principals", lambda email: {"arn:user/a"}), \
                mock.patch.object(self.data, "qs", QuickSight()):
            out = self.data.describe_dataset({"dataset_id": "d1", "_caller": "t", "_analysis": "a1"})
        self.assertEqual([c["name"] for c in out["columns"]], ["price", "station"])  # not "secret"
        self.assertNotIn("secret", out["hidden_columns"])


class ChartsTest(unittest.TestCase):
    def test_find_rows_and_pivot(self):
        rows = charts.find_rows({"columns": [], "rows": [
            {"t": "2026-01-01T00:00:00", "station": "A", "price": 1.5},
            {"t": "2026-01-01T00:00:00", "station": "B", "price": "2"},
            {"t": "2026-01-02T00:00:00", "station": "A", "price": None}]})
        labels, series, _notes = charts.from_rows(rows, "t", ["price"], "station")
        self.assertEqual(labels, ["2026-01-01", "2026-01-02"])
        self.assertEqual(series, [{"name": "A", "data": [1.5, None]}, {"name": "B", "data": [2.0, None]}])
        with self.assertRaises(ValueError):
            charts.from_rows(rows, "t", ["missing"])

    def test_nested_mcp_style_result(self):
        self.assertEqual(charts.find_rows({"result": {"data": [{"a": 1}]}}), [{"a": 1}])
        self.assertIsNone(charts.find_rows({"text": "no rows"}))


if __name__ == "__main__":
    unittest.main()
