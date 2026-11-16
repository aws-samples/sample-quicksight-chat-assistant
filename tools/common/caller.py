"""Who is calling, and what may they do in QuickSight. Shared by the analysis and data tool Lambdas.

Every tool call carries `_caller` (a tool token the web Lambda issued for this user and analysis, see tokens.py) and
`_analysis` (the analysis the chat panel is embedded in). The agent Runtime adds both in code; the model can neither
see nor set them. This module verifies the token (audience "qsca:tools", bound to `_analysis`), maps the email to
the one QuickSight user with that email, and answers permission questions using QuickSight's own sharing settings,
so the assistant never lets anyone do more than QuickSight would.
"""

import hashlib
import hmac
import json
import os
import re
import time

import boto3

import logging_utils
import tokens

ACCOUNT = os.environ["ACCOUNT_ID"]
QS_REGION = os.environ.get("QS_REGION") or os.environ.get("AWS_REGION")
NAMESPACE = os.environ.get("QS_NAMESPACE", "default")
TOOL_SECRET_ID = os.environ["TOOL_SECRET_ID"]  # verifies tool tokens; the session-token key is not readable here
ALLOWED_ANALYSES = [a for a in os.environ.get("ALLOWED_ANALYSIS_IDS", "*").split(",") if a]
CACHE_SECONDS = 60
ANALYSIS_ID = re.compile(r"^[\w-]{1,512}$")

qs = boto3.client("quicksight", region_name=QS_REGION)
jobs = boto3.resource("dynamodb", endpoint_url=os.environ.get("DYNAMODB_ENDPOINT_URL") or None).Table(
    os.environ["JOBS_TABLE"]) if os.environ.get("JOBS_TABLE") else None
_cache = {}


class ToolError(Exception):
    """A refusal or a user-facing problem; the message is returned to the model as {"error": ...}."""


def cached(key, loader, seconds=CACHE_SECONDS):
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < seconds:
        return hit[1]
    value = loader()
    _cache[key] = (time.time(), value)
    return value


def _tool_key():
    def load():
        raw = boto3.client("secretsmanager").get_secret_value(SecretId=TOOL_SECRET_ID)["SecretString"]
        return tokens.signing_key(raw)  # same key as web/auth.py _tool_key
    return cached("tool-key", load, 3600)


def _preview_digest(query):
    encoded = json.dumps(query, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def mint_preview_capability(email, analysis, query):
    """Authorize one exact server-generated visual-preview query for five minutes."""
    return tokens.mint(_tool_key(), tokens.TOOLS_AUDIENCE, email, 300, analysis=analysis,
                       purpose="visual-preview", query_sha256=_preview_digest(query))[0]


def verify_preview_capability(capability, email, analysis, query):
    """Require a capability for this caller, analysis and exact preview query."""
    try:
        claims = tokens.verify(_tool_key(), capability, tokens.TOOLS_AUDIENCE,
                               required=("analysis", "purpose", "query_sha256"))
    except tokens.InvalidToken as error:
        raise ToolError("图表预览授权无效或已过期，请重新生成预览") from error
    valid = claims["sub"] == email and claims["analysis"] == analysis and claims["purpose"] == "visual-preview"
    if not valid or not hmac.compare_digest(str(claims["query_sha256"]), _preview_digest(query)):
        raise ToolError("图表预览授权与当前查询不匹配，请重新生成预览")


# Set by a Lambda that can read the jobs table (the analysis tools): sid -> True when that browser session signed out.
revocation_check = None


def verify_token(token, analysis):
    """Check a tool token (tokens.verify: HS256 signature with the tool key, issuer, audience "qsca:tools", expiry),
    that it was issued for `analysis` ("" for the analysis picker) and names its browser session (`sid`), and, where
    revocation_check is set, that the session has not signed out. A browser session token is refused (other key and
    audience). Returns the email."""
    if not token:
        raise ToolError("缺少已登录用户的身份")
    try:
        claims = tokens.verify(_tool_key(), token, tokens.TOOLS_AUDIENCE, required=("analysis", "sid"))
    except tokens.InvalidToken as error:
        raise ToolError("登录已过期，请重新登录后再试" if error.expired else "用户身份校验失败") from error
    if not isinstance(claims["sid"], str) or not claims["sid"]:
        raise ToolError("用户身份校验失败")
    if claims["analysis"] != analysis:
        raise ToolError("用户身份不是为这个分析签发的")
    if revocation_check is not None and revocation_check(claims["sid"]):
        raise ToolError("已退出登录，请重新登录后再试")
    return claims["sub"]


def analysis_id(args):
    value = str(args.get("_analysis") or "")
    if not ANALYSIS_ID.match(value):
        raise ToolError("聊天窗口没有绑定分析（嵌入地址缺少 analysis 参数），请联系管理员重新接入")
    if "*" not in ALLOWED_ANALYSES and value not in ALLOWED_ANALYSES:
        raise ToolError(f"分析 {value} 未开放给聊天助手")
    return value


def _paged(call, key, **kwargs):
    items, token = [], None
    while True:
        page = call(AwsAccountId=ACCOUNT, **kwargs, **({"NextToken": token} if token else {}))
        items += page.get(key, [])
        token = page.get("NextToken")
        if not token:
            return items


def principals(email):
    """ARNs of the one active QuickSight user with this email and of its groups.

    The email is the only link between the Identity Center sign-in and QuickSight, and QuickSight does not keep it
    unique, so several active users with the same email are refused rather than merged (their permissions would be
    combined, possibly someone else's)."""
    def load():
        users = [u for u in _paged(qs.list_users, "UserList", Namespace=NAMESPACE)
                 if (u.get("Email") or "").lower() == email.lower() and u.get("Active", True)]
        if len(users) > 1:
            raise ToolError(f"QuickSight 里有 {len(users)} 个活跃用户使用同一个邮箱，无法确定是哪一个；"
                            "请管理员停用或删除重复的用户后再试")
        arns = set()
        for user in users:
            arns.add(user["Arn"])
            groups = _paged(qs.list_user_groups, "GroupList", Namespace=NAMESPACE, UserName=user["UserName"])
            arns.update(group["Arn"] for group in groups)
        return arns
    found = cached(f"principals:{email.lower()}", load)
    if not found:
        raise ToolError(f"{email} 在 QuickSight 里没有对应的用户")
    return found


def _has(permissions, arns, action=None):
    return any(p["Principal"] in arns and (action is None or action in p["Actions"]) for p in permissions)


def analysis_permissions(aid):
    return cached(f"aperm:{aid}", lambda: qs.describe_analysis_permissions(
        AwsAccountId=ACCOUNT, AnalysisId=aid).get("Permissions", []))


SOURCE_TAG = "qsca:source-analysis"  # informational only; never used as authorization proof


def _analysis_arn(aid):
    partition = "aws-cn" if QS_REGION.startswith("cn-") else "aws"
    return f"arn:{partition}:quicksight:{QS_REGION}:{ACCOUNT}:analysis/{aid}"


def _dashboard_mapping(dashboard_id):
    if jobs is None:
        return None
    return jobs.get_item(Key={"jobId": f"dashboard#{dashboard_id}"}, ConsistentRead=True).get("Item")


def _dashboard_is_from(dashboard_id, aid, dashboard=None):
    dashboard = dashboard or qs.describe_dashboard(AwsAccountId=ACCOUNT, DashboardId=dashboard_id)["Dashboard"]
    analysis_arn = _analysis_arn(aid)
    version = dashboard["Version"]
    if version.get("SourceEntityArn") == analysis_arn:
        return True
    mapping = _dashboard_mapping(dashboard_id)
    return bool(mapping and mapping.get("analysisArn") == analysis_arn
                and mapping.get("dashboardArn") == dashboard.get("Arn")
                and int(mapping.get("versionNumber") or 0) == int(version.get("VersionNumber") or 0))


def dashboards_of(aid):
    """Dashboards proven to originate from this analysis.

    QuickSight's exact SourceEntityArn is authoritative. Definition-based publishes have no source ARN, so trusted
    publishers write an application-owned dashboard# mapping. Dashboard tags are retained for operations only and
    are deliberately ignored here because a tag is not provenance.
    """
    def load():
        found = []
        for summary in _paged(qs.list_dashboards, "DashboardSummaryList"):
            dashboard_id = summary["DashboardId"]
            try:
                dashboard = qs.describe_dashboard(AwsAccountId=ACCOUNT, DashboardId=dashboard_id)["Dashboard"]
            except qs.exceptions.ResourceNotFoundException:
                continue
            if _dashboard_is_from(dashboard_id, aid, dashboard):
                found.append(dashboard_id)
        return found
    return cached(f"dashboards:{aid}", load, 300)


def require_viewer(args):
    """Return (email, analysis id, dashboard id or None) for the caller's exact viewer scope."""
    aid = analysis_id(args)
    email = verify_token(args.get("_caller"), aid)
    arns = principals(email)
    if _has(analysis_permissions(aid), arns, "quicksight:DescribeAnalysis"):
        return email, aid, None
    for dashboard_id in dashboards_of(aid):
        try:
            if not _dashboard_is_from(dashboard_id, aid):
                continue  # provenance changed since dashboards_of() was cached
            perms = cached(f"dperm:{dashboard_id}", lambda d=dashboard_id: qs.describe_dashboard_permissions(
                AwsAccountId=ACCOUNT, DashboardId=d).get("Permissions", []))
        except qs.exceptions.ResourceNotFoundException:
            continue  # deleted since dashboards_of() was cached
        if _has(perms, arns, "quicksight:DescribeDashboard"):
            return email, aid, dashboard_id
    raise ToolError(f"{email} 没有查看这个分析或其仪表盘的权限")


def viewer_definition(aid, dashboard_id=None):
    """Return (name, definition) from the resource the viewer was authorized to describe."""
    if dashboard_id:
        out = cached(f"dashboard-def:{dashboard_id}", lambda: qs.describe_dashboard_definition(
            AwsAccountId=ACCOUNT, DashboardId=dashboard_id))
    else:
        out = cached(f"def:{aid}", lambda: qs.describe_analysis_definition(
            AwsAccountId=ACCOUNT, AnalysisId=aid))
    return out.get("Name") or aid, out["Definition"]


def require_editor(args):
    """The caller holds quicksight:UpdateAnalysis on the analysis (directly or through a group)."""
    aid = analysis_id(args)
    email = verify_token(args.get("_caller"), aid)
    if not _has(analysis_permissions(aid), principals(email), "quicksight:UpdateAnalysis"):
        raise ToolError(f"{email} 没有编辑这个分析的权限，未做任何修改")
    return email, aid


def uref(email):
    """Keyed deployment-wide user pseudonym for logs."""
    return logging_utils.uref(email)


def log(**fields):
    print(json.dumps(fields, ensure_ascii=False, default=str))
