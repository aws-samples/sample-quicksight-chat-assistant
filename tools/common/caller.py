"""Who is calling, and what may they do in QuickSight. Shared by the analysis and data tool Lambdas.

Every tool call carries `_caller` (a tool token the web Lambda issued for this user and analysis, see tokens.py) and
`_analysis` (the analysis the chat panel is embedded in). The agent Runtime adds both in code; the model can neither
see nor set them. This module verifies the token (audience "qsca:tools", bound to `_analysis`), maps the email to
the one QuickSight user with that email, and answers permission questions using QuickSight's own sharing settings,
so the assistant never lets anyone do more than QuickSight would.
"""

import hashlib
import json
import os
import re
import time

import boto3

import tokens

ACCOUNT = os.environ["ACCOUNT_ID"]
QS_REGION = os.environ.get("QS_REGION") or os.environ.get("AWS_REGION")
NAMESPACE = os.environ.get("QS_NAMESPACE", "default")
TOOL_SECRET_ID = os.environ["TOOL_SECRET_ID"]  # verifies tool tokens; the session-token key is not readable here
ALLOWED_ANALYSES = [a for a in os.environ.get("ALLOWED_ANALYSIS_IDS", "*").split(",") if a]
CACHE_SECONDS = 60
ANALYSIS_ID = re.compile(r"^[\w-]{1,512}$")

qs = boto3.client("quicksight", region_name=QS_REGION)
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


SOURCE_TAG = "qsca:source-analysis"  # set by `qsca publish`, whose dashboards are built from a definition


def dashboards_of(aid):
    """Dashboards whose current version was published from this analysis (console publish: SourceEntityArn;
    `qsca publish`: the SOURCE_TAG tag)."""
    def load():
        partition = "aws-cn" if QS_REGION.startswith("cn-") else "aws"
        arn = f"arn:{partition}:quicksight:{QS_REGION}:{ACCOUNT}:analysis/{aid}"
        found = []
        for summary in _paged(qs.list_dashboards, "DashboardSummaryList"):
            try:
                version = qs.describe_dashboard(AwsAccountId=ACCOUNT, DashboardId=summary["DashboardId"])["Dashboard"]["Version"]
            except qs.exceptions.ResourceNotFoundException:
                continue
            if version.get("SourceEntityArn") == arn:
                found.append(summary["DashboardId"])
                continue
            try:
                tags = qs.list_tags_for_resource(ResourceArn=summary["Arn"]).get("Tags", [])
            except Exception:  # noqa: BLE001 - tags are an optional link
                tags = []
            if any(t["Key"] == SOURCE_TAG and t["Value"] == aid for t in tags):
                found.append(summary["DashboardId"])
        return found
    return cached(f"dashboards:{aid}", load, 300)


def require_viewer(args):
    """The caller may view the analysis, or a dashboard published from it. Returns (email, analysis_id)."""
    aid = analysis_id(args)
    email = verify_token(args.get("_caller"), aid)
    arns = principals(email)
    if _has(analysis_permissions(aid), arns):
        return email, aid
    for dashboard_id in dashboards_of(aid):
        try:
            perms = cached(f"dperm:{dashboard_id}", lambda d=dashboard_id: qs.describe_dashboard_permissions(
                AwsAccountId=ACCOUNT, DashboardId=d).get("Permissions", []))
        except qs.exceptions.ResourceNotFoundException:
            continue  # deleted since dashboards_of() was cached
        if _has(perms, arns):
            return email, aid
    raise ToolError(f"{email} 没有查看这个分析或其仪表盘的权限")


def require_editor(args):
    """The caller holds quicksight:UpdateAnalysis on the analysis (directly or through a group)."""
    aid = analysis_id(args)
    email = verify_token(args.get("_caller"), aid)
    if not _has(analysis_permissions(aid), principals(email), "quicksight:UpdateAnalysis"):
        raise ToolError(f"{email} 没有编辑这个分析的权限，未做任何修改")
    return email, aid


_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def uref(email):
    """Non-reversible short reference for a user, for logs only. The signed-in
    identity is the user's email (PII); web/auth.py and agent/main.py hash it the
    same way, so logs across the Lambdas and the Runtime stay correlatable without
    writing the raw email to CloudWatch."""
    return "u_" + hashlib.sha256((email or "").encode("utf-8")).hexdigest()[:12]


def safe_err(text):
    """Redact email addresses from a tool-error string before it is logged.
    Some refusals embed the user's email (e.g. '<email> 没有编辑这个分析的权限');
    the model/user still receives the full message, but the email must not reach logs."""
    if not isinstance(text, str):
        return text
    return _EMAIL_RE.sub("<redacted-email>", text)


def log(**fields):
    print(json.dumps(fields, ensure_ascii=False, default=str))
