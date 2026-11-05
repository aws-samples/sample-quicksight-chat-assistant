"""API Gateway HTTP API Lambda for the chat panel embedded in QuickSight.

Routes:
  GET  /                       chat page (index.html; its scripts are /static/render-<hash>.js and app-<hash>.js)
  GET  /static/<file>          render.js, app.js and the vendored ECharts / marked / DOMPurify, versioned names,
                               cached for a year
  GET  /auth/login             start IAM Identity Center SAML login (popup)
  POST /saml/acs               SAML assertion consumer; hands a session token (1 hour by default) to the iframe
  POST /auth/logout            sign out: revoke this session token and cancel its running answers
  GET  /me                     who is signed in
  POST /chat                   submit a question: stored as a job, sent to the Runtime, which acknowledges at once
  GET  /jobs/{id}              job status, progress and result (STALLED when heartbeats stop)
  POST /jobs/{id}/cancel       cancel a running job
  POST /changes/{id}/apply     the 应用到分析 button: apply a previewed analysis change as this user
  POST /dashboards/publish     the 发布到仪表盘 button: publish the analysis to its dashboards as this user
  GET  /bindable               an unbound chat visual: analyses this user may bind it to
  GET  /binding?analysis=ID    the analysis' current parameters (the page checks its URL is up to date)
  POST /bind                   the 绑定 / 更新绑定 button: point the chat visual(s) in the analysis at it
  GET  /examples?analysis=ID   the analysis' example questions (none: the page shows the default) and can_edit
  POST /examples               editors save the analysis' examples: {groups} | {add: {question, group}} | {reset}
"""

import base64
import hashlib
import html
import json
import os
import re
import secrets
import time
import urllib.parse
import uuid

import boto3
from botocore.config import Config

import auth

RUNTIME_ARN = os.environ["RUNTIME_ARN"]
RUNTIME_VERSION = os.environ.get("RUNTIME_VERSION", "0")
JOBS_TABLE = os.environ["JOBS_TABLE"]
ANALYSIS_TOOLS_FN = os.environ["ANALYSIS_TOOLS_FN"]
# The ACS URL registered in Identity Center. Default: this API's own address (known only per request, which avoids a
# deployment cycle between the Lambda and the HTTP API); set SAML_ACS_URL when serving through a custom domain.
ACS_OVERRIDE = os.environ.get("SAML_ACS_URL", "")
FRAME_ANCESTORS = os.environ.get("FRAME_ANCESTORS", "https://*.quicksight.amazonaws.cn https://*.amazonaws.cn")
SESSION_ID = re.compile(r"^[A-Za-z0-9-]{33,100}$")
ANALYSIS_ID = re.compile(r"^[\w-]{1,512}$")
NONCE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")
JOB_TTL_SECONDS = 24 * 3600
STALE_SECONDS = 150  # the Runtime heartbeats every 30 s
# Tool tokens (tokens.py): a job's lasts as long as the Runtime session may (maxLifetime), so long answers keep their
# tool access after the browser's 1-hour session token expires; a button click's lasts 5 minutes.
JOB_TOKEN_SECONDS = int(os.environ.get("JOB_TOKEN_SECONDS", "28800"))
BUTTON_TOKEN_SECONDS = 300
SESSION_JOBS_MAX = 50  # chat jobs remembered per sign-in, cancelled on sign-out if still running
# Third-party browser scripts vendored under web/vendor (see vendor/README.md); the page needs no CDN.
STATIC_FILES = ("echarts-6.1.0.min.js", "marked-18.1.1.umd.js", "purify-3.4.17.min.js")

jobs = boto3.resource("dynamodb").Table(JOBS_TABLE)
lambda_client = boto3.client("lambda")
# The Runtime only acknowledges, so a short read timeout is enough (it covers a session cold start).
agentcore = boto3.client("bedrock-agentcore", config=Config(read_timeout=25, connect_timeout=5, retries={"max_attempts": 1}))

HERE = os.path.dirname(os.path.abspath(__file__))
# Optional example questions for the chat page: JSON [{"group", "tip"?, "questions": [...]}] (config.json "examples").
EXAMPLES_JSON = os.environ.get("EXAMPLES_JSON", "") or "null"
STATIC = {}
for _name in STATIC_FILES:
    with open(os.path.join(HERE, "vendor", _name), encoding="utf-8") as script:
        STATIC[f"/static/{_name}"] = script.read()


def _versioned(filename):
    """The page's own scripts, under content-hashed names so the year-long cache never serves an old version."""
    with open(os.path.join(HERE, filename), encoding="utf-8") as script:
        body = script.read()
    name = filename[:-3] + "-" + hashlib.sha256(body.encode("utf-8")).hexdigest()[:16] + ".js"
    STATIC[f"/static/{name}"] = body
    return name


RENDER_JS = _versioned("render.js")  # safe DOM / Markdown rendering, loaded before app.js
APP_JS = _versioned("app.js")
with open(os.path.join(HERE, "index.html"), encoding="utf-8") as page:
    # Example questions travel as a JSON data block (not executed, so the CSP needs no inline script).
    INDEX_HTML = page.read().replace("__RENDER_JS__", RENDER_JS).replace("__APP_JS__", APP_JS).replace(
        "__EXAMPLES__", json.dumps(json.loads(EXAMPLES_JSON), ensure_ascii=True).replace("<", "\\u003c"))
STATIC_HEADERS = {"Content-Type": "application/javascript; charset=utf-8",
                  "Cache-Control": "public, max-age=31536000, immutable",
                  "X-Content-Type-Options": "nosniff"}

SECURITY_HEADERS = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff"}
# Scripts only from this origin (no inline script, no eval); styles allow 'unsafe-inline' because ECharts' tooltip
# writes style attributes. Requests only to this API; no plugins, no <base>, no form posts.
PAGE_CSP = ("default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            f"connect-src 'self'; base-uri 'none'; form-action 'none'; object-src 'none'; frame-ancestors 'self' {FRAME_ANCESTORS}")
PAGE_HEADERS = {**SECURITY_HEADERS, "Content-Type": "text/html; charset=utf-8", "Content-Security-Policy": PAGE_CSP}


def popup_headers(nonce=None):
    """The login popup runs at most one inline script, allowed by a per-response nonce."""
    script = f"'nonce-{nonce}'" if nonce else "'none'"
    return {**SECURITY_HEADERS, "Content-Type": "text/html; charset=utf-8",
            "Content-Security-Policy": (f"default-src 'none'; script-src {script}; style-src 'unsafe-inline'; "
                                        + "base-uri 'none'; form-action 'none'; object-src 'none'; frame-ancestors 'none'")}


def _uref(sub):
    """Non-reversible short reference for a user, for logs only. Keeps per-user
    correlation in CloudWatch without writing the sign-in email (PII) to logs."""
    return "u_" + hashlib.sha256((sub or "").encode("utf-8")).hexdigest()[:12]


_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _safe_err(text):
    """Redact email addresses from a tool-error string before it is logged.
    Analysis/data tools build some errors with the user's email (e.g.
    '<email> 没有编辑这个分析的权限'); the user still sees the full message in the
    response, but the email must not reach CloudWatch."""
    if not isinstance(text, str):
        return text
    return _EMAIL_RE.sub("<redacted-email>", text)


def respond(status, body, headers=None):
    return {"statusCode": status,
            "headers": headers or {**SECURITY_HEADERS, "Content-Type": "application/json; charset=utf-8"},
            "body": body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)}


def raw_body(event):
    body = event.get("body") or ""
    return base64.b64decode(body).decode("utf-8") if event.get("isBase64Encoded") else body


def request_json(event):
    return json.loads(raw_body(event) or "{}")


def bearer(event):
    header = (event.get("headers") or {}).get("authorization", "")
    return header[7:].strip() if header[:7].lower() == "bearer " else ""


def current_user(event):
    """The claims of the request's session token (not revoked), or None."""
    token = bearer(event)
    return auth.verify_session(token, jobs) if token else None


def acs_url(event):
    return ACS_OVERRIDE or f"https://{event['requestContext']['domainName']}/saml/acs"


def origin(event):
    return "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(acs_url(event)))


def popup(status, title, message, payload=None, target_origin=""):
    """Login popup page; hands the session to the opener iframe on this exact origin only."""
    script, nonce = "", None
    if payload is not None:
        nonce = secrets.token_urlsafe(18)
        data = json.dumps(payload, ensure_ascii=True).replace("<", "\\u003c")
        script = (f'<script nonce="{nonce}">(function(){{var d=' + data + ";var o=" + json.dumps(target_origin) + ";"
                  "if(window.opener){window.opener.postMessage(d,o);setTimeout(function(){window.close()},400);}"
                  "else{document.getElementById('m').textContent='登录成功，但无法回传到聊天窗口（弹窗与 QuickSight 页面的连接已断开）。请关闭此窗口，回到 QuickSight 重新点击登录。';}"
                  "})();</script>")
    page = ('<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>' + html.escape(title) + "</title>"
            '<style>body{font:15px/1.6 -apple-system,"PingFang SC",sans-serif;padding:32px;color:#16232b}</style></head>'
            '<body><h3>' + html.escape(title) + '</h3><p id="m">' + html.escape(message) + "</p>" + script + "</body></html>")
    return respond(status, page, popup_headers(nonce))


def login_start(event):
    nonce = (event.get("queryStringParameters") or {}).get("nonce", "")
    if not NONCE.match(nonce):
        return popup(400, "无法登录", "缺少或无效的 nonce，请从聊天窗口点击登录。")
    try:
        location = auth.login_redirect(jobs, nonce, acs_url(event))
    except auth.NotConfigured as error:
        return popup(503, "尚未配置登录", f"{error}。请联系管理员按部署手册完成 Identity Center 配置。")
    return {"statusCode": 302, "headers": {**SECURITY_HEADERS, "Location": location}, "body": ""}


def login_finish(event):
    form = urllib.parse.parse_qs(raw_body(event), keep_blank_values=True)
    try:
        token, payload, nonce, _attributes = auth.complete_login(jobs, (form.get("SAMLResponse") or [""])[0],
                                                                 (form.get("RelayState") or [""])[0], acs_url(event))
    except auth.AuthError as error:
        print(json.dumps({"auth": "rejected", "reason": str(error)[:300]}, ensure_ascii=False))
        return popup(403, "登录失败", str(error))
    except Exception as error:  # noqa: BLE001
        print(json.dumps({"auth": "error", "error": repr(error)[:500]}, ensure_ascii=False))
        return popup(500, "登录失败", "签名或断言校验出错，请稍后重试。")
    print(json.dumps({"auth": "ok", "user": _uref(payload["sub"]), "exp": payload["exp"],
                      "name_source": payload.get("name_source")}, ensure_ascii=False))
    message = {"type": "qsca-auth", "nonce": nonce, "token": token,
               "user": {"sub": payload["sub"], "name": payload["name"], "exp": payload["exp"]}}
    return popup(200, "登录成功", "正在返回聊天窗口…", message, origin(event))


def _session_jobs_key(user):
    return {"jobId": f"sessjobs#{user['jti']}"}


def _remember_job(user, job_id):
    """Record a chat job under this sign-in (the newest SESSION_JOBS_MAX), so sign-out can cancel it."""
    item = jobs.get_item(Key=_session_jobs_key(user), ConsistentRead=True).get("Item") or {}
    ids = [*(item.get("jobIds") or []), job_id][-SESSION_JOBS_MAX:]
    jobs.put_item(Item={**_session_jobs_key(user), "jobIds": ids, "createdAt": int(time.time()),
                        "expiresAt": int(user["exp"]) + 120})  # sign-out needs the session token, which expires


def logout(user):
    """The 退出 button: this session token stops working at once (other browsers' sessions are not affected), its
    answers still running are cancelled, and the analysis tools refuse its tool tokens (caller.revocation_check)."""
    auth.revoke_session(jobs, user, JOB_TOKEN_SECONDS)  # job tool tokens outlive the session token
    cancelled = 0
    item = jobs.get_item(Key=_session_jobs_key(user), ConsistentRead=True).get("Item") or {}
    for job_id in item.get("jobIds") or []:
        try:
            if cancel(str(job_id), user)["statusCode"] == 200:  # 404 / 409: gone or already finished
                cancelled += 1
        except Exception as error:  # noqa: BLE001 - one job must not fail the sign-out
            print(json.dumps({"job": str(job_id), "logoutCancel": repr(error)[:300]}))
    print(json.dumps({"auth": "logout", "user": _uref(user["sub"]), "cancelled": cancelled}))
    return respond(200, {"ok": True, "cancelled": cancelled})


def tool_token(user, analysis):
    """A 5-minute tool token for one button click, bound to this user, analysis ("" for the analysis picker) and
    sign-in (sid)."""
    return auth.mint_tool_token(user["sub"], analysis, BUTTON_TOKEN_SECONDS, sid=user["jti"])


def submit(event, user):
    try:
        body = request_json(event)
    except ValueError:
        return respond(400, {"error": "invalid JSON"})
    prompt = body.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 2000:
        return respond(400, {"error": "prompt must be 1-2000 characters"})
    analysis = body.get("analysis")
    if not isinstance(analysis, str) or not ANALYSIS_ID.match(analysis):
        return respond(400, {"error": "聊天窗口没有绑定分析（地址缺少 analysis 参数），请联系管理员重新接入"})
    session_id = body.get("sessionId")
    if not isinstance(session_id, str) or not SESSION_ID.match(session_id):
        session_id = f"qs-{uuid.uuid4().hex}"
    if publish_command(prompt):
        started = time.time()
        result = run_publish(event, user, analysis)
        if "error" in result:
            answer, ok = f"没有发布：{result['error']}", False
        else:
            names = "、".join(f"“{d['name']}”（第 {d['version']} 版）" for d in result.get("published", []))
            answer, ok = f"已把分析的当前内容发布到仪表盘 {names}。打开仪表盘后刷新即可看到；刚发布时图表可能短暂报错，再刷新一次。", True
        steps = [{"tool": "publish_dashboards", "arguments": {}, "ok": ok}]
        job_id = answer_directly(user, answer, steps)
        print(json.dumps({"job": job_id, "user": _uref(user["sub"]), "event": "publish_command", "ok": ok,
                          "ms": int((time.time() - started) * 1000)}))
        return respond(202, {"jobId": job_id, "sessionId": session_id})
    # A Runtime session keeps the code version it started with and the browser reuses its id for hours, so bind the
    # session to user, analysis and Runtime version: a redeploy, user switch or another analysis starts fresh.
    runtime_session = "qs-" + hashlib.sha256(
        f"{user['sub']}|{analysis}|{session_id}|{RUNTIME_VERSION}".encode()).hexdigest()[:48]
    job_id = uuid.uuid4().hex
    now = int(time.time())
    jobs.put_item(Item={"jobId": job_id, "status": "RUNNING", "owner": user["sub"], "sid": user["jti"], "createdAt": now,
                        "heartbeatAt": now, "runtimeSession": runtime_session, "expiresAt": now + JOB_TTL_SECONDS})
    _remember_job(user, job_id)
    # "auth" is a tool token for this job, not the browser's session token: bound to this user, analysis and sign-in
    # (sid, so the analysis tools refuse it after sign-out), valid for the Runtime session's maximum lifetime. The Runtime never shows it to the model and only attaches it to this
    # solution's own tools, which verify it and check the user's QuickSight permissions.
    # "where": the page the chat is embedded in. The browser does not reveal the QuickSight page, so dashboards
    # published with `qsca publish` carry where=dashboard in the chat URL; anything else counts as the analysis.
    where = "dashboard" if body.get("where") == "dashboard" else "analysis"
    payload = {"job": {"jobId": job_id}, "prompt": prompt, "history": body.get("history") or [],
               "analysis": analysis, "parameters": body.get("parameters") or {}, "where": where,
               "user": {"sub": user["sub"], "name": user.get("name")},
               "auth": auth.mint_tool_token(user["sub"], analysis, JOB_TOKEN_SECONDS, sid=user["jti"], jti=job_id)}
    try:
        response = agentcore.invoke_agent_runtime(
            agentRuntimeArn=RUNTIME_ARN, runtimeSessionId=runtime_session, contentType="application/json",
            accept="application/json", payload=json.dumps(payload, ensure_ascii=False).encode("utf-8"))
        ack = json.loads(response["response"].read().decode("utf-8"))
        if not ack.get("accepted"):
            raise RuntimeError(ack.get("error") or "runtime did not accept the job")
    except Exception as error:  # noqa: BLE001
        print(json.dumps({"job": job_id, "error": repr(error)[:800]}))
        jobs.update_item(Key={"jobId": job_id}, UpdateExpression="SET #s = :s, #e = :e",
                         ExpressionAttributeNames={"#s": "status", "#e": "error"},
                         ExpressionAttributeValues={":s": "FAILED", ":e": f"提交到 Runtime 失败: {str(error)[:300]}"})
        return respond(502, {"error": "runtime did not accept the job", "jobId": job_id})
    print(json.dumps({"job": job_id, "user": _uref(user["sub"]), "event": "submitted", "analysis": analysis, "where": where,
                      "runtimeVersion": RUNTIME_VERSION}, ensure_ascii=False))
    return respond(202, {"jobId": job_id, "sessionId": session_id, "status": "RUNNING"})


def owned_job(job_id, user):
    if not HEX32.match(job_id):
        return None
    item = jobs.get_item(Key={"jobId": job_id}, ConsistentRead=True).get("Item")
    return item if item and item.get("owner") == user["sub"] else None


def status(job_id, user):
    item = owned_job(job_id, user)
    if not item:
        return respond(404, {"error": "job not found"})
    result = {"jobId": job_id, "status": item["status"], "progress": item.get("progress"),
              "heartbeatAt": int(item.get("heartbeatAt") or 0), "createdAt": int(item["createdAt"])}
    if item["status"] == "RUNNING" and time.time() - result["heartbeatAt"] > STALE_SECONDS:
        result["status"] = "STALLED"
        result["error"] = f"任务已 {int(time.time() - result['heartbeatAt'])} 秒没有心跳，Runtime 会话可能已结束"
    if item.get("result"):
        result.update(json.loads(item["result"]))
    if item.get("error"):
        result["error"] = item["error"]
    return respond(200, result)


def cancel(job_id, user):
    item = owned_job(job_id, user)
    if not item:
        return respond(404, {"error": "job not found"})
    try:
        jobs.update_item(Key={"jobId": job_id}, UpdateExpression="SET #s = :c, cancelledAt = :t",
                         ConditionExpression="#s = :running", ExpressionAttributeNames={"#s": "status"},
                         ExpressionAttributeValues={":c": "CANCELLED", ":t": int(time.time()), ":running": "RUNNING"})
    except jobs.meta.client.exceptions.ConditionalCheckFailedException:
        return respond(409, {"error": "job is not running", "status": item["status"]})
    signalled = False
    try:  # same session -> same microVM: the job thread stops now; otherwise at its next heartbeat (<= 30 s)
        response = agentcore.invoke_agent_runtime(
            agentRuntimeArn=RUNTIME_ARN, runtimeSessionId=item["runtimeSession"], contentType="application/json",
            accept="application/json", payload=json.dumps({"cancel": {"jobId": job_id}}).encode("utf-8"))
        signalled = bool(json.loads(response["response"].read().decode("utf-8")).get("cancelled"))
    except Exception as error:  # noqa: BLE001
        print(json.dumps({"job": job_id, "cancelSignal": repr(error)[:500]}))
    print(json.dumps({"job": job_id, "user": _uref(user["sub"]), "event": "cancelled", "signalled": signalled}))
    return respond(200, {"jobId": job_id, "status": "CANCELLED", "signalled": signalled})


def apply_change(change_id, event, user):
    """The 应用到分析 button: the analysis-tools Lambda applies the pending change as this user; no model involved."""
    try:
        body = request_json(event)
    except ValueError:
        body = {}
    analysis = body.get("analysis")
    if not HEX32.match(change_id) or not isinstance(analysis, str) or not ANALYSIS_ID.match(analysis):
        return respond(400, {"error": "invalid change"})
    response = lambda_client.invoke(FunctionName=ANALYSIS_TOOLS_FN, Payload=json.dumps(
        {"__tool": "apply_pending_change", "pending_change_id": change_id, "_caller": tool_token(user, analysis),
         "_analysis": analysis}).encode("utf-8"))
    result = json.loads(response["Payload"].read() or b"{}")
    print(json.dumps({"change": change_id, "user": _uref(user["sub"]), "event": "apply", "ok": "error" not in result,
                      "error": _safe_err(result.get("error"))}, ensure_ascii=False))
    return respond(409 if "error" in result else 200, result)


def publish_dashboards(event, user):
    """The 发布到仪表盘 button after an applied change; the analysis-tools Lambda checks the user's permissions."""
    try:
        body = request_json(event)
    except ValueError:
        body = {}
    analysis = body.get("analysis")
    if not isinstance(analysis, str) or not ANALYSIS_ID.match(analysis):
        return respond(400, {"error": "invalid analysis"})
    result = run_publish(event, user, analysis)
    return respond(409 if "error" in result else 200, result)


def run_button_tool(event, user, tool, analysis=None, extra=None):
    """Button-only analysis tools (never the model): the analysis-tools Lambda checks this user's permissions."""
    payload = {"__tool": tool, "_chat_url": f"https://{event.get('requestContext', {}).get('domainName', '')}",
               **(extra or {})}
    if analysis is not None:
        if not isinstance(analysis, str) or not ANALYSIS_ID.match(analysis):
            return respond(400, {"error": "invalid analysis"})
        payload["_analysis"] = analysis
    payload["_caller"] = tool_token(user, analysis)
    response = lambda_client.invoke(FunctionName=ANALYSIS_TOOLS_FN, Payload=json.dumps(payload).encode("utf-8"))
    result = json.loads(response["Payload"].read() or b"{}")
    if tool == "bind_chat":
        print(json.dumps({"user": _uref(user["sub"]), "event": "bind_chat", "analysis": analysis, "ok": "error" not in result,
                          "changed": result.get("changed"), "error": _safe_err(result.get("error"))}, ensure_ascii=False))
    return respond(409 if "error" in result else 200, result)


def run_publish(event, user, analysis):
    domain = event.get("requestContext", {}).get("domainName", "")
    response = lambda_client.invoke(FunctionName=ANALYSIS_TOOLS_FN, Payload=json.dumps(
        {"__tool": "publish_dashboards", "_caller": tool_token(user, analysis), "_analysis": analysis,
         "_chat_url": f"https://{domain}"}).encode("utf-8"))
    result = json.loads(response["Payload"].read() or b"{}")
    print(json.dumps({"user": _uref(user["sub"]), "event": "publish_dashboards", "ok": "error" not in result,
                      "published": result.get("published"), "error": _safe_err(result.get("error"))}, ensure_ascii=False))
    return result


# "发布到仪表盘" typed in the chat runs the same publish as the button, here and without the model (which could
# answer from the conversation history instead of acting). Short requests only; questions and negations go to the model.
PUBLISH_WORDS = re.compile(r"发布|更新|同步|推送")
PUBLISH_TARGET = re.compile(r"仪表盘|仪表板|控制面板|看板|dashboard", re.I)
NOT_PUBLISH = re.compile(r"不要|别|不用|无需|吗|？|\?|怎么|如何|为什么|什么时候|能否|是否|会不会|撤销|改成|改为|新增|删除|画")


def publish_command(prompt):
    text = re.sub(r"\s+", "", prompt or "")
    return bool(text) and len(text) <= 30 and bool(PUBLISH_WORDS.search(text) and PUBLISH_TARGET.search(text)) \
        and not NOT_PUBLISH.search(text)


def answer_directly(user, answer, steps):
    """Store a finished job (no Runtime call) so the page shows it like any other answer."""
    job_id, now = uuid.uuid4().hex, int(time.time())
    jobs.put_item(Item={"jobId": job_id, "status": "SUCCEEDED", "owner": user["sub"], "createdAt": now, "heartbeatAt": now,
                        "expiresAt": now + JOB_TTL_SECONDS,
                        "result": json.dumps({"answer": answer, "steps": steps, "model": "（直接执行）", "totalMs": 0},
                                             ensure_ascii=False)})
    return job_id


def handler(event, context):
    http = event.get("requestContext", {}).get("http", {})
    method, path = http.get("method", ""), event.get("rawPath", "/")
    if method == "GET" and path in ("/", "/index.html"):
        query = event.get("queryStringParameters") or {}
        print(json.dumps({"event": "page", "params": sorted(query), "where": query.get("where")}))
        return respond(200, INDEX_HTML, PAGE_HEADERS)
    if method == "GET" and path in STATIC:
        return respond(200, STATIC[path], STATIC_HEADERS)
    if method == "GET" and path == "/health":
        return respond(200, {"ok": True})
    if method == "GET" and path == "/auth/login":
        return login_start(event)
    if method == "POST" and path == "/saml/acs":
        return login_finish(event)
    user = current_user(event)
    if not user:
        return respond(401, {"error": "unauthorized", "login": True})
    if method == "GET" and path == "/me":
        return respond(200, {"sub": user["sub"], "name": user.get("name"), "exp": user["exp"]})
    if method == "POST" and path == "/auth/logout":
        return logout(user)
    if method == "POST" and path == "/chat":
        return submit(event, user)
    if method == "POST" and re.fullmatch(r"/changes/[0-9a-f]{32}/apply", path):
        return apply_change(path.split("/")[2], event, user)
    if method == "POST" and path == "/dashboards/publish":
        return publish_dashboards(event, user)
    if method == "GET" and path == "/bindable":
        return run_button_tool(event, user, "bindable_analyses")
    if method == "GET" and path == "/binding":
        return run_button_tool(event, user, "chat_binding", (event.get("queryStringParameters") or {}).get("analysis"))
    if method == "GET" and path == "/examples":
        return run_button_tool(event, user, "get_examples", (event.get("queryStringParameters") or {}).get("analysis"))
    if method == "POST" and path == "/examples":
        try:
            body = request_json(event)
        except ValueError:
            body = {}
        extra = {k: body[k] for k in ("groups", "add", "reset", "base") if k in body}
        return run_button_tool(event, user, "save_examples", body.get("analysis"), extra)
    if method == "POST" and path == "/bind":
        try:
            body = request_json(event)
        except ValueError:
            body = {}
        return run_button_tool(event, user, "bind_chat", body.get("analysis"))
    if method == "POST" and re.fullmatch(r"/jobs/[0-9a-f]{32}/cancel", path):
        return cancel(path.split("/")[2], user)
    if method == "GET" and re.fullmatch(r"/jobs/[0-9a-f]{32}", path):
        return status(path.rsplit("/", 1)[-1], user)
    return respond(404, {"error": "not found"})
