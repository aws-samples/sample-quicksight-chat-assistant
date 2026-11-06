"""Marks this solution's chat in published dashboards, triggered by EventBridge on CreateDashboard / UpdateDashboard.

The browser does not tell the chat page which QuickSight page embeds it, and publishing in the console copies the
analysis' chat URL unchanged. After every publish this function adds where=dashboard to the chat URL in the new
dashboard version (and publishes that), so the chat in a dashboard knows it cannot change what the viewer sees. It
also tags the dashboard with its source analysis, which keeps dashboard-only viewers allowed (caller.dashboards_of).
Its own UpdateDashboard call triggers it again; the URL is then already marked and nothing happens.

publish_definition() is shared with the analysis tools (the 发布到仪表盘 button), which publish an already marked
definition, so the event that follows finds nothing to do.
"""

import json
import os
import re
import time

import boto3

ACCOUNT = os.environ["ACCOUNT_ID"]
CHAT_URL = os.environ.get("CHAT_URL", "").rstrip("/")  # set for the EventBridge function; callers may pass it
SOURCE_TAG = "qsca:source-analysis"
qs = boto3.client("quicksight", region_name=os.environ.get("QS_REGION"))


def log(**fields):
    print(json.dumps(fields, ensure_ascii=False, default=str))


def mark(definition, chat_url=None):
    """Add where=dashboard to every chat URL of this deployment; returns how many were changed."""
    chat_url = (chat_url or CHAT_URL).rstrip("/")
    if not chat_url:
        raise ValueError("chat URL unknown")
    changed = 0
    for sheet in definition.get("Sheets", []):
        for visual in sheet.get("Visuals", []):
            config = (visual.get("CustomContentVisual") or {}).get("ChartConfiguration") or {}
            url = config.get("ContentUrl") or ""
            if not url.startswith(chat_url) or re.search(r"[?&]where=dashboard(&|$)", url):
                continue
            url = re.sub(r"[?&]where=[^&]*", "", url)
            config["ContentUrl"] = url + ("&" if "?" in url else "?") + "where=dashboard"
            changed += 1
    return changed


def wait_until(fetch, ready, timeout, interval):
    """Call fetch() until ready(value) is true or `timeout` seconds (monotonic clock) have passed; returns the last
    value. The one polling loop of the analysis tools and the publisher (QuickSight has no waiter for these)."""
    deadline = time.monotonic() + timeout
    while True:
        value = fetch()
        remaining = deadline - time.monotonic()
        if ready(value) or remaining <= 0:
            return value
        # Bounded poll of a QuickSight status: at most `interval` seconds per round, never past the deadline.
        time.sleep(min(interval, remaining))  # nosemgrep: python.lang.best-practice.sleep.arbitrary-sleep


def _in_progress(info):
    return info["Version"]["Status"].endswith("_IN_PROGRESS")


def _settled(dashboard_id, version=None):
    args = {"VersionNumber": version} if version else {}
    info = wait_until(lambda: qs.describe_dashboard(AwsAccountId=ACCOUNT, DashboardId=dashboard_id, **args)["Dashboard"],
                      lambda i: not _in_progress(i), 120, 3)
    if _in_progress(info):
        raise TimeoutError(f"dashboard {dashboard_id} still in progress")
    return info


def publish_definition(dashboard_id, name, definition, options, description, analysis_id=""):
    """Create a new dashboard version from a definition, wait for it, publish it and tag the source analysis.
    Returns the version number; raises RuntimeError when QuickSight rejects the version."""
    new = qs.update_dashboard(AwsAccountId=ACCOUNT, DashboardId=dashboard_id, Name=name, Definition=definition,
                              DashboardPublishOptions=options or {}, VersionDescription=description[:512])
    number = int(new["VersionArn"].rsplit("/", 1)[-1])
    info = _settled(dashboard_id, number)
    status = info["Version"]
    if not status["Status"].endswith("SUCCESSFUL"):
        raise RuntimeError(f"dashboard {dashboard_id} version {number}: {status['Status']} {status.get('Errors')}")
    qs.update_dashboard_published_version(AwsAccountId=ACCOUNT, DashboardId=dashboard_id, VersionNumber=number)
    if analysis_id:
        arn = info["Arn"].split("/version/")[0]  # describe_dashboard with a version number returns a version ARN
        qs.tag_resource(ResourceArn=arn, Tags=[{"Key": SOURCE_TAG, "Value": analysis_id}])
    return number


def ids_from(event):
    """(dashboard id, analysis id or "") from an EventBridge CloudTrail event. Console publishes arrive as service
    events naming the analysis: a republish (UpdateDashboard) has the dashboard in eventRequestDetails, a first
    publish (CreateDashboard) only in eventResponseDetails. API calls (e.g. qsca publish) carry only the dashboard id."""
    detail = event.get("detail") or {}
    request = detail.get("requestParameters") or {}
    service = detail.get("serviceEventDetails") or {}
    asked, answered = service.get("eventRequestDetails") or {}, service.get("eventResponseDetails") or {}
    dashboard = request.get("dashboardId") or str(asked.get("dashboardId") or answered.get("dashboardId") or "").rsplit("/", 1)[-1]
    return dashboard, str(asked.get("analysisId") or "").rsplit("/", 1)[-1]


def handler(event, _context):
    dashboard_id, analysis_id = ids_from(event)
    if not dashboard_id:
        detail = event.get("detail") or {}
        log(event="dashboard_mark_skipped", reason="no dashboard id in the event", event_name=detail.get("eventName"),
            event_type=detail.get("eventType"))
        return {"skipped": "no dashboard id"}
    # The latest version, not the published one: our own UpdateDashboard triggers this again before its version is
    # published, and that newer version is already marked.
    versions = qs.list_dashboard_versions(AwsAccountId=ACCOUNT, DashboardId=dashboard_id)["DashboardVersionSummaryList"]
    latest = max(v["VersionNumber"] for v in versions)
    info = _settled(dashboard_id, latest)
    version = info["Version"]
    analysis_id = analysis_id or str(version.get("SourceEntityArn") or "").rsplit("/", 1)[-1]
    out = qs.describe_dashboard_definition(AwsAccountId=ACCOUNT, DashboardId=dashboard_id,
                                           VersionNumber=version["VersionNumber"])
    definition = out["Definition"]
    if not mark(definition):
        return {"dashboard": dashboard_id, "changed": False}
    try:
        number = publish_definition(dashboard_id, out["Name"], definition, out.get("DashboardPublishOptions"),
                                    f"chat marked as dashboard (from version {version['VersionNumber']})", analysis_id)
    except RuntimeError as error:
        log(event="dashboard_mark_failed", dashboard=dashboard_id, error=str(error)[:500])
        return {"dashboard": dashboard_id, "changed": False}
    log(event="dashboard_marked", dashboard=dashboard_id, analysis=analysis_id, from_version=version["VersionNumber"],
        version=number)
    return {"dashboard": dashboard_id, "changed": True, "version": number}
