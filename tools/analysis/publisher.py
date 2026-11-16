"""Maintains chat markers and trusted provenance for published dashboards from QuickSight lifecycle events.

The browser does not tell the chat page which QuickSight page embeds it, and publishing in the console copies the
analysis' chat URL unchanged. After every publish this function adds where=dashboard to the chat URL in the new
dashboard version (and publishes that), so the chat in a dashboard knows it cannot change what the viewer sees. It
also records a version-bound dashboard-to-analysis mapping in the application table. The source tag is retained for
operator visibility only and never authorizes a viewer. Its own UpdateDashboard call triggers it again; the URL is
then already marked and nothing happens.

publish_definition() is shared with the analysis tools (the 发布到仪表盘 button), which publish an already marked
definition, so the event that follows finds nothing to do.
"""

import json
import os
import re
import time

import boto3

import logging_utils

ACCOUNT = os.environ["ACCOUNT_ID"]
REGION = os.environ.get("QS_REGION") or os.environ.get("AWS_REGION")
CHAT_URL = os.environ.get("CHAT_URL", "").rstrip("/")  # set for the EventBridge function; callers may pass it
SOURCE_TAG = "qsca:source-analysis"  # informational only
qs = boto3.client("quicksight", region_name=REGION)
jobs = boto3.resource("dynamodb").Table(os.environ["JOBS_TABLE"]) if os.environ.get("JOBS_TABLE") else None


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


def _analysis_arn(analysis_id):
    partition = "aws-cn" if REGION.startswith("cn-") else "aws"
    return f"arn:{partition}:quicksight:{REGION}:{ACCOUNT}:analysis/{analysis_id}"


def _source_analysis_arn(value):
    """Normalize an event/source analysis ID or ARN to this deployment's exact analysis ARN."""
    if not isinstance(value, str) or not value:
        return None
    if re.fullmatch(r"[\w-]{1,512}", value):
        return _analysis_arn(value)
    analysis_id = value.rsplit("/", 1)[-1]
    expected = _analysis_arn(analysis_id) if re.fullmatch(r"[\w-]{1,512}", analysis_id) else None
    return expected if value == expected else None


def validated_analysis_arn(analysis_id):
    """Return an existing same-partition/region/account analysis ARN, or None."""
    if not isinstance(analysis_id, str) or not re.fullmatch(r"[\w-]{1,512}", analysis_id):
        return None
    expected = _analysis_arn(analysis_id)
    try:
        actual = qs.describe_analysis(AwsAccountId=ACCOUNT, AnalysisId=analysis_id)["Analysis"]["Arn"]
    except qs.exceptions.ResourceNotFoundException:
        return None
    return expected if actual == expected else None


def save_mapping(dashboard_id, dashboard_arn, analysis_arn, version_number):
    if jobs is None:
        raise RuntimeError("JOBS_TABLE is required for dashboard provenance")
    jobs.put_item(Item={"jobId": f"dashboard#{dashboard_id}", "dashboardArn": dashboard_arn,
                        "analysisArn": analysis_arn, "versionNumber": int(version_number),
                        "updatedAt": int(time.time())})


def delete_mapping(dashboard_id):
    if jobs is not None:
        jobs.delete_item(Key={"jobId": f"dashboard#{dashboard_id}"})


def publish_definition(dashboard_id, name, definition, options, description, analysis_id=""):
    """Create and publish a dashboard version, then record trusted source provenance."""
    analysis_arn = validated_analysis_arn(analysis_id) if analysis_id else None
    if analysis_id and not analysis_arn:
        raise RuntimeError(f"analysis {analysis_id} is not a validated source in this account and region")
    new = qs.update_dashboard(AwsAccountId=ACCOUNT, DashboardId=dashboard_id, Name=name, Definition=definition,
                              DashboardPublishOptions=options or {}, VersionDescription=description[:512])
    number = int(new["VersionArn"].rsplit("/", 1)[-1])
    info = _settled(dashboard_id, number)
    status = info["Version"]
    if not status["Status"].endswith("SUCCESSFUL"):
        raise RuntimeError(f"dashboard {dashboard_id} version {number}: {status['Status']} {status.get('Errors')}")
    qs.update_dashboard_published_version(AwsAccountId=ACCOUNT, DashboardId=dashboard_id, VersionNumber=number)
    if analysis_arn:
        arn = info["Arn"].split("/version/")[0]  # describe_dashboard with a version number returns a version ARN
        save_mapping(dashboard_id, arn, analysis_arn, number)
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
    if (event.get("detail") or {}).get("eventName") == "DeleteDashboard":
        delete_mapping(dashboard_id)
        return {"dashboard": dashboard_id, "deleted": True}
    # The latest version, not the published one: our own UpdateDashboard triggers this again before its version is
    # published, and that newer version is already marked.
    versions = qs.list_dashboard_versions(AwsAccountId=ACCOUNT, DashboardId=dashboard_id)["DashboardVersionSummaryList"]
    latest = max(v["VersionNumber"] for v in versions)
    info = _settled(dashboard_id, latest)
    version = info["Version"]
    detail = event.get("detail") or {}
    service = detail.get("serviceEventDetails") or {}
    asked = service.get("eventRequestDetails") or {}
    event_source = asked.get("analysisId")
    version_source = version.get("SourceEntityArn")
    event_arn = _source_analysis_arn(event_source)
    version_arn = _source_analysis_arn(version_source)
    sources_agree = not ((event_source and not event_arn) or (version_source and not version_arn)
                         or (event_arn and version_arn and event_arn != version_arn))
    source_arn = (event_arn or version_arn) if sources_agree else None
    candidate = source_arn.rsplit("/", 1)[-1] if source_arn else ""
    analysis_arn = validated_analysis_arn(candidate) if candidate else None
    if analysis_arn != source_arn:
        analysis_arn = None
    analysis_id = candidate if analysis_arn else ""
    out = qs.describe_dashboard_definition(AwsAccountId=ACCOUNT, DashboardId=dashboard_id,
                                           VersionNumber=version["VersionNumber"])
    definition = out["Definition"]
    dashboard_arn = info["Arn"].split("/version/")[0]
    changed = mark(definition)
    if analysis_arn:
        save_mapping(dashboard_id, dashboard_arn, analysis_arn, version["VersionNumber"])
    elif jobs is not None:
        mapping = jobs.get_item(Key={"jobId": f"dashboard#{dashboard_id}"}, ConsistentRead=True).get("Item")
        if changed or (mapping and int(mapping.get("versionNumber") or 0) != int(version["VersionNumber"])):
            delete_mapping(dashboard_id)
    if not changed:
        return {"dashboard": dashboard_id, "changed": False}
    try:
        number = publish_definition(dashboard_id, out["Name"], definition, out.get("DashboardPublishOptions"),
                                    f"chat marked as dashboard (from version {version['VersionNumber']})", analysis_id)
    except RuntimeError as error:
        log(event="dashboard_mark_failed", dashboard=dashboard_id, **logging_utils.exception_fields(error))
        return {"dashboard": dashboard_id, "changed": False}
    log(event="dashboard_marked", dashboard=dashboard_id, analysis=analysis_id, from_version=version["VersionNumber"],
        version=number)
    return {"dashboard": dashboard_id, "changed": True, "version": number}
