# Security threat model

This document describes the controls that the QuickSight chat assistant implements for authentication, authorization,
model input, SQL, browser rendering, deployment and operations. The verified deployment target is AWS China (Beijing,
`cn-north-1`).

**Status.** This repository is sample code, not a production security boundary. Review the controls and residual risks
against your own identity, data, network and model requirements before deployment.

## Why the sample has its own authentication

The chat page runs in an iframe inside QuickSight and does not receive the QuickSight user's identity. Amazon Cognito
user pools are unavailable in AWS China, so the sample uses IAM Identity Center as its SAML identity provider and
validates assertions in the web Lambda. This makes `web/auth.py`, `web/handler.py`, `tools/common/tokens.py` and
`tools/common/caller.py` security-critical application code. Prefer a suitable managed identity service where one is
available.

## Components and trust boundaries

| Component | Accepted trust | Enforced boundary |
|---|---|---|
| Browser (`web/index.html`, `render.js`, `app.js`) | A successful SAML flow and same-origin API responses | Holds only an opaque HttpOnly session cookie and a readable CSRF token; URL parameters and local history never establish identity or authorization |
| Web Lambda (`web/auth.py`, `web/handler.py`) | Identity Center assertions signed by a certificate in stored IdP metadata | Validates the browser session and CSRF token; injects the user, analysis and tool token into jobs and button actions |
| AgentCore Runtime (`agent/main.py`) | The authenticated job payload from the web Lambda | Injects `_caller`, `_analysis` and `_parameters` in code; the model cannot set them; untrusted model input is separated and bounded |
| Analysis/data Lambdas (`tools/`) | A valid `qsca:tools` token and live/cached QuickSight permissions | Recompute authorization, dashboard scope, columns and query policy rather than trusting the model |
| Model endpoint | No authority | Receives data and proposes structured calls; it never supplies identity, raw SQL, IAM decisions or mutation approval |
| Enterprise MCP targets | Only explicit operator configuration | The model sees only exact tool names in `enterpriseReadOnlyTools`; those tools receive no QuickSight user token |

## Authentication, browser session and CSRF

1. `/auth/login` stores one-time `saml#<request-id>` state and redirects to Identity Center with a generated
   AuthnRequest.
2. `/saml/acs` parses XML with DTDs, external entities, network access and huge trees disabled. It requires exactly one
   assertion, verifies its signature against every signing certificate in the stored metadata, and checks issuer,
   audience, ACS recipient, request binding, validity, assertion ID and replay state.
3. After validation, the web Lambda creates a random opaque browser session. DynamoDB stores its claims, expiry, `jti`
   and a separate random CSRF token under a SHA-256-derived `browser-session#...` key. The response sets only
   `__Host-qsca-session=<opaque-id>; Secure; HttpOnly; SameSite=None; Path=/`; the popup sends no credential through
   `postMessage`.
4. The page calls `/me` with the cookie to obtain display identity and the CSRF token. Every authenticated `POST`
   requires `x-csrf-token` to match the server-side session. `GET` routes remain non-mutating.
5. `POST /auth/logout` deletes the opaque browser session, writes `revoked#<jti>` long enough to cover derived tool
   tokens, clears the cookie and attempts to cancel remembered jobs.

A signed HS256 `qsca:session` JWT remains only for the administrator `qsca smoke` path and unit compatibility. Browser
JavaScript never receives or stores it. Tool JWTs use a separate `<prefix>/tool-key`, are bound to user, analysis and
browser-session `jti`, and have audience `qsca:tools`. The analysis tools check revocation. The browser and enterprise
MCP servers never receive a tool token.

## QuickSight authorization and provenance

The SAML NameID email is lower-cased and must map to exactly one active QuickSight user. Zero matches and duplicate
active users both fail closed. Group membership is read with `ListUserGroups`.

- Direct analysis access requires `quicksight:DescribeAnalysis`; edit, apply, bind and example maintenance require
  `quicksight:UpdateAnalysis`.
- Dashboard-only access requires `quicksight:DescribeDashboard`. It uses that dashboard's published definition and
  never falls through to the live analysis draft.
- A dashboard belongs to an analysis only when QuickSight reports the exact same-partition/account/region analysis
  `SourceEntityArn`, or a trusted publisher wrote an application-owned `dashboard#<id>` record for that exact dashboard
  ARN and version. Dashboard tags are informational and never authorize.
- The publisher normalizes event IDs and dashboard-version source ARNs to the same exact
  same-partition/account/region ARN, requires agreement when both exist, validates the analysis, records the final
  marked dashboard version, and removes stale mappings after version or deletion changes. `ALLOWED_ANALYSIS_IDS`
  remains an independent deployment allowlist.
- Permission/group caches last up to 60 seconds; dashboard enumeration lasts up to five minutes. Provenance is checked
  again after the dashboard list cache.

## Dataset, column and fixed-filter policy

Data tools load the definition for the exact authorized resource. Shared dataset metadata is cached without a caller
policy, then narrowed for each caller:

- Dataset RLS and tag RLS must both be present only in the explicitly `DISABLED` state. Dataset filters, joins and
  custom SQL are refused.
- QuickSight column-level permission rules are applied using the caller's user and group principals after every shared
  metadata-cache read.
- Caller-queryable columns come only from visual field wells and reachable controls in the authorized analysis or
  dashboard definition. The model-visible visual, filter, control and parameter summary uses that same post-CLS map;
  denied fields and controls are omitted, as are calculated fields with a denied dependency. Filter-only, sort-only
  and calculated-field dependency columns are not offered to the model. A server-generated visual preview may use an
  exact CLS-permitted parameter-switch dependency only when a short-lived capability signs the complete preview query;
  the capability is not exposed through the model tool schema and cannot authorize dimensions, filters or distinct values.
- Columns required for mandatory policy predicates remain in a separate internal map only after CLS permits them for
  that caller. They cannot be selected or used in a caller QuerySpec, and a mandatory predicate on a CLS-denied column
  rejects the direct query before database access.
- Enabled whole-analysis, single-dataset `AND` category, time-range, numeric-range and numeric-equality filters are
  compiled as mandatory predicates and ANDed into every query, including generated edit previews; previews do not copy
  these policy predicates into the caller-filter portion of QuerySpec. Parameter defaults preserve every declared static
  value. A browser value overrides a default only when the authorized definition contains a viewer-reachable control and
  the value matches its declared type, single/multi-value shape and any static choices. A browser Select All sentinel is
  honored only when that control explicitly sets `DisplayOptions.SelectAllOptions.Visibility` to `VISIBLE`; otherwise
  the trusted declaration default remains. The browser normalizes localized Select All values to the canonical `all`
  sentinel while missing or unsubstituted values remain empty. Hidden/non-control parameters keep their declaration
  defaults. Missing dynamic defaults, unsupported status, OR, partial sheet/visual scope, cross-dataset scope,
  unsupported null semantics or unsupported filter shape fails closed.
- Analysis preview and apply recalculate caller-visible columns. A column hidden after preview cannot be applied.

## QuerySpec to SQL boundary

The model submits a bounded QuerySpec. `tools/data/sqlcompile.py` accepts only known object keys, fixed aggregates,
grains, operators and ordering. Identifiers must exist in the caller-visible plan and are dialect-quoted. Values are
finite bounded scalars or bounded lists and remain driver parameters. Mandatory filters use the caller's CLS-permitted
policy-column map and are appended with `AND`. The relation is one planned `schema.table`; execution uses a read-only
transaction, a 20-second statement timeout and at most 500 rows. The model never submits SQL text.

## Database target, TLS and network boundary

`./qsca datasource-secret <DataSourceId>` resolves the exact same-account/region QuickSight data source and any RDS
instance, prints engine, host, port, database, ARN and `tls_required: true`, then requires operator approval before it
reads and stores the dedicated SELECT-only credential. `./qsca check` compares that pin with current QuickSight/RDS
metadata. The data Lambda compares the full target before reading username/password and refuses old or drifted records.

The data Lambda creates a certificate-verifying, hostname-checking TLS context. PostgreSQL verifies `pg_stat_ssl`.
MySQL checks the server's TLS capability after the greeting but before sending authentication data, then verifies both
PyMySQL's secure-session state and a non-empty `Ssl_cipher`. `DisableSsl`, TLS downgrade, target drift and unverifiable
sessions fail before query execution. The bundle includes the AWS China RDS CA stores only after their fixed SHA-256
values and combined bundle digest pass.

When `dataAccess.vpc` is configured, the stack-owned `DataToolsSg` has `allowAllOutbound: false`. It permits only the
configured `databaseEgress` CIDR/port pairs and TCP 443 to owned QuickSight, Secrets Manager, DynamoDB and RDS API
interface endpoint security groups, or to explicit `endpointHttpsCidrs` when endpoints are managed outside the stack.
Owned DynamoDB and RDS endpoints supply endpoint-specific URLs to their SDK clients; existing endpoints require
validated `dynamodbEndpointUrl` and `rdsEndpointUrl` values because DynamoDB interface endpoints do not override the
regional DNS name and China-region RDS API endpoints use distinct endpoint DNS. Any security group in
`securityGroupIds` contributes additive egress and must be audited not to add NAT, internet or broad VPC access. AWS
China endpoint service names and `arn:aws-cn` partition handling are preserved.

## Explicit mutation boundary

The model may create an analysis-change preview, but it cannot apply one. Apply claims a requester/analysis-bound
pending record once within ten minutes, recalculates authorization and columns, and backs up the current definition.
Publish and undo command text produce confirmation records only. A CSRF-protected browser button invokes the
corresponding button-only route with a five-minute tool token. Undo is absent from the Gateway schema/model tool list,
and `force` is accepted only as the literal boolean `true` from the explicit button action. Stored example text travels
through the same confirmation behavior and cannot publish or undo directly.

Example updates have raw-body, collection, group, question and string limits before traversal. Stable deduplication is
set-backed. Viewer responses omit the last editor identity.

## Model-data boundary

The system role contains only static rules, dashboard mode and the Beijing date. Current request text, control values,
authorized metadata, browser history and every local/Gateway/enterprise tool result are treated as untrusted data.
Before model use, the runtime:

- rejects a tool response above 1 MiB of raw UTF-8 text or 20 nesting levels before JSON parsing;
- removes control, bidirectional, tag and zero-width characters, XML-like openers and the current random boundary
  marker;
- applies one 10,000-node and 20-level traversal budget per model-facing value, along with string, container, history
  and serialized-envelope limits;
- retains at most 500 internally extracted result rows under a separate 20,000-node budget;
- wraps each source in a per-run randomized `UNTRUSTED DATA` envelope outside the system role;
- replaces database and sandbox outputs with bounded values; and
- exposes enterprise tools only when their exact `<target>___<tool>` name is in the operator-reviewed read-only
  allowlist.

These controls reduce prompt-injection opportunities but do not guarantee model obedience. Authorization, identity,
SQL compilation, tool admission and mutations therefore remain code-enforced outside the model.

## Browser rendering and framing

CSP limits scripts and connections to self, disallows objects, base URLs and forms, and takes `frame-ancestors` from a
configuration parser that accepts only unique exact HTTPS origins without wildcard, credentials, path, query or
fragment. The AWS China example uses `https://cn-north-1.quicksight.amazonaws.cn`.

First-party UI uses DOM APIs and text nodes. Markdown passes through one DOMPurify boundary with images, iframes,
styles, classes, `div` and `span` excluded. Links retain only HTTP(S) destinations and receive
`target="_blank" rel="noopener noreferrer"`. Tampered local history goes through the same rendering boundary.

## IAM, dependency and logging controls

DynamoDB permissions use non-vacuous `dynamodb:LeadingKeys` conditions. Runtime updates are limited to exactly
32-character job IDs. Web, analysis and publisher access is split by action and namespaces such as
`browser-session#`, `revoked#`, `pending#`, `examples#` and `dashboard#`. The data Lambda can read only provenance
records plus its dedicated literal data-source secret prefix; configuration prevents that prefix from covering this
stack's session, tool, log or model secrets.

Each deployable Python bundle has a direct `requirements/*.in` and a complete committed transitive
`requirements/*.txt` lock. `qsca build` requires Python 3.10 or newer for Python 3.12 artifacts, installs with
`--require-hashes --no-deps`, and derives dependency stamps from lock contents. RDS CA downloads also require pinned
SHA-256 values.

A dedicated generated log secret keys HMAC-SHA256 user pseudonyms. Without the deployment secret, tests/local
processes use a process-random key, so references cannot be correlated across processes. Runtime catch-all logs record
exception class and correlation metadata, not raw exception messages. User-visible job and sandbox failures are generic
and contain only an exception class and correlation/job ID. Smoke-test model-controlled terminal output is JSON
escaped.

## Residual risks and operator decisions

- **Prompt injection remains possible at the model layer.** Envelopes, scrubbing and code-enforced authority reduce
  impact but cannot guarantee that a chosen model ignores malicious data. Only operator-reviewed read-only enterprise
  tools should be allowlisted.
- The data Lambda does not check browser-session revocation. Cancellation normally stops the agent within a heartbeat,
  but an already issued data-tool token remains cryptographically valid until its job lifetime expires.
- `sessjobs#<jti>` uses read-modify-write. Concurrent submits can lose one remembered job ID, and logout cancellation
  is sequential and may exceed the web Lambda timeout. Revocation is written before cancellation.
- An expired browser session cannot initiate logout; an already running job can retain its tool token until expiry.
- The shared HMAC tool key means a compromised web, analysis or data Lambda can mint tool tokens. This sample has no
  key-rotation workflow.
- QuickSight permission and dashboard-list caches delay some access revocations for their documented cache periods.
- `datasourceSecretPrefix` is prevented from covering this stack's protected secrets, but an overly broad prefix can
  still cover unrelated same-account/region secrets. Use a dedicated prefix.
- Extra VPC security groups have additive rules and can defeat the stack-owned egress restriction. Operators must
  inspect them before deployment.
- The page CSP permits inline style declarations for ECharts tooltips.
- Model questions, history, authorized metadata and query results leave AWS China when the configured model endpoint is
  outside the partition. Amazon Bedrock is unavailable in AWS China; the operator must make the data-residency decision.
- This sample does not configure model content filtering or Guardrails. Apply required controls at the chosen endpoint
  or gateway.
