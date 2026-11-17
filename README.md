# QuickSight Chat Assistant

[English](#english) | [中文](#中文)

---

<a id="english"></a>

A chat panel for **any Amazon QuickSight analysis or dashboard**. Users stay in QuickSight and ask questions in natural
language; the assistant queries the data behind the analysis using the current control values, calculates, draws
charts, tells the user which control values to pick, and edits the analysis conversationally (with a preview the user
must approve, and undo). Built on Amazon Bedrock **AgentCore Runtime, Gateway and Code Interpreter** with
**Strands Agents**; the model is any **OpenAI-compatible endpoint** you provide (e.g. Amazon Bedrock, or a gateway
such as LiteLLM), switchable at any time without redeploying. Verified in AWS China (Beijing,
cn-north-1).


> **Disclaimer / non-production notice.** This is sample code published for demonstration and
> educational purposes only. It is **not intended for production use** and is provided **"as is"**
> without warranty of any kind. Review, test, and harden it for your own security, compliance, and
> operational requirements before deploying it in any environment. You are responsible for the AWS
> costs and for the data the assistant can access through the QuickSight analyses and datasets you
> attach it to.

## Features

| Capability | How it works |
|---|---|
| Ask about the data | Reads the analysis structure (sheets, visuals, parameters, parameter-driven filters, datasets, columns) and runs read-only aggregate queries on the datasets with the current control values |
| Charts in the chat | Answers render as Markdown (headings, lists, tables) and include ECharts line/bar charts; every number in a chart is read from tool results by code, never typed by the model |
| Calculations | `analyze_result` runs pandas on query results in an AgentCore Code Interpreter with **no network** (period-over-period, share, rank, moving average, correlation, outliers, joins) |
| Control guidance | Lists the values to pick in the dashboard controls (QuickSight does not let an embedded iframe change controls) |
| Conversational analysis editing | Change chart type (line / bar / table), title, measures and aggregation, category and date grain, color split, sort; add or delete visuals. Every edit is a **preview** first; only the user's **Apply** button changes the analysis; **undo** restores the saved definition |
| Enterprise tools | Optional MCP servers (e.g. DataHub, Metabase via MCPHub) registered on the gateway |
| Long and cancellable | Answers run as background jobs (HealthyBusy, up to the session lifetime); cancel stops within seconds |
| Access control | Identity Center sign-in (the chat shows the user's name from the Identity Center directory); users only see analyses / dashboards they can view in QuickSight and only edit analyses they can edit there |
| Example questions | A collapsed bar under the input box, one tab per group: the deployment default, or the analysis' own set kept by its editors in the chat |
| Self-service setup | Anyone who can edit an analysis adds the chat by pasting `ChatUrl` into a custom visual and binding it in the chat |
| Publish to dashboards | After **Apply**, **发布到仪表盘** publishes the analysis; dashboard chats (console or chat publish) offer no edits |

## Architecture

```
QuickSight analysis / dashboard
  └ Custom visual content (iframe): chat page
       │ HTTPS + opaque HttpOnly session cookie (after IAM Identity Center SAML sign-in)
       ▼
API Gateway HTTP API ─▶ Web Lambda ───────────────────────────▶ DynamoDB (jobs, sign-in state, pending edits)
                         │ │                                           ▲ heartbeats / result
                         │ └─ sign-in: Identity Center identity store (read the user's name by email)
                         │ submit job + tool token (returns at once)   │
                         ▼                                             │
                  AgentCore Runtime: Strands agent (one microVM per session)
                         │  ├─ local tools: plot_result, preview_analysis_change, suggest_controls
                         │  └─ analyze_result ─▶ AgentCore Code Interpreter (SANDBOX: no network, only result rows)
                         │ MCP + SigV4
                         ▼
                  AgentCore Gateway
                    ├ analysis tools Lambda ─▶ QuickSight API (read / edit analysis, permissions), S3 (backups)
                    ├ data tools Lambda (VPC) ─▶ databases behind the datasets (parameterized read-only SQL)
                    └ enterprise MCP servers (optional)
  (also in the stack: dashboard-publisher Lambda + EventBridge rule for 发布到仪表盘; session-key and tool-key secrets in Secrets Manager)
Model: your OpenAI-compatible endpoint, e.g. Bedrock bedrock-runtime /openai/v1 (URL and key in Secrets Manager)
```

Everything is one CDK stack in the QuickSight region. The `Apply`, publish and undo confirmation buttons call the web
Lambda, which invokes the analysis tools Lambda directly as that user with a 5-minute tool token. The model can create
an edit preview, but only an explicit, CSRF-protected button request can apply, publish or undo a change.

## Repository layout

| Path | Contents |
|---|---|
| `agent/` | Runtime agent (Strands): jobs, heartbeats, cancel, charts (`charts.py`), sandbox (`sandbox.py`), prompt |
| `web/` | Web Lambda: chat page (`index.html` + `render.js` + `app.js`, no inline script), SAML login, job API, apply endpoint; `web/vendor/` ECharts 6.1.0, marked 18.1.1, DOMPurify 3.4.17 (pinned copies with npm integrity, see `web/vendor/README.md`; no CDN) |
| `tools/analysis/` | Gateway tools: describe the analysis, preview / apply / undo edits; button-only tools (publish, bind, example questions); `publisher.py` marks the chat in published dashboards |
| `tools/data/` | Gateway tools: describe datasets, structured aggregate queries, distinct values |
| `tools/common/` | Shared: signed tokens (`tokens.py`, also used by the web Lambda and `qsca`), caller verification and QuickSight permission checks, definition parsing, edit operations |
| `infra/` | CDK (TypeScript) stack |
| `qsca` | CLI: build, deploy, configure, attach, publish, check, smoke test |
| `tests/` | Unit tests (`tests/unit`), chat page rendering tests (`tests/js`, jsdom) and the deployed end-to-end suite (`tests/e2e.py`) |

## Deploy

### Prerequisites

| Item | Requirement |
|---|---|
| AWS | Account and the QuickSight region (cn-north-1 verified); admin-level deploy permissions |
| QuickSight | Enterprise edition, users sign in through IAM Identity Center; QuickSight user emails match Identity Center emails, one active QuickSight user per email |
| Model | OpenAI-compatible Chat Completions endpoint with tool calling and streaming, reachable from the Runtime over public HTTPS (Amazon Bedrock, OpenAI-compatible providers, or a gateway such as LiteLLM for other APIs) |
| Machine | macOS or Linux, Node.js 20+, Python 3.10+ with `pip`, `boto3` and `PyJWT` (`PyJWT` only for `qsca smoke` and the tests; deployment bundles target Python 3.12), access to npm and PyPI (mirrors work: `npm config set registry …`, `PIP_INDEX_URL`). No Docker needed |
| CDK bootstrap | Once per account/region: `cd infra && npm ci && npx cdk bootstrap aws://<account>/<region>` |

### 1. Configure

```bash
cp config.example.json config.json
```

| Key | Meaning |
|---|---|
| `prefix` | Resource name prefix, 2-12 characters, lowercase letters/digits, starting with a letter (e.g. `qsca`) |
| `region` | QuickSight region |
| `quickSight.namespace` / `allowedAnalysisIds` | QuickSight namespace (usually `default`); analyses the chat may be attached to (`["*"]` = any, still per-user permissions) |
| `identityCenter.samlEntityId` | SAML audience you choose, e.g. `urn:quicksight-chat-assistant:chat` |
| `identityCenter.identityStoreId` / `region` | Optional: where to look up users' display names. Default: the Identity Center instance in the deployment region |
| `dataAccess.vpc` | VPC for the data tools Lambda when databases are private: `{ vpcId, subnetIds, securityGroupIds, createInterfaceEndpoints, databaseEgress, endpointHttpsCidrs?, dynamodbEndpointUrl?, rdsEndpointUrl? }` (`null` for public databases). Reusing the QuickSight VPC connection's VPC/subnets is usually easiest |
| `dataAccess.vpc.databaseEgress` | Required explicit database destinations for the owned Lambda security group, for example `[{"cidr":"10.0.0.0/16","port":5432}]`; add each PostgreSQL/MySQL CIDR and port actually used |
| `dataAccess.vpc.securityGroupIds` | Optional extra security groups for inbound database allowlisting. Their outbound rules are additive and **must not** widen egress beyond configured endpoint HTTPS and database destinations |
| `dataAccess.vpc.createInterfaceEndpoints` | `true` creates QuickSight, Secrets Manager, DynamoDB and RDS API interface endpoints and allows TCP 443 only to their security group |
| `dataAccess.vpc.endpointHttpsCidrs` | Required when `createInterfaceEndpoints` is `false`: private CIDRs of the existing QuickSight, Secrets Manager, DynamoDB and RDS API endpoints, allowed on TCP 443 |
| `dataAccess.vpc.dynamodbEndpointUrl` / `rdsEndpointUrl` | Required when `createInterfaceEndpoints` is `false`: exact HTTPS service origins for the existing DynamoDB and RDS API interface endpoints. In China regions, use the endpoint-specific DynamoDB URL and the endpoint-specific RDS URL or documented `rds-api` URL |
| `dataAccess.datasourceSecretPrefix` | Prefix of database credential secrets: replace the example's `REPLACE_ME/datasource/` with your own, e.g. `quicksight-chat-assistant/datasource/`; a literal prefix used only for these secrets, which must not cover `<prefix>/session-key`, `tool-key`, `log-key` or `model-config` |
| `dataAccess.extraSecretArns` | Ignored (accepted so older config files still load): the data tools read only their own `<datasourceSecretPrefix><DataSourceId>` secrets, never QuickSight's |
| `mcpTargets` | Enterprise MCP servers (see below); `[]` for none. Targets are registered but unavailable to the model unless individual tools are allowlisted |
| `enterpriseReadOnlyTools` | Exact reviewed read-only tool names in `<target>___<tool>` form. Defaults to `[]`; only listed tools are exposed to the model |
| `runtime.idleSeconds` / `maxLifetimeSeconds` | Session idle timeout (300) and max lifetime (28800 = 8 h, also the longest job and how long a job's tool token lasts) |
| `sessionSeconds` | Optional: how long a browser sign-in lasts, 300-43200 seconds (default 3600 = 1 h) |
| `api.rateLimit` / `burstLimit` | HTTP API throttling |
| `frameAncestors` | Origins allowed to embed the chat page (the QuickSight console domains of your region) |
| `examples` | Optional example questions for the chat page, replacing the built-in generic ones: `[{"group": "…", "tip": "…", "questions": ["…"]}]`, at most 2500 bytes as JSON. Use it to tailor a demo to your data. Groups with `"edit": true` (or named 修改…) are hidden in dashboards |

### 2. Deploy

```bash
./qsca --profile <aws-profile> deploy        # builds Linux arm64 packages into build/, then cdk deploy
./qsca --profile <aws-profile> outputs       # ChatUrl, AcsUrl, SamlEntityId, ModelSecretName, IdpMetadataParameter, ...
```

### 3. IAM Identity Center application (console, once)

Custom SAML applications cannot be created by API.

1. IAM Identity Center → **Applications** → **Add application** → **I have an application I want to set up** → **SAML 2.0**.
2. Download the **IAM Identity Center metadata** file.
3. Application ACS URL = output `AcsUrl`; application SAML audience = output `SamlEntityId`.
4. **Actions → Edit attribute mappings**: `Subject` → `${user:email}`, format `emailAddress`. The chat page shows the
   user's name: it is read at sign-in from the identity store by email (CJK names family name first, e.g. 张伟).
   Optional SAML attributes `familyName` → `${user:familyName}` and `givenName` → `${user:givenName}` take
   precedence. If Identity Center lives in another account or region, set `identityCenter.identityStoreId` /
   `region`; when the lookup is not possible the email is shown.
5. **Assign users and groups** who may use the assistant.
6. Upload the metadata (takes effect within 5 minutes, no redeploy):

```bash
./qsca --profile <p> idp-metadata ~/Downloads/<metadata>.xml
```

### 4. Model

In Secrets Manager, edit `<prefix>/model-config` (output `ModelSecretName`) as plain text:

```json
{"base_url": "https://your-endpoint/v1", "model": "model-name", "api_key": "your-key", "temperature": 0.2, "timeout": 120}
```

Takes effect within 60 seconds; switching models is just editing this secret (previous versions stay in Secrets
Manager for rollback). Or run `./qsca --profile <p> model [--base-url … --model … --params '{…}' --timeout 180]`,
which prompts for the key without echoing it. Leave out `temperature` for models that reject it.
Optional `max_retries` (default 4) retries model calls that fail with 429, 5xx or a connection error; an error
sent inside an already-open response stream is retried by the agent (up to 3 times).
Optional `params` adds fields to every Chat Completions request (for example `{"reasoning_effort": "medium"}`).
Questions and query results are sent to this endpoint: make sure it meets your data compliance rules and uses HTTPS.

Amazon Bedrock (Chat Completions on the `bedrock-runtime` endpoint, Bedrock API key), for example Kimi K3:

```json
{"base_url": "https://bedrock-runtime.us-east-1.amazonaws.com/openai/v1", "model": "us.moonshotai.kimi-k3",
 "api_key": "<Bedrock API key>", "timeout": 180,
 "params": {"reasoning_effort": "medium", "max_tokens": 8192}}
```

Bedrock is not offered in the AWS China regions, so from China this calls a global region across the border; check
that this is acceptable for the data. Notes from testing Kimi K3 (October 2026):

- It reasons at `max` effort by default, which is slow for a chat; use `medium` (`low` hung on edit requests).
- `us.moonshotai.kimi-k3` answered 2-5x faster than `global.moonshotai.kimi-k3`.
- About 1 in 6 answers degenerated into garbled text regardless of effort or temperature, ending only at
  `max_tokens` (1-2 minutes, then a clear error). Keep `max_tokens` set. Occasional HTTP 500s, also inside an open
  stream, are retried automatically.
- Long-term Bedrock API keys expire (a `401 Authentication failed` from the model means a new key is needed).

After switching models, run `tests/e2e.py`: how well a model fills in tool arguments decides both speed and accuracy.

### 5. Database credentials (built-in data queries)

QuickSight does not reveal stored database passwords, and the assistant never uses the secret of the QuickSight data
source itself. For each QuickSight **data source** the analyses use, create a **dedicated database user that can only
SELECT** the tables behind the datasets, and store it in the same region (required; there is no fallback). The helper
reads the current QuickSight data source (and RDS endpoint, where applicable), displays its exact ARN, engine, host,
port and database, requires operator approval, and stores that target with `tls_required: true` beside the credential:

- name `<datasourceSecretPrefix><DataSourceId>`, value `{"username":"…","password":"…","target":{…}}`
- `./qsca --profile <p> datasource-secret <DataSourceId>` approves and creates it; `./qsca check --analysis <id>`
  verifies every saved target against current QuickSight/RDS metadata. Use `--yes` only after reviewing the displayed
  target in automation.

```sql
-- PostgreSQL / Aurora PostgreSQL
CREATE ROLE qsca_reader LOGIN PASSWORD '<password>';
GRANT CONNECT ON DATABASE <db> TO qsca_reader;
GRANT USAGE ON SCHEMA <schema> TO qsca_reader;
GRANT SELECT ON <schema>.<table> TO qsca_reader;
-- MySQL / Aurora MySQL / MariaDB
CREATE USER 'qsca_reader'@'%' IDENTIFIED BY '<password>';
GRANT SELECT ON <db>.<table> TO 'qsca_reader'@'%';
```

Built-in queries support datasets with one **relational table** (`RelationalTable`); custom SQL datasets are refused.
Dataset and tag RLS must both be explicitly `DISABLED`. Caller CLS is applied after shared metadata-cache reads.
Only columns present in visual field wells or reachable controls of the exact authorized analysis/dashboard definition
can be described or selected. Fixed-filter dependencies remain internal only when CLS permits them for that caller;
a mandatory filter on a CLS-denied column rejects the direct query. Enabled whole-analysis category, time and numeric
filters are ANDed into every query. Their parameter values come from complete declaration defaults; URL values may
override them only for viewer-reachable controls and only after type, single/multi-value and static-choice validation.
A partial-sheet/visual, cross-dataset, OR, unsupported parameter, or unsupported active filter causes the direct query
to fail closed.

The data Lambda always verifies the database certificate and hostname. `DisableSsl`, a changed target pin, a MySQL
server without pre-authentication TLS capability, or a connected session without TLS is refused before query data is
sent. Configure `databaseEgress` for those exact database routes. The stack-owned security group has no default
egress; it allows only configured database CIDR/ports and HTTPS to QuickSight, Secrets Manager, DynamoDB and RDS API
interface endpoints. With `createInterfaceEndpoints: true`, the stack creates all four and configures the data Lambda
to use the endpoint-specific DynamoDB and RDS API URLs. With `false`, supply all endpoint CIDRs plus
`dynamodbEndpointUrl` and `rdsEndpointUrl`. Any group added
through `securityGroupIds` has additive rules, so audit it and do not attach one with NAT, internet, or broader VPC
egress. Allow the owned data Lambda group inbound at the database. Cross-region VPC peering works when its precise
CIDR and port are listed.

### 6. Attach to an analysis

Self-service, no command line: in the analysis editor add a **Custom visual content** whose URL is the bare
`ChatUrl` (output, e.g. `https://<api>.execute-api.<region>.amazonaws.com.cn/`), sign in inside it, and pick the
analysis in the list it shows (the one just edited comes first) and press it to bind. That fills in the analysis id
and every parameter, the same URL `attach` builds; refresh the editor. Binding needs edit permission on the
analysis. When parameters are added or removed later, the chat offers **更新绑定**. Or from the command line:

```bash
./qsca --profile <p> attach <analysis-id>            # print the embed URL only
./qsca --profile <p> attach <analysis-id> --apply    # add the chat visual (backup saved under build/)
```

**After Save As or any API copy**, run `attach <new-analysis-id> --apply` on the copy. QuickSight copies a custom
visual's literal `ContentUrl`; it cannot infer that the `analysis=...` query parameter must change. `check --analysis`
and the e2e auth stage fail when a copied visual still points to its source analysis.

The URL carries every analysis parameter (`?analysis=<id>&p.<name>=<<$name>>…`) so the chat knows the current control
values. Options: `--sheet <id>`, `--replace <visual_id>` (take an existing visual's place). Re-run after adding or
removing parameters, then publish the dashboard with

```bash
./qsca --profile <p> publish <analysis-id> <dashboard-id> [--name "…"]   # creates or updates, then publishes
```

or simply **Publish** in the QuickSight console. The browser does not tell the chat which QuickSight page it is on,
and a console publish copies the analysis' chat URL unchanged, so after every dashboard publish (console or API) an
EventBridge rule runs the `<prefix>-dashboard-publisher` Lambda: it adds `where=dashboard` to this solution's chat URL
in the new version and publishes that (about 20 seconds; refresh the dashboard afterwards). The chat in a dashboard
then offers no edits (edits change the analysis, never a published dashboard) and says where to make them. A
validated publish also writes a version-bound `dashboard#…` provenance record to the application table. Dashboard
source IDs and ARNs are normalized to the same exact same-partition/account/region ARN and must agree when both the
event and dashboard version provide them; the publisher records the final marked version. Dashboard tags remain
informational and never grant access. Dashboard-only viewers are authorized against that exact published dashboard
definition; QuickSight's exact same-account/region `SourceEntityArn` is also accepted. `qsca publish` does the same in
one step. Optional: a parameter `pViewer` whose dynamic default is the
viewer's email lets the chat detect a QuickSight user switch in the same browser (not used for authorization).

### 7. Check

```bash
./qsca --profile <p> check --analysis <analysis-id>                 # model, Identity Center, chat visual, credentials
./qsca --profile <p> smoke --analysis <analysis-id> --email <user>  # one question end to end (admin: reads the signing key)
python3 tests/e2e.py --profile <p> --analysis <id> --editor <email> [--other-editor <email>] \
  [--visual <line/bar visual id>] [--dataset <dataset id> --control-column <column>] \
  [--dataset-identifier <identifier> --category-column <column> --measure-column <numeric column>]
```

### Enterprise MCP servers (optional)

```json
{
  "mcpTargets": [
  {"name": "datahub", "endpoint": "https://mcphub.example.com/datahub/mcp",
   "auth": {"type": "oauth", "providerArn": "arn:aws-cn:bedrock-agentcore:cn-north-1:<acct>:token-vault/default/oauth2credentialprovider/datahub", "scopes": ["read"]}},
  {"name": "metabase", "endpoint": "https://mcphub.example.com/metabase/mcp",
   "auth": {"type": "apiKey", "providerArn": "arn:aws-cn:...:apikeycredentialprovider/metabase", "parameterName": "X-API-Key"}}
  ],
  "enterpriseReadOnlyTools": ["datahub___search", "metabase___list_questions"]
}
```

Registering a target does not expose any of its tools. Review each tool as read-only and list its exact Gateway name in
`enterpriseReadOnlyTools`; all other enterprise tools stay unavailable to the model. `auth.type`: `none`, `oauth` / `apiKey` (create the AgentCore Identity credential provider first), or `iam`
(`service: "bedrock-agentcore"`, `runtimeArn`, optional `region`, for MCP servers hosted on AgentCore Runtime). The
endpoint must be public HTTPS (in China regions the gateway has no VPC egress) and support MCP protocol `2025-03-26`.
These servers never receive the user's identity: expose read-only tools only.

### Update, roll back, uninstall

- Update: pull the new code, `./qsca deploy`. The model secret, Identity Center metadata and credentials are kept.
- Roll back: deploy the previous version of the code.
- Uninstall: `cd infra && AWS_PROFILE=<p> npx cdk destroy --context config=../config.json`. Kept on purpose: the S3
  backup bucket and its access-log bucket (logs expire after 365 days), SSM parameter `/<prefix>/idp-metadata`, data source secrets, the chat visual in analyses, the
  Identity Center application.

Migrating from a version before the security hardening (see [docs/security-threat-model.md](docs/security-threat-model.md)):

- The stack creates a second secret, `<prefix>/tool-key`; the tool Lambdas can no longer read `<prefix>/session-key`.
  Deploy when no answer is running (tokens issued before the update stop working; users just ask again).
- Database credentials come only from `<datasourceSecretPrefix><DataSourceId>` (`./qsca datasource-secret`) with a
  SELECT-only user; the fallback to the QuickSight data source's own secret and `extraSecretArns` are gone.
  `datasourceSecretPrefix` must be a literal prefix (no `*` or `?`) that does not cover `<prefix>/session-key`,
  `<prefix>/tool-key`, `<prefix>/log-key` or `<prefix>/model-config` (deploy refuses it otherwise), and the secrets must be in the
  stack's region.
- Database credential records now include an operator-approved QuickSight/RDS target and mandatory TLS pin. Re-run
  `./qsca datasource-secret` for every data source after deploying; old username/password-only records fail closed.
- Built-in queries refuse either RLS form unless explicitly disabled, apply caller CLS, expose only visual/control
  columns from the authorized analysis or dashboard definition, and enforce reproducible whole-analysis filters.
- Browser authentication now uses a server-side opaque session. After SAML validation, the popup sends only a
  short-lived one-time exchange code to the page; `/auth/exchange` sets the `Secure; HttpOnly; SameSite=None;
  Partitioned` `__Host-qsca-session` cookie in the embedding site's partition. JavaScript never receives the session
  ID. The page reads identity and a separate CSRF token from `/me`; every authenticated POST must present that token.
  Existing browser bearer sessions stop working after deployment, so users sign in again. **退出** deletes the opaque
  session, clears both cookie forms, revokes derived tool tokens and cancels that sign-in's running answers.

## Use

### Add the chat to a new analysis (no admin needed)

Anyone who can edit an analysis can add the assistant to it in the QuickSight editor:

1. **Add a visual → Custom visual content** (自定义可视内容), place and size it (for example a column on the right).
2. Set its URL to the chat address your administrator shares: the stack output `ChatUrl` exactly as it is, e.g.
   `https://<api-id>.execute-api.cn-north-1.amazonaws.com.cn/`, with nothing after the slash.
3. In the new visual, click **使用 Identity Center 登录**. The chat says it is not bound yet and lists the analyses you
   can edit, most recently changed first (the one you are editing is normally at the top).
4. Click this analysis. The chat fills in the analysis id and all of its parameters (so it sees the current control
   values) and saves the analysis.
5. **Refresh the browser page.** The chat now works in this analysis. Publish the dashboard as usual (console
   **Publish**, or **发布到仪表盘** in the chat); its chat knows it is in a dashboard.

Notes: you need edit permission on the analysis; if the administrator limited `quickSight.allowedAnalysisIds`, the
analysis must be on that list. When you later add or remove parameters, the chat shows **更新绑定**: click it and
refresh. Administrators can still do the same from the command line with `./qsca attach <analysis-id> --apply`.

### Customize the example questions

The **示例问题** bar under the input box shows the deployment default until an analysis has its own set: one
question that fits any analysis, or the groups in `examples` of `config.json` if the administrator set them. Editors of the analysis maintain that set in the analysis' chat; viewers of the analysis and
of the dashboards published from it see it (groups whose name contains 修改 are hidden in dashboards). A dashboard is
for using what was published: its chat has no **管理** or **☆ 加入示例**.

- **☆ 加入示例** under any question you asked adds it to the group 常用问题 (the first time, the default examples
  shown at that moment are kept next to it).
- **管理** next to **示例问题** opens an editor: one box per group with a name, an optional tip and one question per
  line; add or delete groups, **保存**, or **恢复默认** to drop the analysis' set (saving with every group
  deleted does the same).
- To start from suggestions, ask the assistant, e.g. *Suggest some example questions for this analysis*; it lists
  questions based on the real visuals, fields and parameters. Paste the ones you want into **管理** and save.

Limits: 8 groups, 20 questions per group, 200 characters per question. Changes apply at once, no redeploy.

### Ask and edit

1. Open an analysis or dashboard with the assistant, click **Sign in with Identity Center** (usually no password when
   already signed in to QuickSight). A sign-in lasts 1 hour (`sessionSeconds`); when it expires, sign in again and the
   conversation continues, including an answer that was still running. **退出** signs out at once. Example questions sit in the collapsed **示例问题** bar
   under the input box, one tab per group; clicking one asks it.
2. Ask, for example:
   - *Which visuals does this analysis have and what do they show?*
   - *Under the current filters, how did the average price trend last month? Draw it.*
   - *Compute month-over-month change of the main metric and rank the stations.* (pandas in the sandbox)
   - *Only show station X on the dashboard.* (lists the control values to pick)
3. Edit the analysis (users with edit permission, in the analysis editor):
   - *Change "Price trend" to a bar chart* · *Show it by month* · *Use the sum of energy instead* · *Split by station*
   - *Sort descending by value* · *Rename it to …* · *Add a table of average price by station* · *Delete that chart*
   - Each request shows a **preview** (chart or table drawn with the edited visual's data) with **Apply** / **Discard**.
     After applying, **refresh the page** (the editor does not refresh by itself). Sending **undo** or **force undo**
     creates a confirmation; the change is restored only when you press the displayed button. After **Apply**,
     **发布到仪表盘** publishes the analysis only when you press its confirmation button. Sending the same words also
     creates that confirmation and never publishes directly. The button stays after a page refresh. Edits change the
     analysis only; republish the dashboard to update it. In a dashboard the chat offers no edits.
4. **Cancel** stops a running answer; a page refresh (e.g. after picking a control value) resumes a running answer.
   The browser keeps 8 hours of conversation per user and analysis.

## Security

| Topic | Mechanism |
|---|---|
| Sign-in | Only users assigned to the Identity Center app; SAML assertions checked for signature (against every signing certificate in the app metadata, so a certificate rotation keeps working), issuer, audience, ACS, request ID, validity and replay; assertions without an ID are refused |
| Session | The browser session is a random opaque ID stored only in `Secure; HttpOnly` cookies; claims and a separate CSRF token live in DynamoDB. After SAML, the popup returns a short-lived one-time exchange code, and `/auth/exchange` sets the `SameSite=None; Partitioned; Path=/` `__Host-qsca-session` cookie in the QuickSight site's partition without exposing the session ID to JavaScript. `/me` returns identity and the CSRF token, and every authenticated POST requires it. The session lasts 1 hour by default (`sessionSeconds`). The signed HS256 session JWT path remains only for the administrator `qsca smoke` command; **退出** deletes and revokes the browser session, clears both cookie forms and cancels its running answers |
| Chat page | Content-Security-Policy: scripts only from the page's own origin (no inline script, content-hashed file names), requests only to its API, no plugins or form posts. `frameAncestors` accepts only unique exact HTTPS origins, without wildcards, paths, credentials, query strings or fragments. Styles allow inline declarations for ECharts tooltips. The page builds its UI with DOM nodes (text, never HTML strings); Markdown goes through one DOMPurify boundary, without images, iframes, styles, classes, `div` or `span` |
| Who sees data | Users need `DescribeAnalysis`, or `DescribeDashboard` on a dashboard with exact QuickSight source provenance or a version-bound application mapping. Dashboard-only users get that published dashboard definition, never the live analysis draft. Tags do not authorize. The signed-in email must match exactly one active QuickSight user |
| Dataset rules | Dataset and tag RLS must be explicitly disabled; dataset filters, joins and custom SQL are refused. Caller CLS is applied after cache reads. Only visual/reachable-control columns are discoverable or included in model-visible visual, filter, control and parameter metadata; calculated fields with a CLS-denied dependency are omitted. Mandatory-filter columns remain policy-only only when CLS permits them, and control overrides require declaration type/multiplicity/static-choice validation. Credentials are bound to an approved target and verified TLS session |
| Queries | The model never writes SQL: structured requests, caller-visible columns, fixed aggregates/operators, bound parameters, read-only transaction, 20 s timeout and at most 500 rows. Reproducible whole-analysis filters are always ANDed in; unsupported active scope/filter shapes fail closed |
| Sandbox | Code Interpreter in SANDBOX network mode, no execution role: it only receives result rows the user could already query |
| Who edits | `quicksight:UpdateAnalysis` on that analysis for the user (QuickSight sharing); apply only by the requester, once, within 10 minutes; the previous definition is backed up to S3 before every change |
| Identity to tools | Tools never get the browser's token. The web Lambda issues a tool token signed with the separate `tool-key` per job (bound to the user, the analysis and the sign-in, valid as long as the Runtime session may run) or per button click (5 minutes); the Runtime adds it to this solution's own tool calls in code; the model cannot see or forge it; enterprise MCP servers do not get it. Tool Lambdas refuse session tokens and tokens issued for another analysis; the analysis tools also refuse tokens of a signed-out sign-in |
| Permission changes | QuickSight users, groups and sharing are cached up to 60 s. Dashboard provenance is bound to the exact version; a mismatched or deleted dashboard mapping is removed by the publisher and cannot authorize even while cached. Runtime DynamoDB writes are limited to exactly 32-character job keys; other components are limited by action and key namespace |
| Data flow | Questions and results go to your model endpoint. Analysis metadata, control values, browser history and every tool result are scrubbed, bounded and placed in per-run randomized untrusted-data envelopes; they never enter the system role. Enterprise tools are absent unless their exact reviewed read-only names appear in `enterpriseReadOnlyTools`. CloudWatch logs never contain tokens, passwords, exception messages, SAML attributes or model-output text. User references are HMAC-SHA256 pseudonyms backed by a dedicated generated log key; diagnostics contain only sizes, counts, exception classes and correlation IDs |

SPICE datasets: built-in queries read the current source data, which may be newer than the last SPICE refresh (the
answer says so).

Threat model and residual risks: [docs/security-threat-model.md](docs/security-threat-model.md).
This sample still needs your own security review before you use it as authentication or authorization guidance.

## Responsible AI

The assistant uses a large language model to read questions and write answers. Treat its answers as a starting point
for analysis, not as decisions.

| Topic | How the sample handles it |
|---|---|
| Intended use | Exploring and editing QuickSight analyses the signed-in user can already view or edit. It is not designed to make decisions about people, such as hiring, credit or eligibility |
| Accuracy | The model can misread a question, pick the wrong column or filter, or describe a result incorrectly. Numbers in charts and previews are read from tool results by code and never typed by the model, but the text around them comes from the model: check important answers against the analysis |
| Transparency | Each answer lists the tools it called with their arguments, and shows the model name and the time taken. Answers say when data came directly from the source instead of the SPICE copy |
| Human oversight | The model cannot change an analysis by itself. An edit is shown as a preview with the data it would display, and the analysis changes only when the requester presses **应用到分析**; the previous definition is backed up first, and the last change can be undone |
| Untrusted content | Dataset values, analysis text, URL-bound controls, browser history and enterprise MCP results can contain instructions aimed at the model (prompt injection). The runtime rejects tool responses above a fixed raw UTF-8 byte limit or nesting depth before JSON parsing, then applies global node/depth budgets while scrubbing containers and strings before wrapping each source in a randomized untrusted-data envelope outside the system role. This reduces accidental instruction following but does not prove that a model will ignore every injection. Identity, analysis and parameters are injected in code; permissions and the enterprise-tool allowlist are enforced outside the model |
| Content filtering | The sample does not configure Amazon Bedrock Guardrails or another content filter: the model is any OpenAI-compatible endpoint, and Amazon Bedrock is not offered in the AWS China Regions. If your use requires content filtering, apply it at your model endpoint or gateway (for example Bedrock Guardrails when you use Amazon Bedrock in a supported Region) |
| Bias | Answers reflect the data in the analysis and the behavior of the model you choose. The sample does not test models for bias; evaluate the model you configure with your own users and data |
| Data sent to the model | Questions, the last turns of the conversation, the analysis structure and query results go to your model endpoint (see *Data flow* above); choose an endpoint whose data-use terms meet your requirements |

## Cost

Usage-based: AgentCore Runtime (active session CPU/memory time), Gateway calls, Code Interpreter sessions, Lambda, API
Gateway, DynamoDB on demand, Secrets Manager secrets, **VPC interface endpoints (4 endpoints × subnets, hourly; usually
the largest fixed cost)**, CloudWatch Logs, plus your model. Use the AWS pricing calculator for estimates.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Popup says sign-in is not configured | Upload Identity Center metadata (`./qsca idp-metadata`) |
| `audience mismatch` / `bearer confirmation does not match` | SAML audience or ACS URL differs from the stack outputs |
| Error inside Identity Center after sign-in | User not assigned to the app, or `Subject` not mapped to `${user:email}` |
| "管理员尚未配置模型" | Model secret still has the placeholder |
| Model error `401 Authentication failed` | API key invalid or expired (Bedrock long-term keys expire): store a new one |
| Answer fails after 1-2 minutes with "输出过长被截断" | The model produced runaway output and hit `max_tokens`; retry, or use a more stable model |
| Answers are slow | Runtime log event `answered` has `setup_ms`, `tool_ms` and `model_ms` per call; repeated failed tool calls or slow model calls show there |
| The chat shows the email, not the name | Log `name_lookup_failed` in the web Lambda: user not in the identity store, or Identity Center in another account / region (set `identityCenter.identityStoreId` / `region`) |
| No permission for the analysis | The user cannot view it in QuickSight, or the emails differ |
| "QuickSight 里有 N 个活跃用户使用同一个邮箱" | Several active QuickSight users share the email (e.g. the same person federated through two IAM roles); deactivate or delete the extra users |
| Asked to sign in again after an hour | Expected: a sign-in lasts `sessionSeconds` (default 1 h); the conversation continues after signing in |
| Missing database credentials | Create the data source secret with a SELECT-only user (step 5); QuickSight's own data source secret is not used |
| Built-in query does not support a dataset | RLS, dataset filters, joins, custom SQL, or an unsupported source; add an enterprise MCP server |
| Query timeout / connection error | Database security group or routing does not allow the data tools Lambda |
| Chat says it is not bound to an analysis | Pick the analysis in the chat to bind it (edit permission needed), or run `attach --apply` |
| Applied but nothing changed | Refresh the page; republish the dashboard |
| Visuals show "出现错误" right after a publish or an applied change | The page still uses the replaced version; refresh (sometimes a few times) |

Logs: `/aws/lambda/<prefix>-web`, `/aws/lambda/<prefix>-analysis-tools`, `/aws/lambda/<prefix>-data-tools`, and
`/aws/bedrock-agentcore/runtimes/<prefix>_agent-…-DEFAULT` (one stream per session; `model_streaming` events show a
model call that runs longer than 20 s, `model_retry` the automatic retries).

## Limitations

- Built-in data queries: PostgreSQL, Aurora PostgreSQL, MySQL, Aurora MySQL, MariaDB, RDS (PostgreSQL / MySQL); single
  relational-table datasets, only caller-visible visual and reachable-control columns from the authorized definition. Custom SQL datasets, Athena, Redshift, S3 and
  others: not supported (use an enterprise MCP server).
- Editing covers line, bar and table visuals (aggregated field wells); sheets with section-based layouts cannot get
  new visuals automatically; deleting a visual referenced by filters or actions is refused.
- Previews of visuals using calculated fields work only for parameter-switch fields (`ifelse(${p} = '…', {col}, …)`).
- The chat cannot change controls; the editor does not refresh after an applied change; unsaved manual edits in the
  editor and an applied change can overwrite each other.
- Cancelling while the model is still "thinking" stops at the end of that step (seconds to tens of seconds).
- Browser support: sign-in works in Chrome, Edge and other Chromium-based browsers, which accept the partitioned
  session cookie inside the QuickSight iframe. Safari with "Prevent cross-site tracking" enabled (the default) blocks
  that cookie, so sign-in does not complete; the chat stays signed out (it fails closed). Do not ask users to turn off
  that setting. Support through the Storage Access API is not implemented yet.

## Development

```bash
python3.12 -m venv ~/.venvs/qsca && ~/.venvs/qsca/bin/pip install signxml==5.2.0 lxml==6.1.3 cryptography==50.0.2 PyJWT==2.15.1 boto3==1.43.115
ACCOUNT_ID=0 SESSION_SECRET_ID=x TOOL_SECRET_ID=y QS_REGION=cn-north-1 AWS_DEFAULT_REGION=cn-north-1 ~/.venvs/qsca/bin/python -m unittest discover -s tests/unit
(cd infra && npm ci && npx tsc --noEmit && npm test)   # npm test: config validation
(cd tests/js && npm ci && npm test)   # chat page rendering in jsdom (dev only)
~/.venvs/qsca/bin/python ./qsca build
```

`qsca build` installs each bundle only from its committed `requirements/*.txt` transitive lock with
`--require-hashes --no-deps`; dependency stamps are derived from lock contents. The build also verifies fixed SHA-256
values for both downloaded AWS China RDS CA files before bundling them. Update the matching `requirements/*.in` and
regenerate/review the complete hash lock whenever a dependency changes; do not hand-edit only a direct version.

The unit tests need `boto3` and `PyJWT`; the SAML and sign-out tests in `tests/unit/test_auth.py` also need `signxml`,
`lxml` and `cryptography` at the pinned versions below (skipped otherwise; the venv above has them).

Pinned: strands-agents 1.61.1, bedrock-agentcore 1.24.2, mcp 1.30.0, boto3 1.43.115, signxml 5.2.0, lxml 6.1.3,
cryptography 50.0.2, PyJWT 2.15.1, pg8000 1.31.5 (with scramp 1.4.18), PyMySQL 1.1.2, aws-cdk-lib 2.274.0, ECharts 6.1.0, marked 18.1.1, DOMPurify 3.4.17.

---

<a id="中文"></a>

# QuickSight 分析助手

给 **任意 Amazon QuickSight 分析或仪表盘** 加一个聊天窗口。用户不离开 QuickSight，用自然语言提问；助手按当前控件值查询分析
背后的数据、做计算、画图、提示要在控件里选什么值，还能用对话修改分析（先预览，用户确认后才生效，可撤销）。基于 Amazon Bedrock
**AgentCore Runtime、Gateway、Code Interpreter** 与 **Strands Agents**；模型是你提供的任意 **OpenAI 兼容端点**（如 Amazon
Bedrock，或 LiteLLM 等网关），随时可以切换，无需重新部署。已在 AWS 中国区北京（cn-north-1）验证。


> **免责声明 / 非生产提示。** 本项目为示例代码，仅用于演示与学习目的，**不适用于生产环境**，并按**"原样"**提供，不附带任何形式的担保。在任何环境部署前，请自行评估、测试并按你的安全、合规与运维要求进行加固。
> 你需自行承担相关 AWS 费用，并对助手通过你接入的 QuickSight 分析与数据集所能访问的数据负责。

## 功能

| 能力 | 实现方式 |
|---|---|
| 数据问答 | 读取分析结构（工作表、图表、参数、参数驱动的筛选、数据集、列），按当前控件值对数据集做只读聚合查询 |
| 聊天出图 | 回答按 Markdown 显示（标题、列表、表格），并附带 ECharts 折线图 / 柱状图；图里的每个数字都由代码从工具结果中读取，不由模型编写 |
| 计算 | `analyze_result` 在 **无网络** 的 AgentCore Code Interpreter 中用 pandas 处理查询结果（环比、占比、排名、移动平均、相关性、异常值、合并结果） |
| 控件提示 | 列出要在仪表盘控件里选择的值（QuickSight 不允许嵌入的 iframe 修改控件） |
| 对话式修改分析 | 改图表类型（折线 / 柱状 / 表格）、标题、指标与聚合、分类字段与时间粒度、颜色分组、排序，新增或删除图表。每次修改先给出 **预览**，只有用户点 **应用到分析** 才会修改分析；**撤销** 恢复保存的定义 |
| 企业工具 | 可选：在 Gateway 上注册 MCP 服务器（如经 MCPHub 的 DataHub、Metabase） |
| 长任务与取消 | 回答作为后台任务运行（HealthyBusy，最长到会话生命周期）；取消几秒内生效 |
| 权限 | Identity Center 登录（聊天窗口显示 Identity Center 目录中的用户姓名）；用户只能看到在 QuickSight 里有权查看的分析 / 仪表盘，只能修改在 QuickSight 里有权编辑的分析 |
| 示例问题 | 输入框下方的折叠栏，每组一个标签：部署级默认，或分析编辑者在聊天里维护的分析专属示例 |
| 自助接入 | 有分析编辑权限的人，把 `ChatUrl` 填进自定义可视内容，在聊天里绑定即可加上聊天窗口 |
| 发布到仪表盘 | 点 **应用到分析** 后，**发布到仪表盘** 发布分析；仪表盘里的聊天（控制台发布或聊天发布）不提供修改 |

## 架构

```
QuickSight 分析 / 仪表盘
  └ 自定义可视内容（iframe）：聊天页
       │ HTTPS + 不透明 HttpOnly 会话 Cookie（IAM Identity Center SAML 登录后）
       ▼
API Gateway HTTP API ─▶ Web Lambda ───────────────────────────▶ DynamoDB（任务、登录状态、待确认修改）
                         │ │                                           ▲ 心跳 / 结果
                         │ └─ 登录：Identity Center 用户目录（按邮箱读取用户姓名）
                         │ 提交任务 + 工具令牌（立即返回）             │
                         ▼                                             │
                  AgentCore Runtime：Strands Agent（每个会话一个 microVM）
                         │  ├─ 本地工具：plot_result、preview_analysis_change、suggest_controls
                         │  └─ analyze_result ─▶ AgentCore Code Interpreter（SANDBOX：无网络，只有结果行）
                         │ MCP + SigV4
                         ▼
                  AgentCore Gateway
                    ├ 分析工具 Lambda ─▶ QuickSight API（读取 / 修改分析、权限），S3（备份）
                    ├ 数据工具 Lambda（VPC）─▶ 数据集背后的数据库（参数化的只读 SQL）
                    └ 企业 MCP 服务器（可选）
  （栈里还有：用于“发布到仪表盘”的仪表盘发布 Lambda + EventBridge 规则；Secrets Manager 里的会话密钥和工具密钥）
模型：你的 OpenAI 兼容端点，如 Bedrock bedrock-runtime /openai/v1（地址和 Key 存在 Secrets Manager）
```

所有资源在 QuickSight 所在区域的一个 CDK 栈里。“应用到分析”、发布和撤销确认按钮调用 Web Lambda，由它以该用户身份、携带
5 分钟工具令牌直接调用分析工具 Lambda。模型可以生成修改预览，但应用、发布和撤销都只能由显式、带 CSRF 校验的按钮请求执行。

## 仓库结构

| 路径 | 内容 |
|---|---|
| `agent/` | Runtime 上的 Agent（Strands）：任务、心跳、取消、图表（`charts.py`）、沙箱（`sandbox.py`）、提示词 |
| `web/` | Web Lambda：聊天页（`index.html` + `render.js` + `app.js`，没有内联脚本）、SAML 登录、任务 API、应用接口；`web/vendor/` 下是 ECharts 6.1.0、marked 18.1.1、DOMPurify 3.4.17（固定版本，带 npm 完整性校验，见 `web/vendor/README.md`；不用 CDN） |
| `tools/analysis/` | Gateway 工具：描述分析、预览 / 应用 / 撤销修改；仅由按钮触发的工具（发布、绑定、示例问题）；`publisher.py` 给已发布仪表盘里的聊天打标记 |
| `tools/data/` | Gateway 工具：描述数据集、结构化聚合查询、去重取值 |
| `tools/common/` | 公共代码：签名令牌（`tokens.py`，web Lambda 和 `qsca` 也使用）、调用者校验与 QuickSight 权限检查、定义解析、修改操作 |
| `infra/` | CDK（TypeScript）栈 |
| `qsca` | 命令行：构建、部署、配置、接入、发布、检查、冒烟测试 |
| `tests/` | 单元测试（`tests/unit`）、聊天页渲染测试（`tests/js`，jsdom）和针对已部署环境的端到端测试（`tests/e2e.py`） |

## 部署

### 前提

| 项目 | 要求 |
|---|---|
| AWS | 账号和 QuickSight 所在区域（已验证 cn-north-1）；管理员级部署权限 |
| QuickSight | 企业版，用户通过 IAM Identity Center 登录；QuickSight 用户邮箱与 Identity Center 邮箱一致，且每个邮箱只对应一个活跃的 QuickSight 用户 |
| 模型 | OpenAI 兼容的 Chat Completions 端点，支持工具调用和流式输出，Runtime 能经公网 HTTPS 访问（Amazon Bedrock、各家 OpenAI 兼容接口，或用 LiteLLM 等网关转换其他接口） |
| 部署机器 | macOS 或 Linux，Node.js 20+，Python 3.10+（带 `pip`、`boto3` 和 `PyJWT`；`PyJWT` 只有 `qsca smoke` 和测试需要；部署包目标为 Python 3.12），能访问 npm 和 PyPI（可用镜像：`npm config set registry …`、`PIP_INDEX_URL`）。不需要 Docker |
| CDK 引导 | 每个账号 / 区域一次：`cd infra && npm ci && npx cdk bootstrap aws://<账号>/<区域>` |

### 1. 配置

```bash
cp config.example.json config.json
```

| 配置项 | 含义 |
|---|---|
| `prefix` | 资源名前缀，2-12 个字符，小写字母或数字，且以字母开头（如 `qsca`） |
| `region` | QuickSight 所在区域 |
| `quickSight.namespace` / `allowedAnalysisIds` | QuickSight 命名空间（通常是 `default`）；允许接入聊天的分析（`["*"]` 表示任意分析，仍按用户权限检查） |
| `identityCenter.samlEntityId` | 你自定的 SAML 受众，如 `urn:quicksight-chat-assistant:chat` |
| `identityCenter.identityStoreId` / `region` | 可选：到哪里查用户显示名。默认：部署区域里的 Identity Center 实例 |
| `dataAccess.vpc` | 数据库在 VPC 内时数据工具 Lambda 使用的 VPC：`{ vpcId, subnetIds, securityGroupIds, createInterfaceEndpoints, databaseEgress, endpointHttpsCidrs?, dynamodbEndpointUrl?, rdsEndpointUrl? }`；公网数据库填 `null` |
| `dataAccess.vpc.databaseEgress` | 必填的数据库目标，例如 `[{"cidr":"10.0.0.0/16","port":5432}]`；逐项填写实际 PostgreSQL/MySQL 网段和端口 |
| `dataAccess.vpc.securityGroupIds` | 可选的额外安全组，只用于数据库入站放行；安全组出口会叠加，**不得**放宽到配置之外的端点 HTTPS 或数据库目标 |
| `dataAccess.vpc.createInterfaceEndpoints` | `true` 创建 QuickSight、Secrets Manager、DynamoDB 和 RDS API 接口端点，TCP 443 只放行到其安全组 |
| `dataAccess.vpc.endpointHttpsCidrs` | `createInterfaceEndpoints` 为 `false` 时必填：已有 QuickSight、Secrets Manager、DynamoDB 和 RDS API 接口端点的私网 CIDR，只放行 TCP 443 |
| `dataAccess.vpc.dynamodbEndpointUrl` / `rdsEndpointUrl` | `createInterfaceEndpoints` 为 `false` 时必填：已有 DynamoDB 和 RDS API 接口端点的准确 HTTPS 服务来源；中国区使用 DynamoDB 端点专用 URL，以及 RDS 端点专用 URL 或文档所述的 `rds-api` URL |
| `dataAccess.datasourceSecretPrefix` | 数据库凭证密钥的名称前缀：把示例里的 `REPLACE_ME/datasource/` 换成自己的前缀，例如 `quicksight-chat-assistant/datasource/`；只用于这些密钥的固定前缀，不能覆盖 `<prefix>/session-key`、`tool-key`、`log-key` 或 `model-config` |
| `dataAccess.extraSecretArns` | 已忽略（保留只为兼容旧配置文件）：数据工具只读取自己的 `<datasourceSecretPrefix><DataSourceId>` 密钥，从不使用 QuickSight 的 |
| `mcpTargets` | 企业 MCP 服务器（见下文）；没有就填 `[]`。只注册目标不会把工具开放给模型，必须逐个列入名单 |
| `enterpriseReadOnlyTools` | 已由操作员审核为只读的准确工具名，格式 `<target>___<tool>`。默认为 `[]`，模型只能看到名单内的工具 |
| `runtime.idleSeconds` / `maxLifetimeSeconds` | 会话空闲超时（300）和最长生命周期（28800 = 8 小时，也是任务的最长时长，以及任务的工具令牌的有效期） |
| `sessionSeconds` | 可选：浏览器一次登录的有效期，300-43200 秒（默认 3600 = 1 小时） |
| `api.rateLimit` / `burstLimit` | HTTP API 限流 |
| `frameAncestors` | 允许嵌入聊天页的来源（你所在区域的 QuickSight 控制台域名） |
| `examples` | 可选：替换内置通用示例的部署级示例问题：`[{"group": "…", "tip": "…", "questions": ["…"]}]`，JSON 不超过 2500 字节。可用于针对客户数据做演示。带 `"edit": true`（或名称以“修改”开头）的分组在仪表盘里不显示 |

### 2. 部署

```bash
./qsca --profile <aws-profile> deploy        # 把 Linux arm64 包构建到 build/，再执行 cdk deploy
./qsca --profile <aws-profile> outputs       # ChatUrl、AcsUrl、SamlEntityId、ModelSecretName、IdpMetadataParameter 等
```

### 3. IAM Identity Center 应用（控制台，一次）

自定义 SAML 应用不能用 API 创建。

1. IAM Identity Center → **应用程序** → **添加应用程序** → **我有要设置的应用程序** → **SAML 2.0**。
2. 下载 **IAM Identity Center 元数据** 文件。
3. 应用程序 ACS URL 填输出 `AcsUrl`；应用程序 SAML 受众填输出 `SamlEntityId`。
4. **操作 → 编辑属性映射**：`Subject` → `${user:email}`，格式 `emailAddress`。聊天页显示用户姓名：登录时按邮箱从用户目录读取
   （中日韩姓名姓在前，如 张伟）。可选的 SAML 属性 `familyName` → `${user:familyName}`、`givenName` → `${user:givenName}`
   优先。如果 Identity Center 在其他账号或区域，配置 `identityCenter.identityStoreId` / `region`；查不到时显示邮箱。
5. **分配用户和组**：可以使用助手的人。
6. 上传元数据（5 分钟内生效，无需重新部署）：

```bash
./qsca --profile <p> idp-metadata ~/Downloads/<metadata>.xml
```

### 4. 模型

在 Secrets Manager 中以明文编辑 `<prefix>/model-config`（输出 `ModelSecretName`）：

```json
{"base_url": "https://your-endpoint/v1", "model": "model-name", "api_key": "your-key", "temperature": 0.2, "timeout": 120}
```

60 秒内生效；切换模型只需编辑这个密钥（旧版本保留在 Secrets Manager 中，可以回退）。也可以运行
`./qsca --profile <p> model [--base-url … --model … --params '{…}' --timeout 180]`，它会提示输入 Key，输入不回显。
不接受 `temperature` 的模型请去掉该字段。可选 `max_retries`（默认 4）在模型调用遇到 429、5xx 或连接失败时重试；响应流已经
开始后才返回的错误，由 Agent 重试（最多 3 次）。可选 `params` 给每个 Chat Completions 请求附加字段（如
`{"reasoning_effort": "medium"}`）。提问和查询结果会发送到这个端点：请确认符合数据合规要求，并使用 HTTPS。

Amazon Bedrock（`bedrock-runtime` 端点上的 Chat Completions，Bedrock API Key），以 Kimi K3 为例：

```json
{"base_url": "https://bedrock-runtime.us-east-1.amazonaws.com/openai/v1", "model": "us.moonshotai.kimi-k3",
 "api_key": "<Bedrock API key>", "timeout": 180,
 "params": {"reasoning_effort": "medium", "max_tokens": 8192}}
```

AWS 中国区没有 Bedrock，从中国区调用会跨境访问海外区域；请确认数据可以这样处理。Kimi K3 实测记录（2026 年 10 月）：

- 默认按 `max` 档推理，对聊天来说太慢；请用 `medium`（`low` 在修改类请求上会卡死）。
- `us.moonshotai.kimi-k3` 比 `global.moonshotai.kimi-k3` 快 2-5 倍。
- 无论推理档位和温度，约六分之一的回答会变成乱码，直到 `max_tokens` 才结束（1-2 分钟后给出明确报错）。请保留
  `max_tokens`。偶发的 HTTP 500（包括响应流中途的）会自动重试。
- Bedrock 长期 API Key 会过期（模型返回 `401 Authentication failed` 表示需要换新 Key）。

换模型后请运行 `tests/e2e.py`：模型填写工具参数的能力决定了速度和准确性。

### 5. 数据库凭证（内置数据查询）

QuickSight 不会提供已保存的数据库密码，助手也从不使用 QuickSight 数据源自己的密钥。分析用到的每个 QuickSight **数据源**，
都要创建一个 **专用的、只能 SELECT** 数据集背后那些表的数据库用户，并保存在同一区域（必需，没有其他来源）。命令会读取
当前 QuickSight 数据源（RDS 时还会解析实例端点），显示准确 ARN、引擎、主机、端口和数据库，由操作员确认后把该目标与
`tls_required: true` 和凭证一起保存：

- 名称 `<datasourceSecretPrefix><DataSourceId>`，内容 `{"username":"…","password":"…","target":{…}}`
- `./qsca --profile <p> datasource-secret <DataSourceId>` 确认并创建；`./qsca check --analysis <id>` 会比较当前元数据与保存目标。
  自动化只有在预先核对显示目标后才应使用 `--yes`。

```sql
-- PostgreSQL / Aurora PostgreSQL
CREATE ROLE qsca_reader LOGIN PASSWORD '<password>';
GRANT CONNECT ON DATABASE <db> TO qsca_reader;
GRANT USAGE ON SCHEMA <schema> TO qsca_reader;
GRANT SELECT ON <schema>.<table> TO qsca_reader;
-- MySQL / Aurora MySQL / MariaDB
CREATE USER 'qsca_reader'@'%' IDENTIFIED BY '<password>';
GRANT SELECT ON <db>.<table> TO 'qsca_reader'@'%';
```

内置查询支持只有一个 **关系表**（`RelationalTable`）的数据集；自定义 SQL 数据集会被拒绝。数据集 RLS 和标签 RLS 都必须明确为
`DISABLED`。每次从共享缓存取出元数据后，仍会按调用者应用列级权限。只允许描述或选择当前获授权分析/仪表盘定义中图表字段井和
可达控件出现的列；固定筛选依赖列只在策略内部使用。覆盖整个分析且可复现的分类、时间和数值筛选会 AND 到每次查询；局部工作表/
图表、跨数据集、OR 或其他不支持的活动筛选会让查询拒绝执行。

数据 Lambda 始终验证数据库证书和主机名。`DisableSsl`、目标漂移、MySQL 服务端在认证前不支持 TLS，或已连接会话没有 TLS 都会在
查询前拒绝。用 `databaseEgress` 精确列出数据库路由；栈自建安全组没有默认出口，只放行这些 CIDR/端口和 QuickSight、Secrets
Manager、DynamoDB、RDS API 接口端点的 HTTPS。`createInterfaceEndpoints: true` 时栈会创建这四个端点，并让数据 Lambda 使用
DynamoDB 和 RDS API 的端点专用 URL；为 `false` 时必须提供全部端点 CIDR、`dynamodbEndpointUrl` 和 `rdsEndpointUrl`。通过
`securityGroupIds` 附加的安全组规则会叠加，不能带来 NAT、互联网或更宽的 VPC 出口。数据库安全组
应放行栈自建的数据 Lambda 安全组；跨区域 VPC 对等连接也必须列出准确网段和端口。

### 6. 接入分析

自助方式，不用命令行：在分析编辑界面添加 **自定义可视内容**（Custom visual content），网址填原样的 `ChatUrl`（输出，如
`https://<api>.execute-api.<region>.amazonaws.com.cn/`），在其中登录，从列出的分析里点选它所在的分析（刚编辑过的排在最前）
即可绑定。绑定会补上分析 ID 和全部参数，与 `attach` 生成的地址相同；之后刷新编辑界面。绑定需要该分析的编辑权限。以后增删了
参数，聊天窗口会提示 **更新绑定**。也可以用命令行：

```bash
./qsca --profile <p> attach <analysis-id>            # 只打印嵌入地址
./qsca --profile <p> attach <analysis-id> --apply    # 把聊天可视对象加进分析（备份保存在 build/）
```

**每次“另存为”或通过 API 复制分析后**，都要对副本运行 `attach <新-analysis-id> --apply`。QuickSight 会原样复制
自定义可视对象的 `ContentUrl`，不知道其中的 `analysis=...` 必须改成副本 ID。`check --analysis` 和 e2e 的认证阶段会在
副本仍指向源分析时失败。

地址带上了分析的全部参数（`?analysis=<id>&p.<name>=<<$name>>…`），聊天窗口由此知道当前控件值。选项：`--sheet <id>`、
`--replace <visual_id>`（占用某个已有可视对象的位置）。增删参数后重新运行，然后用下面的命令发布仪表盘

```bash
./qsca --profile <p> publish <analysis-id> <dashboard-id> [--name "…"]   # 创建或更新，然后发布
```

或者直接在 QuickSight 控制台点 **发布**。浏览器不会告诉聊天窗口自己在哪个 QuickSight 页面，控制台发布又会原样复制分析里的
聊天地址，所以每次发布仪表盘后（控制台或 API），EventBridge 规则会运行 `<prefix>-dashboard-publisher` Lambda：在新版本里给
本方案的聊天地址加上 `where=dashboard` 并发布（约 20 秒，之后刷新仪表盘）。仪表盘里的聊天因此不提供修改（修改只作用于分析，
不会改已发布的仪表盘），并提示到哪里修改。经过验证的发布会在应用表写入绑定具体版本的 `dashboard#…` 来源记录；仪表盘标签
只用于运维信息，从不参与授权。只有仪表盘权限的用户只读取该已发布仪表盘定义；同账号、同区域且完全匹配的 QuickSight
`SourceEntityArn` 也可以独立证明来源。`qsca publish` 一步完成同样的事。可选：建一个参数 `pViewer`，动态默认值为当前用户邮箱，
（不用于授权）。

### 7. 检查

```bash
./qsca --profile <p> check --analysis <analysis-id>                 # 模型、Identity Center、聊天可视对象、凭证
./qsca --profile <p> smoke --analysis <analysis-id> --email <user>  # 端到端问一个问题（管理员：会读取签名密钥）
python3 tests/e2e.py --profile <p> --analysis <id> --editor <email> [--other-editor <email>] \
  [--visual <line/bar visual id>] [--dataset <dataset id> --control-column <column>] \
  [--dataset-identifier <identifier> --category-column <column> --measure-column <numeric column>]
```

### 企业 MCP 服务器（可选）

```json
{
  "mcpTargets": [
  {"name": "datahub", "endpoint": "https://mcphub.example.com/datahub/mcp",
   "auth": {"type": "oauth", "providerArn": "arn:aws-cn:bedrock-agentcore:cn-north-1:<acct>:token-vault/default/oauth2credentialprovider/datahub", "scopes": ["read"]}},
  {"name": "metabase", "endpoint": "https://mcphub.example.com/metabase/mcp",
   "auth": {"type": "apiKey", "providerArn": "arn:aws-cn:...:apikeycredentialprovider/metabase", "parameterName": "X-API-Key"}}
  ],
  "enterpriseReadOnlyTools": ["datahub___search", "metabase___list_questions"]
}
```

只注册目标不会开放任何工具。请逐个确认工具为只读，并把准确 Gateway 名称加入 `enterpriseReadOnlyTools`；其余企业工具不会提供给模型。
`auth.type`：`none`、`oauth` / `apiKey`（先创建 AgentCore Identity 凭证提供程序），或 `iam`（`service: "bedrock-agentcore"`、
`runtimeArn`、可选 `region`，用于部署在 AgentCore Runtime 上的 MCP 服务器）。端点必须是公网 HTTPS（中国区的 Gateway 没有
VPC 出口），并支持 MCP 协议 `2025-03-26`。这些服务器收不到用户身份：只开放只读工具。

### 更新、回滚、卸载

- 更新：拉取新代码后 `./qsca deploy`。模型密钥、Identity Center 元数据和凭证会保留。
- 回滚：部署上一个版本的代码。
- 卸载：`cd infra && AWS_PROFILE=<p> npx cdk destroy --context config=../config.json`。有意保留的资源：S3 备份桶及其访问日志桶（日志 365 天后过期）、SSM 参数
  `/<prefix>/idp-metadata`、数据源密钥、分析里的聊天可视对象、Identity Center 应用。

从安全加固之前的版本迁移（见 [docs/security-threat-model.md](docs/security-threat-model.md)）：

- 栈会新建第二个密钥 `<prefix>/tool-key`；工具 Lambda 不再能读取 `<prefix>/session-key`。请在没有回答正在运行时部署（更新前签发的
  令牌会失效，用户重新提问即可）。
- 数据库凭证只来自 `<datasourceSecretPrefix><DataSourceId>`（`./qsca datasource-secret`），并且必须是只能 SELECT 的用户；不再回退到
  QuickSight 数据源自己的密钥，`extraSecretArns` 也不再生效。`datasourceSecretPrefix` 必须是不含 `*` 或 `?` 的固定前缀，并且不能覆盖
  `<prefix>/session-key`、`<prefix>/tool-key`、`<prefix>/log-key` 或 `<prefix>/model-config`（否则部署会拒绝），密钥也必须在栈所在的区域。
- 数据库凭证记录现在包含操作员批准的 QuickSight/RDS 目标和强制 TLS 标记。部署后要为每个数据源重新运行
  `./qsca datasource-secret`；旧的只有用户名/密码的记录会拒绝使用。
- 内置查询只有在两种 RLS 都明确关闭时才执行；按调用者应用列级权限，只提供获授权分析或仪表盘定义里的图表/控件列，并强制执行
  可精确复现的全分析筛选。
- 浏览器认证改为服务端不透明会话。SAML 校验完成后，弹窗只向页面发送一个短期、一次性的交换码；页面调用
  `/auth/exchange`，在 QuickSight 所在的分区中设置 `Secure; HttpOnly; SameSite=None; Partitioned` 的
  `__Host-qsca-session` Cookie，JavaScript 不会拿到会话 ID。页面再从 `/me` 读取身份和单独的 CSRF 令牌，每个已认证 POST
  都必须携带该令牌。部署后旧的浏览器 Bearer 会话会失效，用户需重新登录。**退出** 会删除不透明会话、清除两种 Cookie、
  吊销派生工具令牌并取消这次登录正在运行的回答。

## 使用

### 给新分析加上聊天窗口（不需要管理员）

有分析编辑权限的人，都可以在 QuickSight 编辑界面里自己加上助手：

1. **添加可视对象 → 自定义可视内容**（Custom visual content），摆好位置和大小（比如放在右侧一列）。
2. 网址填管理员提供的聊天地址：栈输出 `ChatUrl` 原样填写，如 `https://<api-id>.execute-api.cn-north-1.amazonaws.com.cn/`，
   斜杠后面不加任何内容。
3. 在新加的可视对象里点 **使用 Identity Center 登录**。聊天窗口提示还没有绑定，并列出你能编辑的分析，最近修改的排在前面
   （正在编辑的这个通常在第一个）。
4. 点选这个分析。聊天窗口会补上分析 ID 和全部参数（这样才能拿到当前控件值），并保存分析。
5. **刷新浏览器页面**，聊天窗口即可在这个分析里使用。照常发布仪表盘（控制台 **发布**，或在聊天里点 **发布到仪表盘**）；
   仪表盘里的聊天知道自己在仪表盘中。

说明：需要该分析的编辑权限；如果管理员限定了 `quickSight.allowedAnalysisIds`，这个分析必须在名单内。以后增删参数时，聊天窗口
会显示 **更新绑定**：点一下再刷新即可。管理员仍可用命令行 `./qsca attach <analysis-id> --apply` 完成同样的事。

### 自定义示例问题

在分析有自己的一套示例之前，输入框下方的 **示例问题** 栏显示部署级默认：一个适用于任何分析的问题，或管理员在 `config.json`
的 `examples` 里配置的分组。分析的编辑者在分析的聊天里维护这一套；分析的查看者、以及由它发布的仪表盘的查看者都能看到（名称含“修改”
的分组在仪表盘里不显示）。仪表盘只用于使用已发布的内容：仪表盘里的聊天没有 **管理** 和 **☆ 加入示例**。

- 自己问过的问题下方有 **☆ 加入示例**，点一下加入“常用问题”分组（第一次加入时，保留当时显示的默认示例）。
- **示例问题** 旁的 **管理** 打开编辑器：每个分组有名称、可选说明、每行一个问题；可以添加或删除分组、**保存**，或点
  **恢复默认** 删除分析自己的那一套（删除所有分组后保存，效果相同）。
- 想先要一些建议，可以问助手，如“给这个分析出一些示例问题”；它会按真实的图表、字段和参数列出问题。把需要的粘贴到 **管理**
  里保存。

限制：8 个分组，每组 20 个问题，每个问题 200 字。修改立即生效，无需重新部署。

### 提问与修改

1. 打开接入了助手的分析或仪表盘，点 **使用 Identity Center 登录**（已登录 QuickSight 时通常无需密码）。一次登录有效 1 小时（`sessionSeconds`）；过期后重新登录，
   对话会接着进行，包括还在进行中的回答。点 **退出** 立即注销。
   示例问题在输入框下方折叠的 **示例问题** 栏里，每组一个标签；点一个即提问。
2. 提问示例：
   - *这个分析有哪些图表，各自展示什么？*
   - *按当前筛选，上个月的平均价格走势如何？画出来。*
   - *计算主要指标的每月环比，并给各场站排名。*（沙箱里用 pandas 计算）
   - *在仪表盘上只看某某场站。*（列出要在控件里选的值）
3. 修改分析（有编辑权限的用户，在分析编辑界面里）：
   - *把“价格走势”改成柱状图* · *改成按月显示* · *改用电量的总和* · *按场站分组*
   - *按数值降序* · *标题改成……* · *新增一个按场站统计平均价格的表格* · *删除这个图表*
   - 每个请求都会显示 **预览**（用修改后的口径画出的图表或表格），并带 **应用到分析** / **不用了**。应用后请 **刷新页面**
     （编辑界面不会自动刷新）。发送 **撤销** 或 **强制撤销** 只会生成确认提示，必须点击其中的按钮才会恢复修改。点
     **发布到仪表盘** 才会发布；发送同样文字也只生成确认提示，绝不会直接发布。刷新页面后按钮仍在。修改只作用于分析；
     要更新仪表盘需重新发布。仪表盘里的聊天不提供修改。
4. **取消** 停止正在进行的回答；页面刷新后（如选择了控件值）会继续获取正在进行的回答。浏览器按用户和分析保存 8 小时内的对话。

## 安全

| 方面 | 机制 |
|---|---|
| 登录 | 只有分配到 Identity Center 应用的用户；SAML 断言校验签名（逐一对照应用元数据里的每张签名证书，证书轮换期间也能登录）、颁发者、受众、ACS、请求 ID、有效期和重放；没有 ID 的断言拒绝 |
| 会话 | 浏览器会话是只存在于 `Secure; HttpOnly` Cookie 中的随机不透明 ID，声明和单独的 CSRF 令牌保存在 DynamoDB。SAML 完成后，弹窗返回短期的一次性交换码，`/auth/exchange` 在 QuickSight 站点的分区中设置 `SameSite=None; Partitioned; Path=/` 的 `__Host-qsca-session` Cookie，不向 JavaScript 暴露会话 ID。`/me` 返回身份和 CSRF 令牌，每个已认证 POST 都必须校验它。默认有效 1 小时（`sessionSeconds`）。HS256 会话 JWT 路径仅为管理员 `qsca smoke` 保留；点 **退出** 会删除并吊销浏览器会话、清除两种 Cookie、取消正在运行的回答 |
| 聊天页 | Content-Security-Policy：脚本只能来自页面自己的来源（没有内联脚本，文件名带内容哈希），请求只能发往它的 API，不允许插件和表单提交。`frameAncestors` 只接受不重复的准确 HTTPS 来源，不允许通配符、路径、凭证、查询或片段。样式允许内联声明（ECharts 提示框需要）。页面用 DOM 节点构建界面（文本，从不拼 HTML 字符串）；Markdown 只经过一个 DOMPurify 净化边界，不允许图片、iframe、样式、class、`div` 和 `span` |
| 谁能看数据 | 用户要么有分析的 `DescribeAnalysis`，要么有具备准确 QuickSight 来源或版本绑定应用映射的仪表盘 `DescribeDashboard`。只有仪表盘权限的用户只得到已发布仪表盘定义，不能读取实时分析草稿；标签不参与授权。登录邮箱必须恰好对应一个活跃 QuickSight 用户 |
| 数据集规则 | 数据集 RLS 和标签 RLS 都必须明确关闭；数据集筛选、联接和自定义 SQL 会拒绝。缓存后按调用者应用列级权限，只暴露图表/可达控件列，强制筛选列只在策略内部使用；凭证绑定到批准目标和经过验证的 TLS 会话 |
| 查询 | 模型从不写 SQL：结构化请求、调用者可见列、固定聚合/运算符、绑定参数、只读事务、20 秒超时、最多 500 行。可复现的全分析筛选总是 AND 进去；不支持的活动作用域或筛选形状会拒绝 |
| 沙箱 | Code Interpreter 为 SANDBOX 网络模式，没有执行角色：只拿到用户本来就能查询的结果行 |
| 谁能修改 | 用户对该分析有 `quicksight:UpdateAnalysis`（QuickSight 共享）；只有发起人能在 10 分钟内应用一次；每次修改前都把原定义备份到 S3 |
| 工具拿到的身份 | 工具永远拿不到浏览器的令牌。web Lambda 用单独的 `tool-key` 为每个任务签发一个工具令牌（绑定用户、分析和这次登录，有效期为 Runtime 会话的最长时长），为每次按钮点击签发 5 分钟的工具令牌；Runtime 在代码里把它附加到本方案自己的工具调用上；模型看不到也伪造不了；企业 MCP 服务器拿不到。工具 Lambda 拒绝会话令牌，也拒绝为其他分析签发的令牌；分析工具还会拒绝已退出登录的令牌 |
| 权限变更 | QuickSight 用户、组和共享设置最多缓存 60 秒。仪表盘来源绑定具体版本；版本不符或已删除的映射由发布器移除，缓存期间也不能授权。Runtime 的 DynamoDB 写入只允许正好 32 字符的任务键，其他组件按操作和键命名空间限制 |
| 数据流向 | 提问和结果发送到你的模型端点。分析元数据、控件值、浏览器历史和每个工具结果都会先移除控制/隐藏字符并限制大小，再放进每次运行随机的不可信数据边界，不进入 system role。企业工具只有准确名称在 `enterpriseReadOnlyTools` 中才会提供给模型。CloudWatch 日志不含令牌、密码、异常消息、SAML 属性或模型输出文本；用户引用是由专用生成日志密钥计算的 HMAC-SHA256 假名，诊断只记录大小、数量、异常类和关联 ID |

SPICE 数据集：内置查询读取的是源数据的当前值，可能比上次 SPICE 刷新更新（回答里会说明）。

威胁模型和残余风险：[docs/security-threat-model.md](docs/security-threat-model.md)。把本示例当作认证或授权的参考之前，
仍需要你自己的安全评审。

## 负责任的 AI

助手用大语言模型理解提问、撰写回答。请把它的回答当作分析的起点，而不是决策。

| 方面 | 本示例的做法 |
|---|---|
| 预期用途 | 探索和修改登录用户本来就能查看或编辑的 QuickSight 分析。不用于对人做决定，例如招聘、授信或资格审核 |
| 准确性 | 模型可能理解错问题、选错列或筛选条件，也可能描述错结果。图表和预览里的数字由代码从工具结果中读取，从不由模型填写，但周围的文字来自模型：重要的回答请对照分析核实 |
| 透明 | 每个回答都会列出调用过的工具及参数，并显示模型名称和耗时；数据直接取自数据源而不是 SPICE 副本时，回答会说明 |
| 人工把关 | 模型不能自己修改分析。修改先以预览展示（附带修改后会显示的数据），只有发起人点 **应用到分析** 后分析才会改变；修改前会先备份原定义，最近一次修改可以撤销 |
| 不可信内容 | 数据集值、分析文字、URL 绑定控件、浏览器历史和企业 MCP 结果都可能夹带提示注入。Runtime 会在 JSON 解析前拒绝超过固定 UTF-8 原始字节上限或嵌套深度的工具响应，再以全局节点/深度预算清理容器和字符串，并把每类数据放在 system role 之外的随机不可信数据边界中。这能降低误执行风险，但不能证明模型会忽略所有注入。身份、分析和参数由代码注入；权限及企业工具名单由模型外部强制执行 |
| 内容过滤 | 本示例没有配置 Amazon Bedrock Guardrails 或其他内容过滤：模型可以是任意 OpenAI 兼容端点，而 AWS 中国区没有 Amazon Bedrock。如果你的场景需要内容过滤，请在模型端点或网关上配置（例如在支持的区域使用 Amazon Bedrock 时启用 Bedrock Guardrails） |
| 偏差 | 回答取决于分析里的数据和你所选模型的行为。本示例不对模型做偏差测试；请用你自己的用户和数据评估所配置的模型 |
| 发送给模型的数据 | 提问、最近几轮对话、分析结构和查询结果会发送到你的模型端点（见上面的“数据流向”）；请选择数据使用条款符合你要求的端点 |

## 成本

按用量计费：AgentCore Runtime（活跃会话的 CPU / 内存时长）、Gateway 调用、Code Interpreter 会话、Lambda、API Gateway、
按需 DynamoDB、Secrets Manager 密钥、**VPC 接口端点（4 个端点 × 子网数，按小时计费；通常是最大的固定成本）**、CloudWatch
Logs，以及你的模型。费用估算请使用 AWS 价格计算器。

## 故障排查

| 现象 | 原因 / 处理 |
|---|---|
| 弹窗提示登录未配置 | 上传 Identity Center 元数据（`./qsca idp-metadata`） |
| `audience mismatch` / `bearer confirmation does not match` | SAML 受众或 ACS URL 与栈输出不一致 |
| 登录后在 Identity Center 里报错 | 用户没有分配到该应用，或 `Subject` 没有映射到 `${user:email}` |
| “管理员尚未配置模型” | 模型密钥还是占位内容 |
| 模型报 `401 Authentication failed` | API Key 无效或已过期（Bedrock 长期 Key 会过期）：保存新 Key |
| 回答 1-2 分钟后失败，提示“输出过长被截断” | 模型输出失控，触发了 `max_tokens`；重试，或换更稳定的模型 |
| 回答慢 | Runtime 日志的 `answered` 事件里有每次调用的 `setup_ms`、`tool_ms`、`model_ms`；反复失败的工具调用或慢的模型调用会在这里体现 |
| 聊天窗口显示邮箱而不是姓名 | 看 web Lambda 日志的 `name_lookup_failed`：用户不在用户目录里，或 Identity Center 在其他账号 / 区域（配置 `identityCenter.identityStoreId` / `region`） |
| 没有分析的权限 | 用户在 QuickSight 里看不到它，或邮箱不一致 |
| “QuickSight 里有 N 个活跃用户使用同一个邮箱” | 多个活跃的 QuickSight 用户用了同一个邮箱（例如同一个人通过两个 IAM 角色联合登录过）；停用或删除多余的用户 |
| 一小时后要求重新登录 | 正常：一次登录的有效期是 `sessionSeconds`（默认 1 小时）；重新登录后对话会接着进行 |
| 缺少数据库凭证 | 用只能 SELECT 的用户创建数据源密钥（第 5 步）；不使用 QuickSight 数据源自己的密钥 |
| 内置查询不支持某个数据集 | 行级权限、数据集筛选、联接、自定义 SQL，或不支持的数据源；接入企业 MCP 服务器 |
| 查询超时 / 连接错误 | 数据库安全组或路由没有放行数据工具 Lambda |
| 聊天提示没有绑定分析 | 在聊天里点选分析完成绑定（需要编辑权限），或运行 `attach --apply` |
| 已应用但没有变化 | 刷新页面；重新发布仪表盘 |
| 刚发布或应用修改后图表显示“出现错误” | 页面还在用被替换的旧版本；刷新（有时要多刷几次） |

日志：`/aws/lambda/<prefix>-web`、`/aws/lambda/<prefix>-analysis-tools`、`/aws/lambda/<prefix>-data-tools`，以及
`/aws/bedrock-agentcore/runtimes/<prefix>_agent-…-DEFAULT`（每个会话一个日志流；`model_streaming` 事件表示某次模型调用超过
20 秒，`model_retry` 表示自动重试）。

## 限制

- 内置数据查询：PostgreSQL、Aurora PostgreSQL、MySQL、Aurora MySQL、MariaDB、RDS（PostgreSQL / MySQL）；只有一个关系表的
  数据集，并且只能使用获授权定义中调用者可见的图表字段和可达控件列。自定义 SQL 数据集、Athena、Redshift、S3 等不支持（请接入企业 MCP 服务器）。
- 修改支持折线图、柱状图和表格（聚合字段井）；使用分节布局的工作表不能自动新增可视对象；被筛选或动作引用的可视对象拒绝删除。
- 使用计算字段的可视对象，只有参数切换型字段（`ifelse(${p} = '…', {col}, …)`）能预览。
- 聊天不能修改控件；应用修改后编辑界面不会自动刷新；编辑界面里未保存的手动修改与已应用的修改可能互相覆盖。
- 模型还在“思考”时取消，会在这一步结束时停止（几秒到几十秒）。
- 浏览器支持：Chrome、Edge 等 Chromium 内核浏览器可以在 QuickSight 的 iframe 中使用分区会话 Cookie，能正常登录。
  Safari 默认开启“防止跨站跟踪”，会拦截该 Cookie，登录无法完成，聊天保持未登录状态（失败即拒绝）。不要要求用户
  关闭这项设置。通过 Storage Access API 支持 Safari 尚未实现。

## 开发

```bash
python3.12 -m venv ~/.venvs/qsca && ~/.venvs/qsca/bin/pip install signxml==5.2.0 lxml==6.1.3 cryptography==50.0.2 PyJWT==2.15.1 boto3==1.43.115
ACCOUNT_ID=0 SESSION_SECRET_ID=x TOOL_SECRET_ID=y QS_REGION=cn-north-1 AWS_DEFAULT_REGION=cn-north-1 ~/.venvs/qsca/bin/python -m unittest discover -s tests/unit
(cd infra && npm ci && npx tsc --noEmit && npm test)   # npm test：配置校验
(cd tests/js && npm ci && npm test)   # 在 jsdom 里测试聊天页的渲染（仅开发用）
~/.venvs/qsca/bin/python ./qsca build
```

`qsca build` 只从已提交的 `requirements/*.txt` 完整传递依赖锁中安装各部署包，并使用
`--require-hashes --no-deps`；依赖缓存标记由锁文件内容计算。构建还会核对两个 AWS 中国区 RDS CA 下载文件的固定 SHA-256。
依赖变化时，同时更新对应的 `requirements/*.in`，重新生成并审核完整哈希锁，不能只手改直接依赖版本。

单元测试需要 `boto3` 和 `PyJWT`；`tests/unit/test_auth.py` 里的 SAML 和退出登录测试还需要下面固定版本的 `signxml`、`lxml` 和
`cryptography`（没有时跳过；上面的 venv 里都有）。

固定版本：strands-agents 1.61.1、bedrock-agentcore 1.24.2、mcp 1.30.0、boto3 1.43.115、signxml 5.2.0、lxml 6.1.3、cryptography 50.0.2、
PyJWT 2.15.1、pg8000 1.31.5（配 scramp 1.4.18）、PyMySQL 1.1.2、aws-cdk-lib 2.274.0、ECharts 6.1.0、marked 18.1.1、DOMPurify 3.4.17。
