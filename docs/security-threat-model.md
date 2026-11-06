# Security threat model

This document describes how the QuickSight chat assistant authenticates users, authorizes their actions, turns model
output into SQL and HTML, and which risks remain. It ends with a ledger of every row of the AppSec Probe scan
(export `main-20261028`, 58 rows) and what happened to it.

**Status.** This is an AWS sample. It still needs your own AppSec review before you use it as guidance for
authentication or authorization. Its controls are sized for a sample, and the residual risks below are real.

## Components and trust boundaries

| Component | Trusts | Is trusted by |
|---|---|---|
| Chat page (`web/index.html`, `web/render.js`, `web/app.js`) in a QuickSight iframe | Nothing it receives; it renders text, and Markdown only through the sanitizer | Nobody. The server ignores the `viewer` URL parameter for access decisions |
| Web Lambda (`web/handler.py`, `web/auth.py`) | IAM Identity Center SAML assertions signed by a certificate in the stored metadata | The browser (session token), the tool Lambdas (tool token) |
| AgentCore Runtime (`agent/main.py`) | The job payload from the web Lambda | Nothing: it overwrites `_caller`, `_analysis` and `_parameters` in code before every call to this solution's tools, so the model cannot set them |
| Analysis and data tool Lambdas (`tools/`) | A tool token signed with the tool key; QuickSight permissions read live (cached up to 60 s) | The web Lambda (button calls) and the Gateway |
| Model endpoint | Nothing | Nothing. Model output is data: it never becomes SQL text, HTML or identity |

## Authentication flow

1. The iframe opens a popup at `/auth/login?nonce=…`. The web Lambda stores `saml#<request id>` (10 minutes) and
   redirects to Identity Center with an AuthnRequest built with lxml element APIs (`web/auth.py` `_authn_request`).
2. Identity Center posts the signed assertion to `/saml/acs`. `complete_login` consumes the pending request once and
   parses the XML only through `_parse_xml`. That function refuses any DOCTYPE (byte check before parsing, `docinfo`
   check after) and uses a parser with `resolve_entities=False`, `no_network=True`, `load_dtd=False` and
   `huge_tree=False`, and it removes comments and processing instructions.
3. The response must contain exactly one plain assertion. The signature is verified with SignXML against every signing
   certificate in the stored metadata (key info in the document is ignored), and the verified element must be that
   assertion. Then the code checks the status, issuer, `NotBefore`/`NotOnOrAfter` (3 minutes of skew), audience, and
   the bearer `Recipient` (the ACS URL), `InResponseTo` (the RelayState) and expiry. It rejects a replay through
   `samlassert#<ID>` (24 h) and requires a NameID.
4. The popup hands a session token to the iframe with `postMessage`, restricted to the page's origin and matched by
   nonce. The page keeps it in `sessionStorage`, so it is per tab and gone when the tab closes.

## Tokens and keys

| Token | Audience | Signing key (Secrets Manager) | Readable by | Lifetime | Bound to |
|---|---|---|---|---|---|
| Session | `qsca:session` | `<prefix>/session-key` | Web Lambda only | `sessionSeconds` (1 h) | user (email), `jti` |
| Tool | `qsca:tools` | `<prefix>/tool-key` | Web Lambda (signs), analysis and data Lambdas (verify) | job: Runtime max lifetime (8 h); button: 5 min | user, `analysis`, `sid` (the session's `jti`) |

Both are HS256 JWTs made by PyJWT (`tools/common/tokens.py`). The algorithm is fixed, and issuer, audience, expiry and
the required claims are checked. A tool Lambda can verify tool tokens but cannot mint a session token, because it
cannot read `session-key`. The tool key is still a shared HMAC key: a compromised tool Lambda could mint tool tokens
for any user (see residual risks). The browser never receives a tool token, and enterprise MCP servers never get one.

## Email to QuickSight user mapping

The SAML NameID (the Identity Center email, lower-cased) is the only link to QuickSight. `caller.principals` lists
the active QuickSight users with that email. If there are none, the request is refused. If there are several, it is
also refused rather than merged, because their permissions would be combined. Groups come from `ListUserGroups`.

## Authorization layers

1. API: every route except the page, static files, `/health`, login and ACS needs a valid, unrevoked session token.
2. Tool token: the signature, the `analysis` claim equal to `_analysis`, and `sid` present. The analysis tools also
   refuse the token when `revoked#<sid>` exists (`caller.revocation_check`).
3. QuickSight: viewing needs any permission on the analysis or on a dashboard published from it. Editing,
   applying, binding, publishing and saving examples need `quicksight:UpdateAnalysis` (publishing also needs the
   dashboard update permissions). `ALLOWED_ANALYSIS_IDS` limits which analyses can be used at all.
4. Data: the dataset must be declared by the analysis and pass `dataset.plan()`. Only columns the analysis references
   are offered, and column-level security hides columns from users who are not granted them.
5. Edits: the model can only preview. Only the requester can apply a pending change, once, within 10 minutes, after
   the previous definition has been backed up to S3.

## QuerySpec to SQL boundary

The model sends a QuerySpec (`metrics, dimensions, time, filters, order_by, limit`), and `tools/data/sqlcompile.py`
compiles it into one SELECT:

- Unknown keys are refused, not dropped. `query_dataset` refuses any argument other than `dataset_id`, the three
  fields the Runtime sets (`_caller`, `_analysis`, `_parameters`) and the QuerySpec keys, before any access check.
  The compiler refuses unknown keys in the spec, metric, time, filter and order_by objects. Filters keep the existing
  tolerance for garbled `values…` key names.
- Identifiers must be planned columns. They are mapped to their physical names and quoted for the dialect.
  Aggregates, grains and operators come from fixed lists.
- Values are always bound parameters: strings of at most 500 characters or finite, non-boolean numbers. Each filter
  carries exactly the operand its operator takes (`sqlcompile._operand`): one scalar `value` for `eq`, `ne`, `gt`,
  `gte`, `lt`, `lte` and `contains`; a list only for `in`/`not_in` (1–200 values) and `between` (2 values); nothing
  for `is_null`/`not_null`. Any other or extra operand is refused; a present `value` or `values…` key counts as an
  operand even when its value is null. A list operator takes exactly one list representation: `values`, one garbled
  `values…` key, or only indexed keys `values[0]`, `values[1]`, … (contiguous from 0). Mixed or duplicate
  representations are refused, never resolved by picking one. The limit is 1–500 rows.
- `tools/data/handler.py` `_execute` is the one place generated SQL is executed, with the parameters passed to the
  driver separately.
- The relation is always one quoted `schema.table`. The connection runs a read-only transaction with a constant 20 s
  statement timeout.

The referenced columns come from `definition.referenced_columns()`. It collects every `{DataSetIdentifier,
ColumnName}` object anywhere in the analysis definition, maps identifiers to dataset IDs through
`DataSetIdentifierDeclarations`, and adds the `{column}` references of calculated fields, so metric-switch previews keep
working. String literals (single or double quotes, an unterminated one to the end) are masked first, so brace text
such as `'{salary}'` is not read as a column. `dataset.plan()` intersects that set with the dataset's projected columns and then applies column-level
security. Unreferenced columns are not even named in `hidden_columns`.

## Custom SQL policy

Datasets whose physical table is `CustomSql` are refused with a clear message. Querying them would mean embedding the
dataset's SQL text in the query. Only `RelationalTable` datasets are supported. Joins, dataset filters and row-level
security (including tag-based) are still refused, because querying the source directly would bypass them.

## Database credentials

The data Lambda reads only `<datasourceSecretPrefix><DataSourceId>`, created with `./qsca datasource-secret`. Its IAM
policy covers that prefix in the stack's region only. `loadConfig` requires the prefix to be a nonempty literal
secret name prefix (no `*` or `?`) that neither covers nor extends `<prefix>/session-key`, `<prefix>/tool-key` or
`<prefix>/model-config` (`infra/test/config.test.ts`), so the data Lambda cannot read a signing key. The fallback to the QuickSight data source's own `SecretArn` and the
`extraSecretArns` setting were removed. Operators must create a dedicated database user that can only SELECT the
dataset tables (the README has PostgreSQL and MySQL examples). The read-only transaction in the application is defense
in depth, not the control.

## XSS controls

- CSP: `script-src 'self'` with no inline script. The scripts are served by `web/handler.py` under content-hashed
  names (`render-<hash>.js`, `app-<hash>.js`). The CSP also has `connect-src 'self'`, `object-src 'none'`,
  `base-uri 'none'`, `form-action 'none'` and `frame-ancestors` limited to the QuickSight domains.
- First-party UI is built with DOM APIs. `QscaRender.el()` appends strings as text nodes and refuses `on*`
  attributes, and `app.js` contains no `innerHTML`, `outerHTML`, `insertAdjacentHTML` or `document.write` (checked by
  `tests/js`). The remaining `.append` calls are `Node.append` of nodes or text.
- Markdown (answers and the user's own questions) has exactly one boundary, `QscaRender.markdown()`. That function
  runs marked, then DOMPurify with `RETURN_DOM_FRAGMENT`. The allow-list has no `img`, `iframe`, `style`, `class`,
  `div` or `span`; links keep only `http(s)` hrefs and get `target=_blank rel="noopener noreferrer"`. The table
  wrapper is added with DOM after sanitizing.
- History and pending jobs stay in `localStorage` (per user and analysis). They are rendered only through the same
  renderers, so a tampered entry is still shown as text or sanitized Markdown.

## Sign-out behavior

`POST /auth/logout` writes `revoked#<jti>`, so the session token stops working at once. The record's TTL is the
later of the session's expiry and now + the job tool-token lifetime (8 h), plus the clock leeway, so it outlives
every tool token issued under that sign-in. Each chat job row carries `sid`, and the web Lambda records the
sign-in's job IDs in `sessjobs#<jti>` (the newest 50). Sign-out cancels the ones still RUNNING through the existing
cancel path. The analysis tools refuse every tool token whose `sid` is revoked, for the token's whole life, so a
running answer can no longer read or change analyses. The analysis Lambda can read only `revoked#*` items for this
purpose.

## Residual risks and future work

- The data Lambda (in the VPC, no DynamoDB access) does not check revocation. A cancelled job's tool token can query
  data until it expires (up to the Runtime max lifetime). Cancellation stops the agent within one heartbeat (30 s).
- `sessjobs#<jti>` is read-modify-write without a condition. Two simultaneous submits in the same tab could drop one
  ID, and that job would then not be cancelled on sign-out.
- Sign-out cancels jobs one by one, and each cancel can wait up to 25 s for the Runtime. With many running jobs the
  30 s web Lambda timeout can cut it short (the session is revoked first).
- After the browser session expires, the user cannot sign out that session, and its running jobs keep their tool
  tokens until they expire.
- HS256 with a shared tool key: any holder of `tool-key` (the web Lambda and both tool Lambdas) can mint tool tokens.
  There is no key rotation process.
- QuickSight permission caches (60 s, dashboards 5 min) delay revocations of shares and group memberships.
- The referenced-column rule follows the analysis definition. A column the author added to any visual, filter,
  control or calculated field is queryable at row level through aggregates, and a column referenced only through a
  bare name in a non-switch calculated field is not offered.
- `datasourceSecretPrefix` is checked only against this stack's own secrets. Any other secret in the region whose
  name starts with it (for example another deployment's) is readable by the data Lambda, so keep the prefix
  dedicated to assistant database credentials.
- The page CSP allows inline styles (ECharts tooltips). ECharts escapes series names by default.
- Not built here (out of scope): an asynchronous mutation worker, finalizer, SQS/DLQ, EventBridge sweeps, GSIs and
  leases; KMS asymmetric tokens, key rotation and canaries; a separate auth-state table; DynamoDB attribute-level IAM
  conditions; VPC mode or endpoint redesign; release manifests and rollback tooling; exhaustive browser-storage
  schemas; removing the QuickSight permission caches; new toolchains (uv, iam-policy-autopilot); API Gateway access
  logging; request-size schemas beyond the fixes above.

## How the scan was re-run

The Probe export's rules were reproduced with Bandit 1.7.9 (all 12 Bandit rows; Bandit 1.9.4 no longer has the lxml
checks B320/B410), Semgrep 1.184.0 with `p/default` plus `r/javascript`, `r/typescript` and `r/python` (all 46 Semgrep
rows; `p/default` alone reproduces 8 of them), and Checkov 3.4.3 `--framework secrets` (the one Checkov row). The
scanners were installed in a virtual environment outside the repository and run on a `git archive` of the branch.

## Findings outside the Probe input

The Probe did not scan `qsca` (the admin CLI has no file extension). The wider Semgrep set reports, on unchanged
lines of `qsca`: `dangerous-subprocess-use-audit` at lines 97 and 153 (`pip install` and `npx cdk deploy`, argument
lists without a shell, run by the operator), `arbitrary-sleep` at 265, 340 and 432 (bounded CloudFormation/QuickSight
polling loops in the CLI), and `dynamic-urllib-use-detected` at 129 and 413 (fixed `https://` RDS CA URLs, and the
stack's own API URL). They are recorded here and not changed.

## Ledger

Disposition: **fixed** means the code changed to remove the risk. Where a scanner cannot see the mitigation, a narrow
`nosec`/`nosemgrep` annotation remains at the new location, with the reason in the comment above it. **FP** (false
positive) means the flagged code was not a risk; it is annotated the same way (row 1 cannot be, because JSON has no
comments).

| # | Rule | Original | Disposition | Justification | New location |
|---|---|---|---|---|---|
| 1 | Checkov CKV_SECRET_6 | config.example.json:18 | FP | `datasourceSecretPrefix` is a Secrets Manager name prefix, not a secret. The detector also flags other prefix values, and a placeholder such as `<…>` would make invalid secret names and IAM resources | config.example.json:18 |
| 2 | Bandit B320 | tests/unit/test_auth.py:220 | FP | Test fixture parses XML it just built | tests/unit/test_auth.py:265 |
| 3 | Bandit B310 | tests/e2e.py:136 | fixed | `_https()` refuses non-https URLs before `urlopen`; `nosec B310` | tests/e2e.py:149 |
| 4 | Bandit B320 | web/auth.py:57 | fixed | Metadata parsed by `_parse_xml` (hardened parser, DOCTYPE refused); `nosec` at the single parse point | web/auth.py:73 |
| 5 | Bandit B320 | web/auth.py:180 | fixed | SAMLResponse parsed by `_parse_xml`; DOCTYPE/XXE/entity-expansion tests | web/auth.py:73 |
| 6 | Bandit B110 | agent/sandbox.py:107 | fixed | Logs `code_interpreter_stop_failed` instead of `pass` | agent/sandbox.py:108 |
| 7 | Bandit B410 | web/auth.py:27 | FP | SignXML requires lxml; every parse goes through `_parse_xml` | web/auth.py:32 |
| 8 | Bandit B104 | agent/main.py:710 | FP | AgentCore Runtime contract: the container serves 0.0.0.0:8080 inside its microVM | agent/main.py:711 |
| 9 | Bandit B608 | tools/data/sqlcompile.py:243 | FP | Only quoted known identifiers and fixed fragments are formatted in; every value is bound. The one execution point carries a `nosemgrep` with the same reason | tools/data/sqlcompile.py:291; tools/data/handler.py:157 |
| 10 | Bandit B410 | tests/unit/test_auth.py:146 | FP | Test fixture (SignXML needs lxml) | tests/unit/test_auth.py:171 |
| 11 | Bandit B310 | tests/e2e.py:129 | fixed | `_https()` before `urlopen`; `nosec B310` | tests/e2e.py:141 |
| 12 | Bandit B320 | tests/unit/test_auth.py:209 | FP | Test fixture parses XML it just built | tests/unit/test_auth.py:248 |
| 13 | Semgrep html-in-template-string | web/app.js:537 | fixed | Typing indicator built with `el()` | web/app.js:502 |
| 14 | Semgrep formatted-sql-query | tools/data/handler.py:110 | fixed | Constant `SET SESSION max_execution_time = 20000` | tools/data/handler.py:112 |
| 15 | Semgrep html-in-template-string | web/app.js:434 | fixed | `chartsNodes()` | web/app.js:393 |
| 16 | Semgrep html-in-template-string | web/app.js:359 | fixed | `controlsNode()` | web/app.js:315 |
| 17 | Semgrep string-concat-in-list | web/handler.py:96 | fixed | Explicit `+` | web/handler.py:106 |
| 18 | Semgrep jquery-insecure-method | web/app.js:96 | fixed | `addMessage()`; `$` renamed `byId`; `Node.append` of nodes | web/app.js:51 |
| 19 | Semgrep insecure-document-method (ERROR) | web/app.js:566 | fixed | `pending.replaceChildren(answerNode(turn))` | web/app.js:531 |
| 20 | Semgrep jquery-insecure-method | web/app.js:278 | fixed | `Node.append` of a button node; no longer reported | web/app.js:241 |
| 21 | Semgrep insecure-innerhtml (ERROR) | web/app.js:95 | fixed | `addMessage()` builds with `el()` | web/app.js:49 |
| 22 | Semgrep avoid_app_run_with_bad_host | agent/main.py:710 | FP | As row 8; `nosemgrep` | agent/main.py:711 |
| 23 | Semgrep directly-returned-format-string | web/auth.py:149 | fixed | AuthnRequest built with lxml elements; redirect URL concatenated with an urlencoded query | web/auth.py:177, :199 |
| 24 | Semgrep html-in-template-string | web/app.js:424 | fixed | `previewNode()` | web/app.js:375 |
| 25 | Semgrep html-in-template-string | web/app.js:526 | fixed | `answerNode()` | web/app.js:490 |
| 26 | Semgrep html-in-template-string | web/app.js:441 | fixed | `chartsNodes()` | web/app.js:393 |
| 27 | Semgrep detect-non-literal-fs-filename | infra/lib/stack.ts:29 | fixed | Path resolved and asserted inside the repo root; callers pass literals; `nosemgrep` | infra/lib/stack.ts:36 |
| 28 | Semgrep html-in-template-string | web/app.js:303 | fixed | `showGreeting()` with `el()` | web/app.js:263 |
| 29 | Semgrep insecure-document-method (ERROR) | web/app.js:466 | fixed | `box.replaceWith(previewNode(...))` | web/app.js:432 |
| 30 | Semgrep arbitrary-sleep (ERROR) | tools/analysis/publisher.py:54 | fixed | `wait_until()`: monotonic deadline, the same 120 s limit, one annotated sleep | tools/analysis/publisher.py:58, :65 |
| 31 | Semgrep insecure-innerhtml (ERROR) | web/app.js:466 | fixed | As row 29 | web/app.js:432 |
| 32 | Semgrep path-join-resolve-traversal | infra/lib/stack.ts:29 | fixed | As row 27; `nosemgrep` | infra/lib/stack.ts:31 |
| 33 | Semgrep html-in-template-string | web/app.js:417 | fixed | `previewNode()` | web/app.js:375 |
| 34 | Semgrep sqlalchemy-execute-raw-query (ERROR) | tools/data/handler.py:110 | fixed | Constant statement | tools/data/handler.py:112 |
| 35 | Semgrep html-in-template-string | web/app.js:529 | fixed | `answerNode()` | web/app.js:490 |
| 36 | Semgrep html-in-template-string | web/app.js:304 | fixed | `showGreeting()` | web/app.js:263 |
| 37 | Semgrep html-in-template-string | web/app.js:434 | fixed | `chartsNodes()` | web/app.js:393 |
| 38 | Semgrep html-in-template-string | web/app.js:439 | fixed | `chartsNodes()` | web/app.js:393 |
| 39 | Semgrep html-in-template-string | web/app.js:310 | fixed | `showLogin()` with `el()` | web/app.js:270 |
| 40 | Semgrep insecure-innerhtml (ERROR) | web/app.js:566 | fixed | As row 19 | web/app.js:531 |
| 41 | Semgrep html-in-template-string | web/app.js:356 | fixed | `controlsNode()` | web/app.js:315 |
| 42 | Semgrep html-in-template-string | web/app.js:595 | fixed | `replayHistory()` with `el()` | web/app.js:556 |
| 43 | Semgrep detect-non-literal-fs-filename | infra/lib/config.ts:47 | fixed | Operator-chosen config path, resolved and required to be a regular `.json` file; `nosemgrep` | infra/lib/config.ts:55, :56, :58 |
| 44 | Semgrep html-in-template-string | web/app.js:437 | fixed | `chartsNodes()` | web/app.js:393 |
| 45 | Semgrep html-in-template-string | web/app.js:355 | fixed | `controlsNode()` | web/app.js:315 |
| 46 | Semgrep html-in-template-string | web/app.js:433 | fixed | `chartsNodes()` | web/app.js:393 |
| 47 | Semgrep html-in-template-string | web/app.js:415 | fixed | `previewNode()` | web/app.js:375 |
| 48 | Semgrep html-in-template-string | web/app.js:414 | fixed | `previewNode()` | web/app.js:375 |
| 49 | Semgrep insecure-document-method (ERROR) | web/app.js:95 | fixed | As row 21 | web/app.js:49 |
| 50 | Semgrep html-in-template-string | web/app.js:435 | fixed | `chartsNodes()` | web/app.js:393 |
| 51 | Semgrep pg8000-sqli | tools/data/handler.py:98 | fixed | Constant `SET statement_timeout = 20000` | tools/data/handler.py:100 |
| 52 | Semgrep jquery-insecure-method | web/app.js:144 | fixed | `byId("who").append` of nodes | web/app.js:104 |
| 53 | Semgrep arbitrary-sleep (ERROR) | tools/analysis/handler.py:76 | fixed | `publisher.wait_until(…, 30, 1)` keeps the 30 s limit | tools/analysis/handler.py:81 |
| 54 | Semgrep html-in-template-string | web/app.js:418 | fixed | `previewNode()` | web/app.js:375 |
| 55 | Semgrep html-in-template-string | web/app.js:429 | fixed | `previewNode()` | web/app.js:375 |
| 56 | Semgrep string-concat-in-list | tools/analysis/handler.py:106 | fixed | Explicit `+` | tools/analysis/handler.py:112 |
| 57 | Semgrep jquery-insecure-method | web/app.js:43 | fixed | `byId("ctx").append` of a node | web/app.js:45 |
| 58 | Semgrep jquery-insecure-method | web/app.js:290 | fixed | `Node.append` of a button node | web/app.js:253 |
