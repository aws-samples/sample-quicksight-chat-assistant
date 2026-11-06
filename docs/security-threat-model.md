# Security threat model

This document describes how the QuickSight chat assistant authenticates users, authorizes their actions, turns model
output into SQL and HTML, and which risks remain.

**Status.** This is an AWS sample. It still needs your own security review before you use it as guidance for
authentication or authorization. Its controls are sized for a sample, and the residual risks below are real.

## Why the sample has its own authentication

The chat page runs in an iframe inside a QuickSight analysis and does not receive the QuickSight user's identity, so
it signs the user in separately. The sample targets the AWS China Regions, where Amazon Cognito user pools are not
available ([Amazon Cognito in the China Regions](https://docs.amazonaws.cn/en_us/aws/latest/userguide/cognito.html)).
Without a managed user pool there is no managed token issuer to put in front of the API, so the sample uses IAM
Identity Center as the SAML identity provider, validates the assertion in the web Lambda, and issues its own
short-lived tokens. That makes `web/auth.py`, `tools/common/tokens.py` and `tools/common/caller.py` security-critical
code that you maintain. If you deploy where a managed identity service is available, prefer it over this code.

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
  `values…` key, only indexed keys `values[0]`, `values[1]`, … (contiguous from 0), or a list under `value`. Mixed or
  duplicate representations are refused, never resolved by picking one, and every list element is checked and bound
  on its own. The limit is 1–500 rows.
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
policy covers that prefix in the stack's region only. `parseConfig` (infra/lib/config.ts) requires the prefix to be a nonempty literal
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
