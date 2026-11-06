import * as fs from 'fs';
import * as path from 'path';

/** One enterprise MCP server registered on the gateway (e.g. DataHub or Metabase behind MCPHub). */
export interface McpTargetConfig {
  /** Target name; its tools appear to the agent as `<name>___<tool>`. Letters, digits and hyphens. */
  name: string;
  /** Public HTTPS Streamable HTTP endpoint (the gateway has no VPC egress in China regions). */
  endpoint: string;
  description?: string;
  /**
   * none: no outbound auth. iam: SigV4 with the gateway role (MCP servers hosted on AgentCore Runtime: set runtimeArn so
   * the role may invoke it, and region when it is in another region).
   * oauth / apiKey: an AgentCore Identity credential provider you created (providerArn).
   */
  auth: { type: 'none' } | { type: 'iam'; service: string; region?: string; runtimeArn?: string } |
    { type: 'oauth'; providerArn: string; scopes: string[] } |
    { type: 'apiKey'; providerArn: string; parameterName?: string; prefix?: string; location?: 'HEADER' | 'QUERY_PARAMETER' };
}

export interface AppConfig {
  prefix: string;
  region: string;
  quickSight: { namespace: string; allowedAnalysisIds: string[] };
  identityCenter: {
    samlEntityId: string;
    /** Optional: where to look up users' names (default: the deployment region, its only Identity Center instance). */
    identityStoreId?: string;
    region?: string;
  };
  dataAccess: {
    /** Where the data tool Lambda runs so it can reach the databases behind QuickSight datasets; null = no VPC. */
    vpc: null | { vpcId: string; subnetIds: string[]; securityGroupIds: string[]; createInterfaceEndpoints: boolean };
    datasourceSecretPrefix: string;
    /** Ignored: the data tools read only `<datasourceSecretPrefix><DataSourceId>` (no other secrets). Kept so older
     * config files still load. */
    extraSecretArns?: string[];
  };
  mcpTargets: McpTargetConfig[];
  runtime: { idleSeconds: number; maxLifetimeSeconds: number };
  /** Optional: how long a browser sign-in lasts, in seconds (default 3600; 300-43200). */
  sessionSeconds?: number;
  api: { rateLimit: number; burstLimit: number };
  frameAncestors: string;
  /** Optional example questions shown in the chat page, replacing the built-in generic ones. */
  examples?: { group: string; tip?: string; questions: string[] }[];
}

/** Secrets the stack creates as `<prefix>/<name>` (stack.ts); the data Lambda's secret prefix must not cover them. */
export const STACK_SECRETS = ['session-key', 'tool-key', 'model-config'];

/** The operator's deployment config (`-c config=...` or config.json). It is the operator's own choice of file, so
 * it may live anywhere; it must be a regular .json file. The nosemgrep markers cover the operator-chosen path. */
export function loadConfig(file: string): AppConfig {
  const resolved = path.resolve(file); // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
  const stat = fs.statSync(resolved); // nosemgrep: javascript.lang.security.audit.detect-non-literal-fs-filename.detect-non-literal-fs-filename
  if (path.extname(resolved) !== '.json' || !stat.isFile()) throw new Error(`config ${file}: must be a regular .json file`);
  const config = JSON.parse(fs.readFileSync(resolved, 'utf-8')) as AppConfig; // nosemgrep: javascript.lang.security.audit.detect-non-literal-fs-filename.detect-non-literal-fs-filename
  const problems: string[] = [];
  if (!/^[a-z][a-z0-9]{1,11}$/.test(config.prefix)) problems.push('prefix: 2-12 lowercase letters/digits, starting with a letter');
  if (!config.region) problems.push('region is required');
  if (!config.identityCenter?.samlEntityId) problems.push('identityCenter.samlEntityId is required');
  const vpc = config.dataAccess?.vpc;
  if (vpc && (!vpc.vpcId || !vpc.subnetIds?.length)) problems.push('dataAccess.vpc needs vpcId and subnetIds (or set it to null)');
  // The data Lambda may read `<datasourceSecretPrefix>*`: a literal name prefix that cannot cover the stack's secrets.
  const secretPrefix = config.dataAccess?.datasourceSecretPrefix;
  const own = STACK_SECRETS.map((name) => `${config.prefix}/${name}`);
  if (typeof secretPrefix !== 'string' || !/^[A-Za-z0-9/_+=.@-]{1,200}$/.test(secretPrefix)) {
    problems.push('dataAccess.datasourceSecretPrefix: a nonempty secret name prefix (letters, digits, /_+=.@-; no * or ?)');
  } else if (own.some((name) => name.startsWith(secretPrefix) || secretPrefix.startsWith(name))) {
    problems.push(`dataAccess.datasourceSecretPrefix "${secretPrefix}" overlaps the stack's own secrets (${own.join(', ')}); ` +
      'use a dedicated prefix such as quicksight-chat-assistant/datasource/');
  }
  for (const target of config.mcpTargets ?? []) {
    if (!/^[A-Za-z0-9-]{1,40}$/.test(target.name) || ['analysis', 'data'].includes(target.name)) {
      problems.push(`mcpTargets.name "${target.name}": letters, digits, hyphens; "analysis" and "data" are reserved`);
    }
    if (!target.endpoint?.startsWith('https://')) problems.push(`mcpTargets "${target.name}": endpoint must be https://`);
  }
  const session = config.sessionSeconds;
  if (session !== undefined && !(Number.isInteger(session) && session >= 300 && session <= 43200)) {
    problems.push('sessionSeconds: whole seconds between 300 and 43200 (default 3600)');
  }
  const examples = Buffer.byteLength(JSON.stringify(config.examples ?? []), 'utf8');
  if (examples > 2500) problems.push(`examples: ${examples} bytes as JSON; keep under 2500 (Lambda environment variables share a 4 KB limit)`);
  if (problems.length) throw new Error(`config ${file}:\n  - ${problems.join('\n  - ')}`);
  return config;
}
