import { isIP } from 'net';

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
    vpc: null | {
      vpcId: string;
      subnetIds: string[];
      /** Extra groups must not contain broader outbound rules than this owned group. */
      securityGroupIds: string[];
      createInterfaceEndpoints: boolean;
      /** Database destinations the owned Lambda security group may reach. */
      databaseEgress: { cidr: string; port: number }[];
      /** Required when using existing interface endpoints; their private IPv4/IPv6 CIDRs on TCP 443. */
      endpointHttpsCidrs?: string[];
      /** Required with existing endpoints because DynamoDB interface endpoints do not override regional DNS. */
      dynamodbEndpointUrl?: string;
      /** Required with existing endpoints; use the RDS API interface endpoint URL (rds-api in China regions). */
      rdsEndpointUrl?: string;
    };
    datasourceSecretPrefix: string;
    /** Ignored: the data tools read only `<datasourceSecretPrefix><DataSourceId>` (no other secrets). Kept so older
     * config files still load. */
    extraSecretArns?: string[];
  };
  mcpTargets: McpTargetConfig[];
  /** Exact `<target>___<tool>` names reviewed by the operator as read-only. Enterprise tools default to unavailable. */
  enterpriseReadOnlyTools?: string[];
  runtime: { idleSeconds: number; maxLifetimeSeconds: number };
  /** Optional: how long a browser sign-in lasts, in seconds (default 3600; 300-43200). */
  sessionSeconds?: number;
  api: { rateLimit: number; burstLimit: number };
  frameAncestors: string;
  /** Optional example questions shown in the chat page, replacing the built-in generic ones. */
  examples?: { group: string; tip?: string; questions: string[] }[];
}

/** Secrets the stack creates as `<prefix>/<name>` (stack.ts); the data Lambda's secret prefix must not cover them. */
export const STACK_SECRETS = ['session-key', 'tool-key', 'log-key', 'model-config'];

/** Validate the operator's deployment config, given as JSON text. `source` names it in error messages. Reading the
 * file (the operator's own choice of `-c config=...` or config.json) is done by bin/app.ts, the CLI entry point. */
export function parseConfig(text: string, source: string): AppConfig {
  const config = JSON.parse(text) as AppConfig;
  const problems: string[] = [];
  if (!/^[a-z][a-z0-9]{1,11}$/.test(config.prefix)) problems.push('prefix: 2-12 lowercase letters/digits, starting with a letter');
  if (!config.region) problems.push('region is required');
  if (!config.identityCenter?.samlEntityId) problems.push('identityCenter.samlEntityId is required');
  const vpc = config.dataAccess?.vpc;
  if (vpc && (!vpc.vpcId || !vpc.subnetIds?.length)) problems.push('dataAccess.vpc needs vpcId and subnetIds (or set it to null)');
  if (vpc) {
    if (!Array.isArray(vpc.databaseEgress) || !vpc.databaseEgress.length) {
      problems.push('dataAccess.vpc.databaseEgress needs at least one explicit {cidr, port} database destination');
    } else {
      const destinations = new Set<string>();
      for (const rule of vpc.databaseEgress) {
        const [address, prefix, extra] = typeof rule?.cidr === 'string' ? rule.cidr.split('/') : [];
        const family = isIP(address ?? '');
        const bits = Number(prefix);
        if (extra !== undefined || !family || !Number.isInteger(bits) || bits < 0 || bits > (family === 4 ? 32 : 128)) {
          problems.push(`dataAccess.vpc.databaseEgress cidr "${String(rule?.cidr)}" is not an IPv4 or IPv6 CIDR`);
        }
        if (!Number.isInteger(rule?.port) || rule.port < 1 || rule.port > 65535) {
          problems.push(`dataAccess.vpc.databaseEgress port "${String(rule?.port)}" must be 1-65535`);
        }
        const key = `${rule?.cidr}:${rule?.port}`;
        if (destinations.has(key)) problems.push(`dataAccess.vpc.databaseEgress duplicate destination "${key}"`);
        destinations.add(key);
      }
    }
    const endpointCidrs = vpc.endpointHttpsCidrs ?? [];
    if (!vpc.createInterfaceEndpoints && !endpointCidrs.length) {
      problems.push('dataAccess.vpc.endpointHttpsCidrs is required when createInterfaceEndpoints is false');
    }
    for (const cidr of endpointCidrs) {
      const [address, prefix, extra] = typeof cidr === 'string' ? cidr.split('/') : [];
      const family = isIP(address ?? '');
      const bits = Number(prefix);
      if (extra !== undefined || !family || !Number.isInteger(bits) || bits < 0 || bits > (family === 4 ? 32 : 128)) {
        problems.push(`dataAccess.vpc.endpointHttpsCidrs entry "${String(cidr)}" is not an IPv4 or IPv6 CIDR`);
      }
    }
    if (new Set(endpointCidrs).size !== endpointCidrs.length) {
      problems.push('dataAccess.vpc.endpointHttpsCidrs entries must be unique');
    }
    const endpointUrls: [string, string | undefined, (host: string) => boolean][] = [
      ['dynamodbEndpointUrl', vpc.dynamodbEndpointUrl,
        (host) => host.startsWith('vpce-') && host.includes('.dynamodb.')],
      ['rdsEndpointUrl', vpc.rdsEndpointUrl,
        (host) => (host.startsWith('vpce-') && host.includes('.rds.')) || host.startsWith('rds-api.')],
    ];
    for (const [key, value, hostMatches] of endpointUrls) {
      if (!vpc.createInterfaceEndpoints && !value) {
        problems.push(`dataAccess.vpc.${key} is required when createInterfaceEndpoints is false`);
        continue;
      }
      if (value) {
        try {
          const url = new URL(value);
          const awsHost = url.hostname.endsWith('.amazonaws.com') || url.hostname.endsWith('.amazonaws.com.cn');
          if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search ||
              url.hash || url.origin !== value || !awsHost || !hostMatches(url.hostname)) {
            problems.push(`dataAccess.vpc.${key} must be the exact HTTPS AWS service endpoint origin`);
          }
        } catch {
          problems.push(`dataAccess.vpc.${key} must be the exact HTTPS AWS service endpoint origin`);
        }
      }
    }
  }
  // The data Lambda may read `<datasourceSecretPrefix>*`: a literal name prefix that cannot cover the stack's secrets.
  const secretPrefix = config.dataAccess?.datasourceSecretPrefix;
  const own = STACK_SECRETS.map((name) => `${config.prefix}/${name}`);
  if (typeof secretPrefix !== 'string' || !/^[A-Za-z0-9/_+=.@-]{1,200}$/.test(secretPrefix)) {
    problems.push('dataAccess.datasourceSecretPrefix: a nonempty secret name prefix (letters, digits, /_+=.@-; no * or ?)');
  } else if (own.some((name) => name.startsWith(secretPrefix) || secretPrefix.startsWith(name))) {
    problems.push(`dataAccess.datasourceSecretPrefix "${secretPrefix}" overlaps the stack's own secrets (${own.join(', ')}); ` +
      'use a dedicated prefix such as quicksight-chat-assistant/datasource/');
  }
  const targetNames = new Set<string>();
  for (const target of config.mcpTargets ?? []) {
    if (!/^[A-Za-z0-9-]{1,40}$/.test(target.name) || ['analysis', 'data'].includes(target.name)) {
      problems.push(`mcpTargets.name "${target.name}": letters, digits, hyphens; "analysis" and "data" are reserved`);
    }
    if (targetNames.has(target.name)) problems.push(`mcpTargets.name "${target.name}": target names must be unique`);
    targetNames.add(target.name);
    if (!target.endpoint?.startsWith('https://')) problems.push(`mcpTargets "${target.name}": endpoint must be https://`);
  }
  const enterpriseTools = config.enterpriseReadOnlyTools ?? [];
  if (!Array.isArray(enterpriseTools)) {
    problems.push('enterpriseReadOnlyTools must be an array of exact <target>___<tool> names');
  } else {
    for (const tool of enterpriseTools) {
      const match = typeof tool === 'string' && /^([A-Za-z0-9-]{1,40})___[A-Za-z0-9_-]{1,128}$/.exec(tool);
      if (!match || !targetNames.has(match[1])) {
        problems.push(`enterpriseReadOnlyTools entry "${String(tool)}" must exactly name a tool on a configured MCP target`);
      }
    }
    if (new Set(enterpriseTools).size !== enterpriseTools.length) {
      problems.push('enterpriseReadOnlyTools: exact tool names must be unique');
    }
    if (Buffer.byteLength(enterpriseTools.join(','), 'utf8') > 2000) {
      problems.push('enterpriseReadOnlyTools: combined allowlist must be at most 2000 bytes');
    }
  }
  const frameAncestors = config.frameAncestors;
  if (typeof frameAncestors !== 'string' || !frameAncestors.trim()) {
    problems.push('frameAncestors: one or more exact HTTPS origins are required');
  } else {
    const origins = frameAncestors.trim().split(/\s+/);
    if (new Set(origins).size !== origins.length) problems.push('frameAncestors: origins must be unique');
    for (const origin of origins) {
      try {
        const url = new URL(origin);
        if (origin.includes('*') || url.protocol !== 'https:' || url.username || url.password ||
            url.pathname !== '/' || url.search || url.hash || url.origin !== origin) {
          problems.push(`frameAncestors "${origin}": use an exact HTTPS origin without credentials, path, query, fragment or wildcard`);
        }
      } catch {
        problems.push(`frameAncestors "${origin}": invalid HTTPS origin`);
      }
    }
  }
  const session = config.sessionSeconds;
  if (session !== undefined && !(Number.isInteger(session) && session >= 300 && session <= 43200)) {
    problems.push('sessionSeconds: whole seconds between 300 and 43200 (default 3600)');
  }
  const examples = Buffer.byteLength(JSON.stringify(config.examples ?? []), 'utf8');
  if (examples > 2500) problems.push(`examples: ${examples} bytes as JSON; keep under 2500 (Lambda environment variables share a 4 KB limit)`);
  if (problems.length) throw new Error(`config ${source}:\n  - ${problems.join('\n  - ')}`);
  return config;
}
