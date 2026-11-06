#!/usr/bin/env node
import * as fs from 'fs';
import * as path from 'path';
import { App } from 'aws-cdk-lib';
import { parseConfig } from '../lib/config';
import { ChatAssistantStack } from '../lib/stack';

const app = new App();
// The operator chooses the deployment config (`-c config=...`, default config.json); it must be a regular .json file.
const configPath = path.resolve(app.node.tryGetContext('config') ?? path.join(__dirname, '..', '..', 'config.json'));
if (path.extname(configPath) !== '.json' || !fs.statSync(configPath).isFile()) {
  throw new Error(`config ${configPath}: must be a regular .json file`);
}
const config = parseConfig(fs.readFileSync(configPath, 'utf-8'), configPath);
const account = process.env.CDK_DEFAULT_ACCOUNT;
new ChatAssistantStack(app, `${config.prefix}-chat-assistant`, config, {
  env: { account, region: config.region },
  description: 'QuickSight chat assistant: chat panel for any QuickSight analysis (AgentCore Runtime + Gateway)',
});
