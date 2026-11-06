// Config validation regressions. Run: cd infra && npm test
import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'fs';
import * as path from 'path';
import { parseConfig } from '../lib/config';

const EXAMPLE = fs.readFileSync(path.join(__dirname, '..', '..', 'config.example.json'), 'utf-8');

function withPrefix(secretPrefix: unknown): string {
  const config = JSON.parse(EXAMPLE);
  config.prefix = 'qsca';
  config.dataAccess.datasourceSecretPrefix = secretPrefix;
  return JSON.stringify(config);
}

test('the example config loads', () => {
  assert.equal(parseConfig(EXAMPLE, 'config.example.json').prefix, JSON.parse(EXAMPLE).prefix);
});

test('a dedicated datasource secret prefix loads', () => {
  for (const good of ['quicksight-chat-assistant/datasource/', 'qsca/datasource/']) {
    assert.equal(parseConfig(withPrefix(good), 'test').dataAccess.datasourceSecretPrefix, good);
  }
});

test('a datasource secret prefix that could cover the stack secrets is refused', () => {
  for (const bad of ['', '*', 'qsca/*', 'qsca/?', 'q', 'qsca', 'qsca/', 'qsca/session', 'qsca/tool-key',
    'qsca/model-config-', 'qsca/session-key-', undefined, 42]) {
    assert.throws(() => parseConfig(withPrefix(bad), 'test'), /datasourceSecretPrefix/, String(bad));
  }
});
