// Config validation regressions. Run: cd infra && npm test
import { after, test } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { loadConfig } from '../lib/config';

const EXAMPLE = path.join(__dirname, '..', '..', 'config.example.json');
const DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'qsca-config-'));
after(() => fs.rmSync(DIR, { recursive: true, force: true }));

function withPrefix(secretPrefix: unknown): string {
  const config = JSON.parse(fs.readFileSync(EXAMPLE, 'utf-8'));
  config.prefix = 'qsca';
  config.dataAccess.datasourceSecretPrefix = secretPrefix;
  const file = path.join(DIR, 'config.json');
  fs.writeFileSync(file, JSON.stringify(config));
  return file;
}

test('a dedicated datasource secret prefix loads', () => {
  for (const good of ['quicksight-chat-assistant/datasource/', 'qsca/datasource/']) {
    assert.equal(loadConfig(withPrefix(good)).dataAccess.datasourceSecretPrefix, good);
  }
});

test('a datasource secret prefix that could cover the stack secrets is refused', () => {
  for (const bad of ['', '*', 'qsca/*', 'qsca/?', 'q', 'qsca', 'qsca/', 'qsca/session', 'qsca/tool-key',
    'qsca/model-config-', 'qsca/session-key-', undefined, 42]) {
    assert.throws(() => loadConfig(withPrefix(bad)), /datasourceSecretPrefix/, String(bad));
  }
});
