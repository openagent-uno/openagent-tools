import assert from 'node:assert/strict';
import test from 'node:test';
import { renderingArgs } from './browser.js';

test('software rendering is explicit and rejects unknown host configuration', () => {
  assert.deepEqual(renderingArgs({}), []);
  assert.deepEqual(renderingArgs({OPENAGENT_CHROME_RENDERER:'default'}), []);
  assert.deepEqual(renderingArgs({OPENAGENT_CHROME_RENDERER:'software'}),
    ['--disable-gpu','--use-angle=swiftshader','--enable-unsafe-swiftshader']);
  assert.throws(() => renderingArgs({OPENAGENT_CHROME_RENDERER:'unknown'}), /default or software/);
  assert.ok(!renderingArgs({OPENAGENT_CHROME_RENDERER:'software'}).includes('--no-sandbox'));
});
