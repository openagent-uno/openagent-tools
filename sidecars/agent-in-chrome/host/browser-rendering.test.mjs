import assert from 'node:assert/strict';
import test from 'node:test';
import { renderingArgs } from './browser.js';
import { macosAppShimServiceName } from './macos-host-requirements.js';

test('software rendering is explicit and rejects unknown host configuration', () => {
  assert.deepEqual(renderingArgs({}), []);
  assert.deepEqual(renderingArgs({OPENAGENT_CHROME_RENDERER:'default'}), []);
  assert.deepEqual(renderingArgs({OPENAGENT_CHROME_RENDERER:'software'}),
    ['--disable-gpu','--use-angle=swiftshader','--enable-unsafe-swiftshader']);
  assert.throws(() => renderingArgs({OPENAGENT_CHROME_RENDERER:'unknown'}), /default or software/);
  assert.ok(!renderingArgs({OPENAGENT_CHROME_RENDERER:'software'}).includes('--no-sandbox'));
});

test('macOS IPC requirements bind one absolute profile without wildcard authority', () => {
  const one=macosAppShimServiceName('org.chromium.Chromium','/private/host-a/profile');
  const two=macosAppShimServiceName('org.chromium.Chromium','/private/host-b/profile');
  assert.match(one,/^org\.chromium\.Chromium\.apps\.[A-F0-9]{64}$/);
  assert.notEqual(one,two);
  for(const profile of ['relative','/private/host-a/../profile','/private/profile\n'])
    assert.throws(()=>macosAppShimServiceName('org.chromium.Chromium',profile));
  assert.throws(()=>macosAppShimServiceName('org.chromium.*','/private/profile'));
});
