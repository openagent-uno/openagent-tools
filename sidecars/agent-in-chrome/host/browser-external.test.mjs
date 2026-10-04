import assert from "node:assert/strict";
import test from "node:test";
import { closeDedicatedBrowser } from "./browser.js";

test("closing an externally supervised MCP leaves its Chrome service running", async () => {
  const previous = process.env.OPENAGENT_BROWSER_EXTERNAL;
  process.env.OPENAGENT_BROWSER_EXTERNAL = "1";
  const requests = [];
  let disconnected = false;
  try {
    const result = await closeDedicatedBrowser({
      closed: false,
      async send(method) { requests.push(method); },
      close() { disconnected = true; },
    }, { ownsBrowser: false, port: 65534, timeoutMs: 0 });
    assert.equal(result, true);
    assert.equal(disconnected, true);
    assert.deepEqual(requests, []);
  } finally {
    if (previous === undefined) delete process.env.OPENAGENT_BROWSER_EXTERNAL;
    else process.env.OPENAGENT_BROWSER_EXTERNAL = previous;
  }
});
