import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

test("write-enabled MCP catalog exposes video upload without changing existing tools", async () => {
  const entrypoint = fileURLToPath(new URL("../index.js", import.meta.url));
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entrypoint],
    env: {
      ...process.env,
      META_ADS_ACCESS_TOKEN: "test-token",
      META_ADS_ENABLE_WRITE_TOOLS: "true",
    },
    stderr: "pipe",
  });
  const client = new Client({ name: "catalog-test", version: "1.0.0" });

  try {
    await client.connect(transport);
    const catalog = await client.listTools();
    assert.equal(catalog.tools.length, 55);
    assert.ok(catalog.tools.some((tool) => tool.name === "meta_ads_upload_ad_image"));
    const videoUpload = catalog.tools.find(
      (tool) => tool.name === "meta_ads_upload_ad_video"
    );
    assert.ok(videoUpload);
    assert.deepEqual(videoUpload.inputSchema.required, ["act_id", "video_url"]);
  } finally {
    await client.close();
  }
});
