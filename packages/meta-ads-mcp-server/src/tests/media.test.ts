import assert from "node:assert/strict";
import test from "node:test";

import { normalizeAdVideoUrl } from "../tools/media.js";

test("keeps a public HTTPS video URL unchanged", () => {
  assert.equal(
    normalizeAdVideoUrl("https://cdn.example.com/video.mp4"),
    "https://cdn.example.com/video.mp4"
  );
});

test("converts a Google Drive sharing path into a direct download URL", () => {
  assert.equal(
    normalizeAdVideoUrl("https://drive.google.com/file/d/abc_DEF-123/view?usp=sharing"),
    "https://drive.usercontent.google.com/download?id=abc_DEF-123&export=download&confirm=t"
  );
});

test("converts a Google Drive query ID into a direct download URL", () => {
  assert.equal(
    normalizeAdVideoUrl("https://drive.google.com/open?id=abc_DEF-123"),
    "https://drive.usercontent.google.com/download?id=abc_DEF-123&export=download&confirm=t"
  );
});

test("rejects Drive URLs without a file ID", () => {
  assert.throws(
    () => normalizeAdVideoUrl("https://drive.google.com/drive/folders/example"),
    /does not contain a file ID/
  );
});

test("rejects non-HTTP URLs", () => {
  assert.throws(() => normalizeAdVideoUrl("file:///tmp/video.mp4"), /http or https/);
});
