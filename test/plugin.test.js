import { test } from "node:test";
import assert from "node:assert/strict";
import { apply, DEFAULTS } from "../lib/index.js";

/** Minimal Cordis-like context that captures the post-execute handler. */
function fakeCtx() {
  const handlers = [];
  return {
    handlers,
    on(event, handler, options) {
      if (event === "tools/post-execute") handlers.push({ handler, options });
    },
    logger: { info() {} }
  };
}

/**
 * Invoke the hook the way the tools pipeline does: (exec, result, next),
 * where `result` carries the content and `next` resolves the decision.
 */
async function run(content, config = {}) {
  const ctx = fakeCtx();
  apply(ctx, config);
  const entry = ctx.handlers[0];
  assert.ok(entry, "post-execute handler registered");
  const result = { kind: "accept", content };
  const decision = { kind: "accept" };
  const out = await entry.handler({ name: "bash" }, result, async () => decision);
  return { out, result, decision, entry };
}

test("registers one post-execute handler with global scope", () => {
  const ctx = fakeCtx();
  apply(ctx, {});
  assert.equal(ctx.handlers.length, 1);
  assert.deepEqual(ctx.handlers[0].options, { global: true });
});

test("redacts a string result and keeps the rest", async () => {
  const { out } = await run("aws=AKIAIOSFODNN7EXAMPLE\nnormal=hello-world");
  assert.ok(!out.content.includes("AKIAIOSFODNN7EXAMPLE"));
  assert.ok(out.content.includes("[REDACTED:aws-access-key]"));
  assert.ok(out.content.includes("normal=hello-world"));
});

test("redacts block-array content and leaves other blocks alone", async () => {
  const content = [
    { type: "text", text: "aws=AKIAIOSFODNN7EXAMPLE" },
    { type: "image", url: "file:///tmp/x.png" }
  ];
  const { out } = await run(content);
  assert.ok(out.content[0].text.includes("[REDACTED:aws-access-key]"));
  assert.deepEqual(out.content[1], content[1]);
});

test("leaves clean content untouched (returns the decision itself)", async () => {
  const { out, decision } = await run("hello-world");
  assert.equal(out, decision);
});

test("leaves clean block arrays untouched", async () => {
  const { out, decision } = await run([{ type: "text", text: "hello" }]);
  assert.equal(out, decision);
});

test("passes blocked results through unchanged", async () => {
  const ctx = fakeCtx();
  apply(ctx, {});
  const entry = ctx.handlers[0];
  const blocked = { kind: "block", feedback: "AKIAIOSFODNN7EXAMPLE" };
  const out = await entry.handler({}, { kind: "accept", content: "AKIAIOSFODNN7EXAMPLE" }, async () => blocked);
  assert.equal(out, blocked);
});

test("enabled:false disables redaction", async () => {
  const { out, decision } = await run("AKIAIOSFODNN7EXAMPLE", { enabled: false });
  assert.equal(out, decision);
});

test("keywords tier is off by default and can be enabled", async () => {
  const off = await run("password=hunter2hunter2");
  assert.equal(off.out, off.decision);
  const on = await run("password=hunter2hunter2", { tiers: { keywords: true } });
  assert.ok(on.out.content.includes("[REDACTED:value]"));
});

test("DEFAULTS are sane", () => {
  assert.equal(DEFAULTS.enabled, true);
  assert.deepEqual(DEFAULTS.tiers, { exact: true, patterns: true, context: true, keywords: false });
});
