import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { evaluate, report, selfCheck, DEFAULT_HEALTH_FILE } from "../lib/health.js";

const sandbox = () => mkdtempSync(join(tmpdir(), "dsh-redact-health-"));

test("evaluate passes the pattern probe when patterns are on", () => {
  const { status, detail } = evaluate({ patterns: true, exact: true }, []);
  assert.equal(status, "ok");
  assert.match(detail, /probe=patterns redacted=yes/);
});

test("evaluate uses the exact probe when patterns are disabled", () => {
  const { status, detail } = evaluate({ patterns: false, exact: true }, []);
  assert.equal(status, "ok");
  assert.match(detail, /probe=exact redacted=yes/);
});

test("evaluate reports probe=off rather than a false failure when every tier is off", () => {
  const { status, detail } = evaluate({ patterns: false, exact: false }, []);
  assert.equal(status, "ok");
  assert.match(detail, /probe=off/);
});

test("evaluate counts the inventory as rules", () => {
  const inventory = [
    { name: "A_KEY", value: "aaaaaaaaaaaa" },
    { name: "B_KEY", value: "bbbbbbbbbbbb" }
  ];
  assert.match(evaluate({}, inventory).detail, /rules=2/);
});

test("report appends one aligned line", () => {
  const file = join(sandbox(), "health.log");
  assert.equal(report({ status: "ok", detail: "rules=3 probe=patterns redacted=yes" }, { file }), true);
  const lines = readFileSync(file, "utf8").trim().split("\n");
  assert.equal(lines.length, 1);
  assert.match(
    lines[0],
    /^\d{4}-\d{2}-\d{2}T[\d:.]+Z dsh-redact +ok +rules=3 probe=patterns redacted=yes$/
  );
});

test("report appends rather than truncating", () => {
  const file = join(sandbox(), "health.log");
  report({ status: "ok", detail: "a" }, { file });
  report({ status: "ok", detail: "b" }, { file });
  assert.equal(readFileSync(file, "utf8").trim().split("\n").length, 2);
});

test("report creates a missing directory", () => {
  const file = join(sandbox(), "nested", "deeper", "health.log");
  assert.equal(report({ status: "ok", detail: "x" }, { file }), true);
  assert.match(readFileSync(file, "utf8"), /x/);
});

test("report never throws when the path is unwritable", () => {
  const sandboxDir = sandbox();
  const blocker = join(sandboxDir, "blocking-file");
  writeFileSync(blocker, "not a directory");
  // Parent is a regular file, so mkdirSync/appendFileSync must fail internally.
  assert.equal(report({ status: "ok", detail: "x" }, { file: join(blocker, "health.log") }), false);
});

test("report honours DSH_HEALTH_LOG", () => {
  const file = join(sandbox(), "env.log");
  const previous = process.env.DSH_HEALTH_LOG;
  process.env.DSH_HEALTH_LOG = file;
  try {
    report({ status: "ok", detail: "env" });
    assert.match(readFileSync(file, "utf8"), /env/);
  } finally {
    if (previous === undefined) delete process.env.DSH_HEALTH_LOG;
    else process.env.DSH_HEALTH_LOG = previous;
  }
});

test("selfCheck evaluates and records in one call", () => {
  const file = join(sandbox(), "health.log");
  const result = selfCheck({ tiers: { patterns: true }, inventory: [], file });
  assert.equal(result.status, "ok");
  assert.match(readFileSync(file, "utf8"), /dsh-redact +ok/);
});

test("default path is under the DSH home", () => {
  assert.match(DEFAULT_HEALTH_FILE, /\.dsh[\\/]health\.log$/);
});
