import { test } from "node:test";
import assert from "node:assert/strict";
import { buildInventory, redactText, internals } from "../lib/redact.js";

const rep = (ch, n) => ch.repeat(n);

/** Every known format with a sample of the documented length. */
const SAMPLES = [
  ["aws-access-key", `AKIA${rep("A", 16)}`],
  ["github-token", `ghp_${rep("a", 36)}`],
  ["github-pat", `github_pat_${rep("a", 22)}_${rep("b", 59)}`],
  ["gitlab-pat", `glpat-${rep("a", 20)}`],
  ["openai-key", `sk-${rep("a", 48)}`],
  ["openai-project-key", `sk-proj-${rep("a", 40)}`],
  ["anthropic-key", `sk-ant-${rep("a", 20)}`],
  ["google-api-key", `AIza${rep("a", 35)}`],
  ["stripe-secret", `sk_live_${rep("a", 24)}`],
  ["twilio-key", `SK${rep("a", 32)}`],
  ["sendgrid-key", `SG.${rep("a", 22)}.${rep("b", 43)}`],
  ["npm-token", `npm_${rep("a", 36)}`],
  ["digitalocean-token", `dop_v1_${rep("a", 64)}`],
  ["shopify-token", `shpat_${rep("a", 32)}`],
  ["mailgun-key", `key-${rep("a", 32)}`],
  ["slack-token", `xoxb-${rep("a", 20)}`]
];

for (const [kind, sample] of SAMPLES) {
  test(`catalog: ${kind} is redacted at its documented length`, () => {
    const { text, hits } = redactText(`value=${sample}`);
    assert.ok(text.includes(`[REDACTED:${kind}]`), text);
    assert.ok(!text.includes(sample), "original credential must not survive");
    assert.ok(hits.some((hit) => hit.kind === kind));
  });
}

test("catalog: declared lengths match the compiled samples", () => {
  for (const [kind, sample] of SAMPLES) {
    const rule = internals.KNOWN_CREDENTIAL_RULES.find((entry) => entry.kind === kind);
    assert.ok(rule, `missing rule ${kind}`);
    const match = redactText(sample).hits.some((hit) => hit.kind === kind);
    assert.ok(match, `${kind} sample of length ${sample.length} did not match`);
  }
});

test("catalog: short lookalikes are not redacted", () => {
  for (const input of ["AKIA1234", "ghp_short", "sk-abc", "AIza123", "glpat-x"]) {
    assert.equal(redactText(input).text, input);
  }
});

test("catalog: slack accepts longer variable-length tokens", () => {
  const long = `xoxb-${rep("a", 40)}`;
  assert.ok(redactText(long).text.includes("[REDACTED:slack-token]"));
});

test("catalog: glued suffix still redacts the credential portion", () => {
  const { text } = redactText(`probe=AKIA${rep("A", 16)}SOMETHING`);
  assert.equal(text, "probe=[REDACTED:aws-access-key]SOMETHING");
});

test("structural: PEM, JWT, Bearer, URL userinfo", () => {
  const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n-----END RSA PRIVATE KEY-----";
  assert.ok(redactText(pem).text.includes("[REDACTED:private-key]"));
  assert.ok(redactText("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcdefghijklmnop").text.includes("[REDACTED:jwt]"));
  assert.ok(redactText("Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345").text.includes("[REDACTED:bearer]"));
  assert.equal(
    redactText("postgres://alice:hunter2@db.local:5432/app").text,
    "postgres://alice:[REDACTED:password]@db.local:5432/app"
  );
});

test("context: aws secret only beside its assignment name", () => {
  const secret = rep("A", 40);
  assert.ok(redactText(`aws_secret_access_key=${secret}`).text.includes("[REDACTED:aws-secret-access-key]"));
  assert.equal(redactText(secret).text, secret);
});

test("exact: known env values, longest first, allowNames skipped", () => {
  const inventory = buildInventory({ DATABASE_URL: "postgres://u:p4ssw0rd@db.local/app" });
  assert.equal(
    redactText("connecting to postgres://u:p4ssw0rd@db.local/app now", { inventory }).text,
    "connecting to [REDACTED:DATABASE_URL] now"
  );
  assert.deepEqual(buildInventory({ SSH_AUTH_SOCK: "/tmp/ssh-agent.sock" }), []);
});

test("paths are not treated as secrets (PWD, OLDPWD, KUBECONFIG)", () => {
  assert.deepEqual(buildInventory({
    PWD: "/Users/someone/projects/app",
    OLDPWD: "/Users/someone",
    KUBECONFIG: "/Users/someone/.kube/config"
  }), []);
});

test("MYSQL_PWD is a password, not a path", () => {
  assert.equal(buildInventory({ MYSQL_PWD: "sup3rs3cret" }).length, 1);
});

test("hashes and UUIDs are untouched", () => {
  const sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
  const uuid = "123e4567-e89b-12d3-a456-426614174000";
  const { text, hits } = redactText(`${sha} ${uuid}`);
  assert.equal(text, `${sha} ${uuid}`);
  assert.equal(hits.length, 0);
});

test("tiers can be disabled individually", () => {
  const sample = `AKIA${rep("A", 16)}`;
  const off = redactText(sample, { tiers: { patterns: false } });
  assert.equal(off.text, sample);
});

test("keywords tier is off by default and can be enabled", () => {
  const input = "password=hunter2hunter2";
  assert.equal(redactText(input).text, input);
  assert.equal(redactText(input, { tiers: { keywords: true } }).text, "password=[REDACTED:value]");
});
