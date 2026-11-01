/**
 * Pure redaction core for dsh-redact.
 *
 * Design: redact the transcript, never the process. These functions only ever
 * rewrite text destined for the model and the session log; they never touch
 * process state, the filesystem, or the environment.
 *
 * Tiers:
 *   1. exact    — known secret values from the environment / config
 *   2. patterns — known credential formats (prefix + vendor length) and
 *                 structural shapes (PEM, JWT, Bearer, URL userinfo)
 *   3. context  — credentials with no prefix, recognised beside their
 *                 documented assignment name (AWS secret/session token)
 *   4. keywords — keyword-anchored values, off by default
 */
import { KNOWN_CREDENTIAL_RULES, STRUCTURAL_RULES, CONTEXT_RULES } from "./credentials.js";

/** Environment variable names whose values are worth treating as secrets. */
export const DEFAULT_SENSITIVE_NAME = /(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|AUTH|DATABASE_URL|DB_URL|CONNECTION_STRING|DSN|PROXY|(?:^|_)PWD(?:$|_))/i;

/** Names that indicate a real credential even when the value looks like a path. */
const STRONG_SECRET_NAME = /(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL)/i;

/** Values that are locations rather than credentials (PWD, KUBECONFIG, …). */
const PATH_LIKE = /^(?:\/|~\/|[A-Za-z]:[\\/])/;

/** Names that look sensitive but whose values are locations, not secrets. */
export const DEFAULT_ALLOW_NAMES = ["SSH_AUTH_SOCK"];

const MARKER = (label) => `[REDACTED:${label}]`;

/**
 * Build the exact-value inventory.
 *
 * @param {Record<string, string | undefined>} env - environment to inspect.
 * @param {{ minLength?: number, allowNames?: string[], secrets?: string[], sensitiveName?: RegExp }} [options]
 * @returns {{ name: string, value: string }[]} unique values, longest first.
 */
export function buildInventory(env, options = {}) {
  const minLength = options.minLength ?? 8;
  const allow = new Set((options.allowNames ?? DEFAULT_ALLOW_NAMES).map((name) => name.toUpperCase()));
  const sensitive = options.sensitiveName ?? DEFAULT_SENSITIVE_NAME;
  const found = new Map();

  for (const [name, value] of Object.entries(env ?? {})) {
    if (typeof value !== "string" || value.length < minLength) continue;
    if (allow.has(name.toUpperCase())) continue;
    if (!sensitive.test(name)) continue;
    // A path is a location, not a secret: redacting it would mangle output
    // (PWD, OLDPWD, KUBECONFIG, …) without protecting anything.
    if (PATH_LIKE.test(value) && !STRONG_SECRET_NAME.test(name)) continue;
    if (!found.has(value)) found.set(value, name);
  }

  for (const [index, value] of (options.secrets ?? []).entries()) {
    if (typeof value !== "string" || value.length < minLength) continue;
    if (!found.has(value)) found.set(value, `config.secrets[${index}]`);
  }

  return [...found.entries()]
    .map(([value, name]) => ({ value, name }))
    .sort((left, right) => right.value.length - left.value.length);
}

/** Keyword-anchored rule, opt-in via tiers.keywords. */
const KEYWORD_RULE = {
  kind: "keyword-value",
  re: /\b(password|passwd|pwd|token|secret|api[_-]?key)\b(\s*[:=]\s*)(["']?)([^\s"'&,;]{8,})/gi,
  replace: (_match, keyword, separator, quote) => `${keyword}${separator}${quote}${MARKER("value")}`
};

/**
 * Apply one rule list to `text`, collecting hit kinds.
 * @returns {{ text: string, hits: { kind: string }[] }}
 */
function applyRules(text, rules, hits) {
  let out = text;
  for (const rule of rules) {
    out = out.replace(rule.re, (...args) => {
      hits.push({ kind: rule.kind });
      if (rule.replace) return rule.replace(...args);
      return MARKER(rule.kind);
    });
  }
  return { text: out, hits };
}

/**
 * Redact one string.
 *
 * @param {string} text - model-visible text.
 * @param {{ inventory?: { name: string, value: string }[], tiers?: { exact?: boolean, patterns?: boolean, context?: boolean, keywords?: boolean } }} [options]
 * @returns {{ text: string, hits: { kind: string, name?: string }[] }}
 */
export function redactText(text, options = {}) {
  if (typeof text !== "string" || text.length === 0) return { text, hits: [] };
  const tiers = { exact: true, patterns: true, context: true, keywords: false, ...(options.tiers ?? {}) };
  const hits = [];
  let out = text;

  if (tiers.exact) {
    for (const { name, value } of options.inventory ?? []) {
      if (!out.includes(value)) continue;
      out = out.split(value).join(MARKER(name));
      hits.push({ kind: "exact", name });
    }
  }

  if (tiers.patterns) {
    out = applyRules(out, KNOWN_CREDENTIAL_RULES, hits).text;
    out = applyRules(out, STRUCTURAL_RULES, hits).text;
  }

  if (tiers.context) {
    out = applyRules(out, CONTEXT_RULES, hits).text;
  }

  if (tiers.keywords) {
    out = applyRules(out, [KEYWORD_RULE], hits).text;
  }

  return { text: out, hits };
}

/** Exposed for tests and documentation. */
export const internals = { KNOWN_CREDENTIAL_RULES, STRUCTURAL_RULES, CONTEXT_RULES, KEYWORD_RULE, MARKER };
