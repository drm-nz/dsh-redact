/**
 * dsh-redact — host-only Cordis plugin.
 *
 * Redacts secrets from tool output before the result is persisted and sent to
 * the model. Tools keep full access to the environment and filesystem; only
 * the transcript is rewritten, so no workflow is restricted.
 *
 * Deliberately dependency-free: no host packages are imported, so the plugin
 * loads even if a future Harness release reshapes its internal module graph.
 */
import { appendFileSync } from "node:fs";
import { buildInventory, redactText, DEFAULT_ALLOW_NAMES } from "./redact.js";
import { selfCheck } from "./health.js";

/** Cordis plugin name. */
export const name = "dsh-redact";

/** Defaults applied when the profile supplies no config. */
export const DEFAULTS = {
  enabled: true,
  tiers: { exact: true, patterns: true, context: true, keywords: false },
  minLength: 8,
  allowNames: [...DEFAULT_ALLOW_NAMES],
  secrets: []
};

/**
 * Register the post-execute redaction.
 * @param ctx - plugin context.
 * @param raw - operator configuration (unvalidated object).
 */
export function apply(ctx, raw) {
  const config = {
    ...DEFAULTS,
    ...(raw ?? {}),
    tiers: { ...DEFAULTS.tiers, ...(raw?.tiers ?? {}) },
    allowNames: raw?.allowNames ?? DEFAULTS.allowNames,
    secrets: raw?.secrets ?? DEFAULTS.secrets,
    minLength: raw?.minLength ?? DEFAULTS.minLength
  };

  const inventory = buildInventory(process.env, {
    minLength: config.minLength,
    allowNames: config.allowNames,
    secrets: config.secrets
  });

  if (typeof raw?.debugFile === "string" && raw.debugFile.length > 0) {
    try {
      appendFileSync(raw.debugFile, `${new Date().toISOString()} apply inventory=${inventory.length} patterns=${config.tiers.patterns !== false}\n`);
    } catch {
      /* diagnostics only */
    }
  }

  ctx.logger?.info?.(
    "dsh-redact: active (%d exact-value rule(s), patterns=%s, keywords=%s)",
    inventory.length,
    String(config.tiers.patterns !== false),
    String(config.tiers.keywords === true)
  );

  // Boot probe: prove the matcher still redacts, and record it where it can be
  // read later. The host does not persist logger output, and this plugin fails
  // open, so without a written record a regression looks like "nothing to do".
  const health = selfCheck({ tiers: config.tiers, inventory, file: raw?.healthFile });
  if (health.status !== "ok") {
    ctx.logger?.error?.("dsh-redact: self-check %s (%s)", health.status, health.detail);
  }

  /** Redact one text block's string; returns undefined when nothing changed. */
  const redactString = (text) => {
    if (typeof text !== "string" || text.length === 0) return undefined;
    const out = redactText(text, { inventory, tiers: config.tiers });
    return out.hits.length === 0 ? undefined : out.text;
  };

  /**
   * Redact tool-result content, which tools may express either as a plain
   * string or as an array of content blocks (`[{ type: "text", text }]`).
   * Non-text blocks (images, attachments) pass through untouched.
   */
  const redactContent = (content) => {
    if (typeof content === "string") {
      const next = redactString(content);
      return next === undefined ? undefined : next;
    }
    if (!Array.isArray(content)) return undefined;
    let changed = false;
    const blocks = content.map((block) => {
      if (block === null || typeof block !== "object") return block;
      if (typeof block.text !== "string") return block;
      const next = redactString(block.text);
      if (next === undefined) return block;
      changed = true;
      return { ...block, text: next };
    });
    return changed ? blocks : undefined;
  };

  const debugFile = typeof raw?.debugFile === "string" && raw.debugFile.length > 0 ? raw.debugFile : undefined;
  const trace = (line) => {
    if (debugFile === undefined) return;
    try { appendFileSync(debugFile, line + "\n"); } catch { /* diagnostics only */ }
  };

  // `global` bypasses the agent-scope listener filter: the dispatch runs with
  // the agent's scoped context, which would otherwise exclude a top-level plugin.
  ctx.on("tools/post-execute", async (exec, result, next) => {
    const downstream = await next();
    const shape = Array.isArray(result?.content) ? "array" : typeof result?.content;
    trace(`hook ${String(exec?.name)} kind=${String(downstream?.kind)} content=${shape}`);
    if (config.enabled === false) return downstream;
    if (downstream === undefined || downstream === null) return downstream;
    if (downstream.kind === "block") return downstream;
    let content;
    try {
      content = redactContent(result?.content);
    } catch {
      return downstream;
    }
    trace(`  redacted=${content === undefined ? "no" : "yes"}`);
    if (content === undefined) return downstream;
    return { ...downstream, content };
  }, { global: true });
}

export default apply;
