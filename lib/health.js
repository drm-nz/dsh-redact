/**
 * Startup self-check for dsh-redact.
 *
 * Why this exists: the plugin fails open by design. A rule set that stops
 * matching, or a hook that never fires, produces exactly the same observable
 * behaviour as "nothing needed redacting". The host does not persist logger
 * output to disk, so a silent regression would never be seen.
 *
 * What it proves: the matcher still works on the text shape the hook receives,
 * at boot, with no tool call and no cost. What it cannot prove: that the hook
 * itself is invoked — that needs a live agent tool call.
 */
import { appendFileSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { redactText } from "./redact.js";

/** Shared health log; both custom plugins append to it. */
export const DEFAULT_HEALTH_FILE = join(homedir(), ".dsh", "health.log");

/** Plugin name as it appears in the log, padded so lines from both plugins align. */
export const NAME = "dsh-redact";

/** Synthetic credential in the declared github-token shape: prefix + 36 body. */
const PATTERN_PROBE = `ghp_${"a".repeat(36)}`;

/** Synthetic value used to exercise the exact tier when patterns are disabled. */
const EXACT_PROBE = "dsh-redact-self-check-value";

/**
 * Probe whichever tier is enabled, so an intentionally disabled tier is not
 * reported as a failure.
 *
 * @param {{ exact?: boolean, patterns?: boolean }} tiers
 * @param {{ name: string, value: string }[]} inventory
 * @returns {{ status: "ok" | "fail", detail: string }}
 */
export function evaluate(tiers = {}, inventory = []) {
  if (tiers.patterns !== false) {
    const { hits } = redactText(`probe=${PATTERN_PROBE}`, { tiers, inventory });
    const redacted = hits.some((hit) => hit.kind === "github-token");
    return {
      status: redacted ? "ok" : "fail",
      detail: `rules=${inventory.length} probe=patterns redacted=${redacted ? "yes" : "no"}`
    };
  }
  if (tiers.exact !== false) {
    const values = [...inventory, { name: "self-check", value: EXACT_PROBE }];
    const { hits } = redactText(`probe=${EXACT_PROBE}`, { tiers, inventory: values });
    return {
      status: hits.length > 0 ? "ok" : "fail",
      detail: `rules=${inventory.length} probe=exact redacted=${hits.length > 0 ? "yes" : "no"}`
    };
  }
  return { status: "ok", detail: `rules=${inventory.length} probe=off` };
}

/**
 * Append one health line. Never throws: a diagnostics failure must not stop the
 * plugin from loading.
 *
 * @param {{ status: string, detail: string }} result
 * @param {{ file?: string, now?: () => string }} [options]
 * @returns {boolean} whether the line was written.
 */
export function report(result, options = {}) {
  const file = options.file ?? process.env.DSH_HEALTH_LOG ?? DEFAULT_HEALTH_FILE;
  const stamp = (options.now ?? (() => new Date().toISOString()))();
  try {
    mkdirSync(dirname(file), { recursive: true });
    appendFileSync(file, `${stamp} ${NAME.padEnd(18)} ${result.status.padEnd(4)} ${result.detail}\n`);
    return true;
  } catch {
    return false;
  }
}

/**
 * Evaluate the probe and record it.
 *
 * @param {{ tiers?: object, inventory?: { name: string, value: string }[], file?: string, now?: () => string }} [options]
 * @returns {{ status: "ok" | "fail", detail: string }}
 */
export function selfCheck(options = {}) {
  let result;
  try {
    result = evaluate(options.tiers ?? {}, options.inventory ?? []);
  } catch (error) {
    result = { status: "fail", detail: `probe=threw error=${error instanceof Error ? error.message : String(error)}` };
  }
  report(result, { file: options.file, now: options.now });
  return result;
}
