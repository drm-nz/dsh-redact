/**
 * Known credential formats.
 *
 * Each entry declares a literal/regex prefix, the body character class, and the
 * body length vendors actually issue. Building the matcher from the declared
 * length keeps the rule and its documentation from drifting apart.
 *
 * Matching deliberately omits a trailing word boundary: if a credential is
 * pasted with text glued to it, the credential portion must still disappear.
 * The leading boundary is kept so a prefix inside a longer word is ignored.
 */

/**
 * @typedef {object} KnownCredential
 * @property {string} kind - redaction marker suffix.
 * @property {string} prefix - regex source for the fixed prefix.
 * @property {string} body - regex character class for the body.
 * @property {number} bodyLength - body length vendors issue.
 * @property {boolean} [atLeast] - accept longer bodies (variable-length formats).
 * @property {string} [note] - human description, including total length.
 */

/** @type {KnownCredential[]} */
export const KNOWN_CREDENTIALS = [
  { kind: "aws-access-key", prefix: "(?:AKIA|ASIA)", body: "[0-9A-Z]", bodyLength: 16, note: "AKIA/ASIA + 16 uppercase alphanumerics (20 chars)" },
  { kind: "github-token", prefix: "gh[pousr]_", body: "[A-Za-z0-9]", bodyLength: 36, note: "ghp_/gho_/ghu_/ghs_/ghr_ + 36 (40 chars)" },
  { kind: "github-pat", prefix: "github_pat_[A-Za-z0-9]{22}_", body: "[A-Za-z0-9]", bodyLength: 59, note: "github_pat_ + 22 + _ + 59 (93 chars)" },
  { kind: "gitlab-pat", prefix: "glpat-", body: "[A-Za-z0-9_-]", bodyLength: 20, note: "glpat- + 20 (26 chars)" },
  { kind: "openai-key", prefix: "sk-", body: "[A-Za-z0-9]", bodyLength: 48, note: "sk- + 48 (51 chars)" },
  { kind: "openai-project-key", prefix: "sk-proj-", body: "[A-Za-z0-9_-]", bodyLength: 40, atLeast: true, note: "sk-proj- + 40 or more" },
  { kind: "anthropic-key", prefix: "sk-ant-", body: "[A-Za-z0-9_-]", bodyLength: 20, atLeast: true, note: "sk-ant-… (>= 27 chars)" },
  { kind: "google-api-key", prefix: "AIza", body: "[0-9A-Za-z_-]", bodyLength: 35, note: "AIza + 35 (39 chars)" },
  { kind: "stripe-secret", prefix: "(?:sk|rk)_live_", body: "[0-9A-Za-z]", bodyLength: 24, note: "sk_live_/rk_live_ + 24 (32 chars)" },
  { kind: "twilio-key", prefix: "SK", body: "[0-9a-fA-F]", bodyLength: 32, note: "SK + 32 hex (34 chars)" },
  { kind: "sendgrid-key", prefix: "SG\\.[A-Za-z0-9_-]{22}\\.", body: "[A-Za-z0-9_-]", bodyLength: 43, note: "SG. + 22 + . + 43 (69 chars)" },
  { kind: "npm-token", prefix: "npm_", body: "[A-Za-z0-9]", bodyLength: 36, note: "npm_ + 36 (40 chars)" },
  { kind: "digitalocean-token", prefix: "dop_v1_", body: "[a-f0-9]", bodyLength: 64, note: "dop_v1_ + 64 hex (71 chars)" },
  { kind: "shopify-token", prefix: "shpat_", body: "[a-f0-9]", bodyLength: 32, note: "shpat_ + 32 hex (38 chars)" },
  { kind: "mailgun-key", prefix: "key-", body: "[a-f0-9]", bodyLength: 32, note: "key- + 32 hex (36 chars)" },
  { kind: "slack-token", prefix: "xox[baprs]-", body: "[0-9A-Za-z-]", bodyLength: 10, atLeast: true, note: "xox?-… (>= 16 chars)" }
];

/** Compile one declared format into a global RegExp. */
export function compileCredential(entry) {
  const quantifier = entry.atLeast ? `{${entry.bodyLength},}` : `{${entry.bodyLength}}`;
  return new RegExp(`\\b${entry.prefix}${entry.body}${quantifier}`, "g");
}

/** Compiled known-credential rules, each carrying its declared total length. */
export const KNOWN_CREDENTIAL_RULES = KNOWN_CREDENTIALS.map((entry) => ({
  kind: entry.kind,
  note: entry.note,
  bodyLength: entry.bodyLength,
  atLeast: entry.atLeast === true,
  re: compileCredential(entry)
}));

/** Credentials identified by structure rather than by a vendor prefix. */
export const STRUCTURAL_RULES = [
  {
    kind: "private-key",
    re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g
  },
  {
    kind: "jwt",
    re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g
  },
  {
    // Keep "Bearer " so the shape stays obvious; replace only the credential.
    kind: "bearer",
    re: /\b(Bearer\s+)([A-Za-z0-9._~+/=-]{16,})/gi,
    replace: (_match, prefix) => `${prefix}[REDACTED:bearer]`
  },
  {
    // scheme://user:password@host — redact the password only.
    kind: "url-userinfo",
    re: /\b([a-z][a-z0-9+.-]*:\/\/)([^\s:@/]+):([^\s@/]+)@/gi,
    replace: (_match, scheme, user) => `${scheme}${user}:[REDACTED:password]@`
  }
];

/**
 * Credentials with no distinguishing prefix, recognised only next to their
 * documented assignment name. Kept narrow on purpose: a bare 40-character
 * base64 string is far too common to redact on sight.
 */
export const CONTEXT_RULES = [
  {
    kind: "aws-secret-access-key",
    re: /\b(aws_secret_access_key|aws_session_token)(\s*[:=]\s*)(["']?)([A-Za-z0-9/+=]{32,})/gi,
    replace: (_match, name, separator, quote) => `${name}${separator}${quote}[REDACTED:aws-secret-access-key]`
  }
];
