# dsh-redact

Redacts secrets from tool output before it reaches the model or the session log.

An agent's transcript is written to disk and sent to a model provider on every turn.
That transcript quietly fills up with credentials: `env` output, a `cat .env`, a
`git remote -v` with a token in the URL, a connection string in a stack trace. This
plugin rewrites that copy in place, so the transcript is safe to keep and share while
the tools themselves keep full access.

**Design principle: redact the transcript, never the process.**

```
tool executes ──► result content ──► tools/post-execute hook ──► model + session log
    full access                        (this plugin)                [REDACTED:NAME]
```

Nothing is blocked, no command is rewritten, and no permission is reduced. Only the
text destined for the model and the saved session is altered.

## What it catches

Four tiers, each independently switchable.

| Tier | Default | Catches |
|---|---|---|
| `exact` | on | Values of sensitive-looking environment variables (`DATABASE_URL`, `MYSQL_PWD`, proxy URLs, …) plus any `secrets` you configure |
| `patterns` | on | Known credential formats (below), PEM private keys, JWTs, `Bearer …` headers, and URL userinfo passwords |
| `context` | on | Prefix-less credentials recognised only beside their documented name (AWS secret/session tokens) |
| `keywords` | off | `password=`, `token=`, `api_key=` anchored values. Opt-in: higher false-positive risk |

### Recognised credential formats

Rules are generated from a declared prefix, body character class, and the length
vendors actually issue, so the matcher cannot drift away from this table.

| Format | Prefix | Body length |
|---|---|---|
| `aws-access-key` | `AKIA` / `ASIA` | 16 |
| `github-token` | `gh[pousr]_` | 36 |
| `github-pat` | `github_pat_` + 22 + `_` | 59 |
| `gitlab-pat` | `glpat-` | 20 |
| `openai-key` | `sk-` | 48 |
| `openai-project-key` | `sk-proj-` | ≥ 40 |
| `anthropic-key` | `sk-ant-` | ≥ 20 |
| `google-api-key` | `AIza` | 35 |
| `stripe-secret` | `sk_live_` / `rk_live_` | 24 |
| `twilio-key` | `SK` | 32 hex |
| `sendgrid-key` | `SG.` + 22 + `.` | 43 |
| `npm-token` | `npm_` | 36 |
| `digitalocean-token` | `dop_v1_` | 64 hex |
| `shopify-token` | `shpat_` | 32 hex |
| `mailgun-key` | `key-` | 32 hex |
| `slack-token` | `xox[baprs]-` | ≥ 10 |

Matching deliberately omits a trailing word boundary: a credential pasted with text
glued to it still loses its credential portion. A lookalike that is too short is left
alone. Unknown formats are out of scope by design — the `exact` tier is what covers
secrets without a recognisable shape.

Path-like values (`PWD`, `OLDPWD`, `KUBECONFIG`) are never redacted unless the
variable name strongly indicates a credential (`MYSQL_PWD` is a password; `PWD` is
not), so ordinary output stays readable.

## What it does not do

Worth knowing before you rely on it:

- **It redacts, it does not revoke.** If a secret already reached a provider, this
  plugin does not un-send it.
- **Only tool output is covered.** Model-authored text, prompts, your shell history,
  and the application's own log files are outside the hook.
- **The `exact` tier is snapshotted at startup** from the environment the plugin loads
  in. A variable exported later is not picked up until restart.
- **Values shorter than `minLength`** (default 8) are ignored, to avoid redacting
  ordinary words.
- **It cannot recognise what it has no rule for.** Base64-wrapped, split, or
  re-encoded secrets pass through. Coverage is a net, not a guarantee.
- **No network access and no process mutation.** It reads text and returns text; the
  only write is an optional diagnostic line to `debugFile`.

## Install

Requires a [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) install
with the plugin manager. The package has **zero runtime dependencies**, so it does not
need the Harness package graph to import.

### From GitHub (recommended)

```sh
dsh plugin --profile desktop add github:drm-nz/dsh-redact
```

The plugin manager verifies the repository, installs it, and selects it into the
profile's bundle list. Host plugins load at boot, so **restart the app** afterwards.
The plugin then appears in **Settings → Plugins**, enabled by default.

To remove it:

```sh
dsh plugin --profile desktop remove dsh-redact
```

### From a local checkout

Add the dependency to the profile's `package.json`:

```jsonc
{
  "dependencies": { "dsh-redact": "link:/absolute/path/to/dsh-redact" },
  "dsh": { "profile": { "bundles": ["dsh-redact"] } }
}
```

Then run `pnpm install` in the profile directory and restart.

The shipped `cordis.patch.yml` names its entry relatively (`./lib/index.js`) on
purpose. A `link:` install's real directory sits outside `node_modules`, where a bare
package name resolves through a dependency mapping that does not exist there; a
relative name resolves beside the patch in every install shape. This is safe here
only because the plugin imports nothing from the Harness — a plugin that imports
Harness packages must be named bare instead.

## Configure

Override the bundle's row by id in the profile's `cordis.patch.yml`. Use an override,
not a second `insert` — inserting again would declare the row twice.

```yaml
- id: dsh-redact
  config:
    enabled: true
    tiers:
      exact: true
      patterns: true
      context: true
      keywords: false
    minLength: 8
    allowNames: ["SSH_AUTH_SOCK"]
    secrets: []
    # debugFile: /tmp/dsh-redact.log  # optional: one line per hook call
```

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Master switch; `false` returns every result untouched |
| `tiers.exact` | `true` | Redact known secret values from the environment and `secrets` |
| `tiers.patterns` | `true` | Redact known formats and structural shapes |
| `tiers.context` | `true` | Redact name-anchored credentials |
| `tiers.keywords` | `false` | Redact keyword-anchored values (noisy) |
| `minLength` | `8` | Shortest value considered a secret |
| `allowNames` | `["SSH_AUTH_SOCK"]` | Variable names to skip even when their value looks sensitive |
| `secrets` | `[]` | Extra literal values to redact, for anything the environment does not expose |

A secret present in both the environment and `secrets` is redacted once, labelled with
the environment variable's name. Values are matched longest-first, so a longer secret
is replaced before a shorter one that is a substring of it.

## Verify it works

Ask the agent to run something that prints a fresh token, then read the session log:
the value should appear as `[REDACTED:NAME]`. The hook also logs a one-line summary at
startup:

```
dsh-redact: active (12 exact-value rule(s), patterns=true, keywords=false)
```

## Tests

```sh
node --test test/
```

37 tests covering every declared format, the structural rules, the exact tier's
longest-first replacement, path-versus-secret classification, and the hook's behaviour
on string content, block arrays, blocked results, and each tier toggle.

Every fixture in the suite is synthetic: format-valid values built from repeated
fillers, published vendor documentation examples, and `example`-style hosts. None is,
or was derived from, a live credential.

## Layout

| Path | Purpose |
|---|---|
| `lib/index.js` | Cordis plugin; registers the `tools/post-execute` hook |
| `lib/redact.js` | Pure redaction core: inventory, tiers, text rewriting |
| `lib/credentials.js` | Declared credential formats and structural rules |
| `test/` | Unit tests and hook tests |

## License

MIT.
