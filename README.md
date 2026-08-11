# pi-share-hf

Publish [pi](https://pi.dev) coding agent sessions from one OSS project to a Hugging Face dataset.

It is an incremental pipeline for:

1. collecting sessions for one project
2. redacting exact secrets from your env file and `--secret`
3. rejecting sessions that match user-provided deny patterns via `--deny`
4. scanning redacted output with [TruffleHog](https://github.com/trufflesecurity/trufflehog) to detect and verify surviving secrets
5. running LLM review on the remaining sessions
6. uploading only sessions that pass all checks

Use it if you want to:

- publish a public dataset of your pi traces
- share real agent traces for analysis or training data
- keep project-specific sessions on Hugging Face over time without reprocessing everything on every run

It keeps state in a workspace, so repeated runs only process what changed (updated sessions, new sessions).

## Supported input

- [pi](https://pi.dev) coding agent session files
- session format: https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/docs/session.md

## Install

```bash
npm install -g pi-share-hf
npm install -g @mariozechner/pi-coding-agent
```

Install TruffleHog:

```bash
brew install trufflehog
```

For Linux and Windows, use the upstream install instructions:

- https://github.com/trufflesecurity/trufflehog

For Hugging Face auth, create a write token and either:

```bash
export HF_TOKEN=hf_xxx
```

or save it to:

```text
~/.cache/huggingface/token
```

The CLI checks startup requirements and exits with install or auth instructions if something is missing.

## Workflow

Use one workspace per OSS project. In your OSS project directory:

1. add `.pi/hf-sessions/` to `.gitignore`
2. run `pi-share-hf init` once
3. run `pi-share-hf collect` to gather changed and new sessions, redact known secrets, filter by `--deny`, scan with TruffleHog, and run LLM review
4. inspect what would be uploaded with `pi-share-hf list --uploadable`, `pi-share-hf grep`, and the images folder if images are enabled
5. reject anything you do not want published
6. run `pi-share-hf upload`
7. repeat from step 3 whenever you want to publish new sessions

The workspace is incremental. It keeps the collected state so repeated runs only process what changed.

You can use pi-share-hf on multiple machines for the same project.

## Quick start

Inside your OSS project:

```bash
cd /path/to/my-project
echo ".pi/hf-sessions/" >> .gitignore
```

Initialize once:

```bash
# personal namespace
pi-share-hf init --repo myuser/my-project-sessions

# or org namespace
pi-share-hf init --repo my-project-sessions --organization myorg
```

Collect sessions:

```bash
pi-share-hf collect \
  --secret secrets.txt \
  --deny deny.txt \
  --provider openai-codex --model gpt-5.4 --thinking medium \
  --parallel 4 \
  README.md AGENTS.md
```

Recommended inputs:

- `secrets.txt`: one known secret per line. Generate it just before `collect`, do not commit it, and delete it after use.
- `deny.txt`: one regex per line for names, topics, or projects that should never be published
- `README.md AGENTS.md`: project context for the LLM review so it can distinguish OSS work from unrelated work

You can also repeat flags directly:

- `--secret <file>` or `--secret <literal>`
- `--deny <file>` or `--deny <regex>`

If you do not want a secrets file on disk, pass repeated `--secret <literal>` values instead.

Check what would be uploaded:

```bash
pi-share-hf list --uploadable
```

Search only the uploadable set:

```bash
pi-share-hf grep -i 'my-private-project|counterparty-name|finance'
```

Reject anything you do not want published:

```bash
pi-share-hf reject 2026-01-16T11-03-04-216Z_b8b30402-d134-4f0d-9e6e-e2f72ada5a2f.jsonl
```

Upload:

```bash
pi-share-hf upload --dry-run
pi-share-hf upload
```

## What deterministic redaction does

It only knows exact secret values.

Sources:

- `--env-file` (default: `~/.zshrc`)
- `--secret <file>` with one secret per line
- `--secret <literal>`

This is deliberate. Exact values are high precision. Generic token regexes are noisy. TruffleHog handles generic secret detection after redaction.

## What TruffleHog does here

TruffleHog scans the redacted output, not the original raw session.

That means:

- exact secrets should already be gone
- TruffleHog acts as a backstop for anything secret-like that survived

Any TruffleHog finding blocks the session automatically.

That includes:

- `verified`
- `unverified`
- `unknown`

So you do not need to manually inspect TruffleHog hits to decide whether a session is uploadable. The reports are there for debugging, auditing, and understanding why a session was blocked.

Per-session TruffleHog reports are stored in:

```text
.pi/hf-sessions/reports/<session>.trufflehog.json
```

Example:

```json
{
  "file": "...jsonl",
  "redacted_hash": "sha256:...",
  "findings": [
    {
      "detector": "NpmToken",
      "status": "verified",
      "line": 132,
      "raw_sha256": "sha256:...",
      "masked": "npm_tnl0***x4eE",
      "verification_from_cache": false
    }
  ],
  "summary": {
    "findings": 1,
    "verified": 1,
    "unverified": 0,
    "unknown": 0,
    "top_detectors": ["NpmToken"]
  }
}
```

## What the LLM review does

The LLM sees project context files plus a plain-text transcript of the redacted session.

It answers:

- is this about the target OSS project?
- is it fit to publish publicly?
- does it still appear to contain sensitive data?

Review output includes:

- `about_project`: `yes | no | mixed`
- `shareable`: `yes | no | manual_review`
- `missed_sensitive_data`: `yes | no | maybe`
- `flagged_parts`
- `summary`

Review files are stored in:

```text
.pi/hf-sessions/review/<session>.review.json
```

Changing provider, model, or thinking level changes the review cache key. The key includes the redacted session hash, context file hashes, provider, model, thinking level, deny-pattern hash, prompt version, and chunk size. If you rerun review with different settings, existing review sidecars for those sessions are replaced.

## What `upload` does

`upload` pushes only sessions that passed deterministic checks, TruffleHog, and LLM review.

It skips sessions that are manually rejected, missing review data, failed review, or already unchanged on the remote dataset.

Use `upload --dry-run` first if you want counts without pushing anything.

## Review before upload

Before uploading, inspect what is currently uploadable:

```bash
pi-share-hf list --uploadable
```

Useful checks:

- search the uploadable set with `pi-share-hf grep`
- review `deny.txt` and rerun `collect` if you discover a new never-publish topic
- inspect `.pi/hf-sessions/images/` when image preservation is enabled
- inspect `.pi/hf-sessions/reports/*.trufflehog.json` only if you want to debug or audit why a session was blocked by TruffleHog
- reject anything suspicious manually with `pi-share-hf reject`

Typical grep checks:

```bash
pi-share-hf grep -i 'private-project|counterparty|finance|agreement|royalt'
pi-share-hf grep -i 'gmail|calendar|drive|slack'
```

## Commands

### `init`

Creates `.pi/hf-sessions/`, writes `workspace.json`, and records which project directory maps to which Hugging Face dataset repo.

By default it uses:

- current directory as `--cwd`
- `.pi/hf-sessions` as `--workspace`
- preserved embedded images
- stripped encrypted reasoning signatures (`thinkingSignature`, `thoughtSignature`, `textSignature`)

Signatures are stripped by default because they are client-side encrypted reasoning payloads that cannot be sanitized by secret redaction.

```bash
pi-share-hf init --repo user/dataset
pi-share-hf init --repo dataset-name --organization myorg
```

Main options:

- `--cwd <dir>` project directory to map to pi session storage
- `--repo <id>` HF dataset repo
- `--organization <name>` optional namespace when `--repo` is a bare name
- `--workspace <dir>` workspace dir, default `.pi/hf-sessions`
- `--no-images` strip embedded images from redacted output
- `--keep-signatures` keep encrypted reasoning signature fields in redacted output (default: stripped)

### `collect`

Collects sessions for the configured project, redacts literal secrets, runs TruffleHog on changed redacted files, and runs the LLM review to write or update review sidecars.

By default it uses:

- `.pi/hf-sessions` as `--workspace`
- `~/.zshrc` as `--env-file`
- `README.md` and `AGENTS.md` as context files when present
- current pi settings unless you override provider, model, or thinking

```bash
pi-share-hf collect [context-files...]
```

Main options:

- `--workspace <dir>` workspace, default `.pi/hf-sessions`
- `--env-file <path>` secret source file, default `~/.zshrc`
- `--secret <file>|<text>` repeatable
- `--force` reprocess all sessions
- `--provider <name>` review provider override
- `--model <id>` review model override
- `--thinking <level>` review thinking override
- `--parallel <n>` concurrent LLM reviews
- `--deny <file>|<regex>` reject sessions matching this pattern
- `--session <file>` process one session only

### `review`

Reruns only the LLM review step on already-redacted sessions in the workspace.

By default it uses:

- `.pi/hf-sessions` as `--workspace`
- `README.md` and `AGENTS.md` as context files when present
- current pi settings unless you override provider, model, or thinking

```bash
pi-share-hf review [context-files...]
```

Uses the same review-related flags as `collect`.

### `reject`

Marks a session as never uploadable by adding it to `reject.txt`.

By default it uses `.pi/hf-sessions` as `--workspace`.

```bash
pi-share-hf reject <session.jsonl|image.png>
```

If you pass an extracted image path, the owning session is rejected.

### `list`

Lists sessions from the workspace.

By default it uses `.pi/hf-sessions` as `--workspace`.

```bash
pi-share-hf list --uploadable
```

### `grep`

Searches only the currently uploadable sessions.

By default it uses `.pi/hf-sessions` as `--workspace`.

```bash
pi-share-hf grep -i 'finance|counterparty|private-project'
```

### `upload`

Uploads the current uploadable sessions and updates the remote dataset manifest.

By default it uses `.pi/hf-sessions` as `--workspace`.

```bash
pi-share-hf upload --dry-run
pi-share-hf upload
```

Uses the built-in TypeScript Hugging Face client. No `huggingface-cli` is needed.

## Workspace layout

```text
.pi/hf-sessions/
  workspace.json
  manifest.local.jsonl
  remote-manifest.jsonl
  manifest.jsonl
  redacted/       public candidate files
  reports/        private deterministic + TruffleHog reports
  review/         private LLM review sidecars
  review-chunks/  private transcript chunks
  images/         extracted preserved images for uploadable sessions
  reject.txt
```

## Dataset layout

```text
manifest.jsonl
<session>.jsonl
```

Each uploaded `*.jsonl` file is a redacted pi session.

Session format docs:

- https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/docs/session.md

## Development

```bash
npm run check
```
