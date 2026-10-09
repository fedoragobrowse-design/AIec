# Claude provider

`aiec-agent` speaks two model wires and picks by model or base URL, never by
which key happens to be in the environment. `claude-*` / `anthropic*` model
names, or a base URL naming Anthropic/Claude, select the Anthropic Messages
API (`POST {base}/v1/messages`); everything else keeps the OpenAI-compatible
chat completions path unchanged.

## Auth: your key, your subscription

- `AIEC_AGENT_API_KEY` (or `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`) as
  `x-api-key`. Set this to an API key for metered use.
- `ANTHROPIC_OAUTH_TOKEN` (or `CLAUDE_CODE_OAUTH_TOKEN`, which is what the
  Claude Code harness exports) as `Authorization: Bearer` with
  `anthropic-beta: oauth-2025-04-20`. This is the user-owned OAuth
  passthrough: run `claude login` yourself and hand the token to the task
  environment. Explicit key env wins when both are set, so one task can pin
  a different key without clearing the ambient subscription. An OAuth token
  sent as `x-api-key` is rejected by the endpoint, which is why the two
  credentials ride different headers.
Anthropic's terms bar third-party services from piggybacking subscription
logins without approval, which is why the design is passthrough rather than
brokered: AIec never sees, stores, or forwards your subscription. The task
document form is:

```json
{ "model": { "provider": "anthropic", "model": "claude-opus-4-6" } }
```

`provider: "anthropic"` alone selects Messages even with no Anthropic model
name; `model: "claude-..."` alone selects it with no provider field.

## Guard egress

The Guard model endpoint is host-agnostic: `ModelEndpoint.host` is set by the
task's Guard selection, so `api.anthropic.com` needs no code change. A
`model-only` policy permits exactly the named endpoint; no allowlist entry
means no egress.

## Tool calls

Messages `tool_use` blocks become the same `ToolCall { id, name, arguments }`
the OpenAI path produces, and harness `tool`-role results ride back as
`tool_result` user blocks keyed by call id. The reverse direction matters
more: every assistant turn re-emits its `tool_calls` sidecar as `tool_use`
content blocks alongside the text, because the following `tool_result` ids
only exist if this side re-states them. Text-only echo earns a 400 for an
unmatched `tool_use_id` on the second turn. The agent loop never learns
which provider answered.

Thinking budgets: a numeric `reasoning` string is forwarded as Anthropic
`thinking.budget_tokens`; an effort word ("medium") is dropped rather than
sent, because Messages would reject a value the harness only guessed at.

## Claude sandbox runtime

AIec sandboxes are the Claude runtime: Firecracker microVMs in production,
Docker or bubblewrap locally, with Guard egress default-deny. Anthropic's own
`srt` (`@anthropic-ai/sandbox-runtime`, evaluated at 0.0.79, current as of
2026-10-07) is the same bwrap primitive on Linux plus a seccomp wrapper and
host proxy pair; it is usable as extra confinement for the harness process
itself where the host grants nested user namespaces, and refused where it
does not (this container: `apply-seccomp` denied on `/proc/self/setgroups`).
`srt` had one fail-open advisory (GHSA-9gqj-5w7c-vx47 / CVE-2025-66479,
empty allowlist skipped the sandbox, patched in 0.0.16); pin `>=0.0.16`.
`srt` remains beta research preview.

Detection code: `crates/aiec-agent/src/model.rs` (`detect_provider`,
`try_anthropic` / `anthropic_wire`, `parse_anthropic_reply`). Tests: parser,
detection, and a second-turn `tool_use`/`tool_result` id-match round-trip
alongside the 69 pre-existing agent tests.
